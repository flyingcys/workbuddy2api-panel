package upstream

// egress_gate_test.go 出口判据的**机制门禁**（替代手写枚举）。
//
// 为什么不能靠枚举：早先有一版 TestAllOutboundPathsHonorRoute，手工列了 10 个
// 入口逐个断言「经过代理」。变异验证证明它是假绿——把 DesktopChatWithExpert /
// globalModelsOnce / fetchV3ConfigModelMap 改回 c.HTTP.Do、把 RefreshToken 的
// 账号参数改成 nil，它全部照旧通过（那三个入口根本不在枚举里）。
//
// 两条结构性判据：
//
//  1. **函数级**豁免：internal/upstream 里任何 HTTP 客户端的 Do，必须位于一个
//     「本函数内确实调用了 clientFor / classifyRouteTransportErr」的函数里。
//     豁免按函数签发，不是按文件——早先按文件放行 client.go，结果「在 client.go
//     里顺手加一个 c.HTTP.Do 的方法」完全不被发现，而那恰恰是最该设防的文件。
//  2. 账号参数不得写 nil（等于静默走默认出口）。
//
// 两条都是「现状 0 违规、违规必须红」，新增出站路径时自动被覆盖。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// exemptFuncs 函数级豁免：这些函数里的裸 Do 是允许的。
//
// 键是 "文件:函数名"。每一条都必须有理由，且理由是「这个 Do **已经**在账号分派
// 之后」或「这个请求与账号无关」——不能是「这个文件比较特殊」。
//
//	client.go:do            —— 唯一发出点本身（client 来自 clientFor）
//	modelsdev.go:fetchDoc   —— 拉 models.dev 公共目录，与账号无关
//
// 注意 ChatStreamContext 不需要豁免：它在循环外调 clientFor 解析出 chatClient，
// 再由「本函数内调用了 clientFor」这条规则自动放行。
var exemptFuncs = map[string]string{
	"client.go:do":          "唯一发出点（client 来自 clientFor，已分派）",
	"modelsdev.go:fetchDoc": "models.dev 公共目录，与账号无关",
}

// dispatchFuncs 出现即视为「本函数已完成账号分派」的调用名。
var dispatchFuncs = map[string]bool{
	"clientFor":                 true,
	"classifyRouteTransportErr": true,
	// 注：曾误加过 chatHTTPFor —— 那个函数在仓库里**不存在**，是凭记忆敲的。
	// 幽灵条目无害但说明这个集合是手写的、没和源码对齐；下面的
	// TestGateExemptFuncsAreReal 会把这类错误变成测试失败。
}

// TestGateNoUnroutedOutbound 扫描源码：出站 Do 必须经账号分派。
func TestGateNoUnroutedOutbound(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()

	type violation struct{ where, expr string }
	var bad []violation

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := name + ":" + fn.Name.Name
			if _, exempt := exemptFuncs[key]; exempt {
				continue
			}
			if expr := firstHTTPDoExpr(fn.Body); expr != "" && !bodyDispatches(fn.Body) {
				bad = append(bad, violation{
					where: name + ":" + itoaTest(fset.Position(fn.Pos()).Line) + " " + fn.Name.Name + "()",
					expr:  expr,
				})
			}
		}
	}

	if len(bad) > 0 {
		sort.Slice(bad, func(i, j int) bool { return bad[i].where < bad[j].where })
		var sb strings.Builder
		sb.WriteString("发现未经账号分派的出站请求（会绕过账号绑定的出口线路）：\n")
		for _, b := range bad {
			sb.WriteString("  " + b.where + "  →  " + b.expr + "\n")
		}
		sb.WriteString("修法：改用 c.do(acct, req, kind)，或在函数内显式调用 clientFor 拿到该账号的 client。\n")
		sb.WriteString("若确属「与账号无关」的请求，把理由写进 exemptFuncs（函数级，不是文件级）。")
		t.Fatal(sb.String())
	}
}

// TestGateNoNilAccount 扫描：不得把账号参数写成 nil（那等于静默走默认出口）。
func TestGateNoNilAccount(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()

	target := map[string]bool{
		"do": true, "doJSON": true, "doSearch": true,
		"clientFor": true, "chatHTTPFor": true, "classifyRouteTransportErr": true,
	}

	var bad []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !target[sel.Sel.Name] || len(call.Args) == 0 {
				return true
			}
			if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "nil" {
				pos := fset.Position(call.Pos())
				bad = append(bad, name+":"+itoaTest(pos.Line)+"  "+exprString(call))
			}
			return true
		})
	}

	if len(bad) > 0 {
		t.Fatalf("把账号参数写成 nil 会让该请求静默走默认出口：\n  %s\n"+
			"若确实没有账号上下文（登录流程等），请显式调用不接收账号的 API 并注明原因。",
			strings.Join(bad, "\n  "))
	}
}

// firstHTTPDoExpr 返回函数体内第一个 HTTP 客户端 Do 的表达式文本（没有则空串）。
func firstHTTPDoExpr(body *ast.BlockStmt) string {
	found := ""
	ast.Inspect(body, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Do" || len(call.Args) != 1 {
			return true
		}
		if isHTTPClientReceiver(exprString(sel.X)) {
			found = exprString(call)
		}
		return true
	})
	return found
}

// bodyDispatches 判断函数体内的 Do 是否真的经账号分派。
//
// **不是**「函数里出现过 clientFor 就放行整函数」——那样一来，任何既有函数只要
// 前半段调过 clientFor，后半段新加的裸 c.HTTP.Do 就完全不可见（实测 v1 判据
// 对该形态全绿）。这正是最该防的场景：有人在既有函数里顺手加一条出站。
//
// 现在的判据：Do 的接收者必须是**本函数内由分派函数赋值得到的局部变量**
// （如 client, err := c.clientFor(...)）。裸 c.HTTP / c.ChatHTTP 一律不算，
// 除非该函数在 exemptFuncs 里显式豁免。
func bodyDispatches(body *ast.BlockStmt) bool {
	// 收集：本函数内由分派函数赋值得到的局部变量名
	dispatched := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if !rhsCallsDispatch(as.Rhs) {
			return true
		}
		for _, l := range as.Lhs {
			if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
				dispatched[id.Name] = true
			}
		}
		return true
	})
	if len(dispatched) == 0 {
		return false
	}
	// 每个 HTTP Do 的接收者都必须在 dispatched 里
	ok := true
	ast.Inspect(body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "Do" || len(call.Args) != 1 {
			return true
		}
		recv := exprString(sel.X)
		if !isHTTPClientReceiver(recv) {
			return true
		}
		// 形如 x.Do(...) 且 x 是分派得到的局部变量 → 放行
		if id, isId := sel.X.(*ast.Ident); isId && dispatched[id.Name] {
			return true
		}
		ok = false
		return false
	})
	return ok
}

// rhsCallsDispatch 赋值右侧是否调用了分派函数。
func rhsCallsDispatch(rhs []ast.Expr) bool {
	for _, e := range rhs {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			continue
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if dispatchFuncs[fn.Sel.Name] {
				return true
			}
		case *ast.Ident:
			if dispatchFuncs[fn.Name] {
				return true
			}
		}
	}
	return false
}

// isHTTPClientReceiver 判断 Do 的接收者是否可能是 *http.Client。
func isHTTPClientReceiver(recv string) bool {
	switch recv {
	case "client", "chatClient", "http.DefaultClient",
		"c.HTTP", "c.ChatHTTP", "c.chatHTTP()":
		return true
	}
	return strings.HasSuffix(recv, ".HTTP") || strings.HasSuffix(recv, ".ChatHTTP") ||
		strings.HasSuffix(recv, ".chatHTTP()")
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "()"
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.BasicLit:
		return v.Value
	case *ast.UnaryExpr:
		return v.Op.String() + exprString(v.X)
	}
	return "?"
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestGateExemptFuncsAreReal 豁免表本身必须可信。
//
// 三条断言，对应三种「把门禁悄悄放水」的方式：
//  1. 键必须形如 `file:func` —— 挡住有人写成文件级（`client.go`）这种宽泛豁免，
//     那等于整个文件不设防（v1 就栽在这里）。
//  2. 被豁免的函数必须在源码里真实存在 —— 挡住幽灵条目（`chatHTTPFor` 就这么来过）。
//  3. 理由必须非空 —— 强制解释，review 时看得见。
//
// 另外限制总数：豁免是「必须解释的例外」，不是可以随手加的开关。超了就得先
// 想想是不是该改设计。
func TestGateExemptFuncsAreReal(t *testing.T) {
	const maxExempt = 3
	if len(exemptFuncs) > maxExempt {
		t.Fatalf("豁免条目 %d 个，超过上限 %d —— 每加一条都意味着又多了一处不受门禁管辖的出站",
			len(exemptFuncs), maxExempt)
	}

	// 收集源码里实际存在的函数名
	real := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				real[name+":"+fn.Name.Name] = true
			}
		}
	}

	for key, reason := range exemptFuncs {
		if !strings.Contains(key, ":") || strings.HasSuffix(key, ".go") {
			t.Errorf("豁免键 %q 不是 `file:func` 形式（文件级豁免等于整个文件不设防）", key)
			continue
		}
		if !real[key] {
			t.Errorf("豁免键 %q 指向的函数在源码中不存在（幽灵条目）", key)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("豁免键 %q 没有填写理由", key)
		}
	}
}
