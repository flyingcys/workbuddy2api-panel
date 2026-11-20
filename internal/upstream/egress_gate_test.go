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
	"chatHTTPFor":               true,
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

// bodyDispatches 函数体内是否调用了账号分派函数（用于函数级豁免）。
func bodyDispatches(body *ast.BlockStmt) bool {
	ok := false
	ast.Inspect(body, func(n ast.Node) bool {
		if ok {
			return false
		}
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if dispatchFuncs[fn.Sel.Name] {
				ok = true
			}
		case *ast.Ident:
			if dispatchFuncs[fn.Name] {
				ok = true
			}
		}
		return true
	})
	return ok
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
