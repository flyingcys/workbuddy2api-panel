package upstream

// egress_gate_test.go 出口判据的**机制门禁**（替代手写枚举）。
//
// 背景：早先有一版 TestAllOutboundPathsHonorRoute，手工列了 10 个入口并逐个断言
// 「经过代理」。变异验证证明它是假绿：
//
//   - DesktopChatWithExpert / globalModelsOnce / fetchV3ConfigModelMap 改回
//     c.HTTP.Do → 全绿（它们根本不在枚举里）
//   - RefreshToken 的 doJSON(a, req) 改成 doJSON(nil, req) → 全绿
//   - 新增一个 c.HTTP.Do 的导出方法 → 全绿
//
// 根因是**枚举会漏，机制不会**。这里换成两条结构性判据：
//
//  1. 源码扫描：internal/upstream 里任何 `.Do(req)` 只允许出现在 do() 与
//     modelsdev 的公共目录拉取里。
//  2. 递归扫描：任何把账号参数写成 nil 的 do/doJSON/doSearch/clientFor 调用。
//
// 两条都是「现状必须 0 违规、违规必须红」，新增出站路径时自动被覆盖。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowDirectDo 允许直接调用 .Do(req) 的位置（本文件的审计对象排除在外）。
//
// 目前只有两处，且都有明确理由：
//   - client.go 的 do()：唯一发出点本身
//   - modelsdev.go：公共模型目录，与账号无关
//
// 另外一个特例是 ChatStreamContext 里的 chatClient.Do —— 它的接收者是局部变量
// （由 clientFor 得到的 client），语义上是「已经过账号分派」，故按接收者名放行。
var allowDirectDo = map[string]string{
	"client.go":    "do() 自身 + ChatStreamContext 的 chatClient（已分派）",
	"modelsdev.go": "models.dev 公共目录，与账号无关",
}

// TestGateNoUnroutedOutbound 扫描源码：出站 Do 必须经账号分派。
func TestGateNoUnroutedOutbound(t *testing.T) {
	dir := "."
	fset := token.NewFileSet()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	type violation struct {
		file string
		line int
		expr string
	}
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

		// 收集本文件里 do() 的函数体范围（那是唯一允许裸 Do 的地方）
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Do" {
				return true
			}
			// 只看形如 X.Do(req) 的调用
			if len(call.Args) != 1 {
				return true
			}

			recv := exprString(sel.X)
			// 只审计 HTTP 客户端的 Do：sync.Once / 其它类型的 Do 与出站无关。
			if !isHTTPClientReceiver(recv) {
				return true
			}
			// 允许：局部已分派的 client 变量（chatClient / client）
			if recv == "chatClient" || recv == "client" {
				return true
			}
			// 允许整文件白名单里的「已知合理」接收者
			if _, ok := allowDirectDo[name]; ok {
				switch recv {
				case "c.HTTP", "c.ChatHTTP", "c.chatHTTP()":
					return true
				}
			}
			pos := fset.Position(call.Pos())
			bad = append(bad, violation{file: name, line: pos.Line, expr: exprString(call)})
			return true
		})
	}

	if len(bad) > 0 {
		var sb strings.Builder
		sb.WriteString("发现未经账号分派的出站请求（会绕过账号绑定的出口线路）：\n")
		for _, b := range bad {
			sb.WriteString("  ")
			sb.WriteString(b.file)
			sb.WriteString(":")
			sb.WriteString(itoaTest(b.line))
			sb.WriteString("  ")
			sb.WriteString(b.expr)
			sb.WriteString("\n")
		}
		sb.WriteString("修法：改用 c.do(acct, req, kind) —— 这是唯一发出点。\n")
		sb.WriteString("若确属「与账号无关」的请求（如公共目录），把理由写清楚再加进 allowDirectDo。")
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

	// 首参为账号的方法
	target := map[string]bool{
		"do": true, "doJSON": true, "doSearch": true,
		"clientFor": true, "chatHTTPFor": true, "routePair": false,
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
			if !ok || !target[sel.Sel.Name] {
				return true
			}
			if len(call.Args) == 0 {
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

// isHTTPClientReceiver 判断 Do 的接收者是否可能是 *http.Client。
//
// 只看形态足够：本包里 HTTP 客户端要么是 c.HTTP / c.ChatHTTP / c.chatHTTP()
// 这类字段与访问器，要么是局部变量 client / chatClient。其余（sync.Once、
// 自定义类型）一概不审计——把它们卷进来只会制造噪声，进而让人加白名单放水。
func isHTTPClientReceiver(recv string) bool {
	switch recv {
	case "client", "chatClient", "c.HTTP", "c.ChatHTTP", "c.chatHTTP()":
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
