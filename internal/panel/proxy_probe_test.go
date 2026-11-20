package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 探测接口：只接受线路表里已有的名字，不接受任意地址。
//
// 这条约束是安全性质：否则登录用户填个内网地址，就能让面板去打
// 169.254.169.254 之类的元数据服务。
func TestProbeUnknownRouteRejected(t *testing.T) {
	e := newProxyTestEnv(t)
	code, body := e.do(t, "POST", "/panel/api/proxy/probe", `{"name":"ghost"}`)
	if code != http.StatusNotFound {
		t.Fatalf("code=%d body=%v", code, body)
	}
}

func TestProbeRequiresName(t *testing.T) {
	e := newProxyTestEnv(t)
	code, _ := e.do(t, "POST", "/panel/api/proxy/probe", `{"name":""}`)
	if code != http.StatusBadRequest {
		t.Fatalf("code=%d", code)
	}
}

// forwardProxy 一个极简 HTTP 正向代理：对 CONNECT / 绝对 URI 请求都转发。
//
// 为什么不用 http.DefaultClient 转发：那会再次经过环境代理造成环路（实测 502）。
// 这里直接按原始 TCP 转发，不参与任何代理配置。
func forwardProxy(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		// 用裸 Transport（Proxy=nil）转发，避免环境代理介入
		tr := &http.Transport{Proxy: nil}
		defer tr.CloseIdleConnections()
		req := r.Clone(r.Context())
		resp, err := tr.RoundTrip(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// 探测成功时要把出口 IP 与归属地带回来。
func TestProbeThroughProxyReturnsExitInfo(t *testing.T) {
	exit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"198.51.100.9","country":"JP","city":"Tokyo"}`))
	}))
	defer exit.Close()

	px := forwardProxy(t)
	res := probeThroughRoute(context.Background(), px.URL, exit.URL)
	if !res.OK {
		t.Fatalf("探测失败：%+v", res)
	}
	if res.ExitIP != "198.51.100.9" {
		t.Errorf("exit_ip=%q，期望 198.51.100.9", res.ExitIP)
	}
	if !strings.Contains(res.ExitInfo, "JP") || !strings.Contains(res.ExitInfo, "Tokyo") {
		t.Errorf("exit_info=%q，期望含 JP / Tokyo", res.ExitInfo)
	}
	if res.MS < 0 {
		t.Errorf("ms 不该为负：%d", res.MS)
	}
}

// 代理不可达：错误可读，且**不含地址里的密码**。
func TestProbeUnreachableRedactsPassword(t *testing.T) {
	res := probeThroughRoute(context.Background(), "http://user:s3cr3t@127.0.0.1:1", "http://example.invalid/")
	if res.OK {
		t.Fatal("不可达的代理不该报成功")
	}
	if res.Error == "" {
		t.Fatal("错误信息为空")
	}
	if strings.Contains(res.Error, "s3cr3t") {
		t.Fatalf("错误里泄漏了密码：%s", res.Error)
	}
}

// 端点返回非 JSON：连通即算成功，但要给提示（不能静默返回空结果）。
func TestProbeNonJSONEndpointGivesNotice(t *testing.T) {
	exit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("connected"))
	}))
	defer exit.Close()

	res := probeThroughRoute(context.Background(), forwardProxy(t).URL, exit.URL)
	if !res.OK {
		t.Fatalf("连通即应成功：%+v", res)
	}
	if res.ExitIP != "" {
		t.Errorf("不该凭空造出 IP：%q", res.ExitIP)
	}
	if res.Notice == "" {
		t.Error("解析不出 IP 时必须给提示")
	}
}

// 端点返回非 200：明确报错并带状态码。
func TestProbeNon200Reported(t *testing.T) {
	exit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer exit.Close()

	res := probeThroughRoute(context.Background(), forwardProxy(t).URL, exit.URL)
	if res.OK {
		t.Fatal("非 200 不该算成功")
	}
	if !strings.Contains(res.Error, "403") {
		t.Errorf("错误里应带状态码：%s", res.Error)
	}
}

// redactUserinfo：只抹真正的凭据段，不误伤普通文本。
func TestRedactUserinfo(t *testing.T) {
	cases := []struct{ in, want string }{
		{"dial socks5://user:pw@h:1080 failed", "dial socks5://***@h:1080 failed"},
		{"no credentials here", "no credentials here"},
		{"http://host/path@fragment", "http://host/path@fragment"}, // @ 不在 userinfo 位置
	}
	for _, c := range cases {
		if got := redactUserinfo(c.in); got != c.want {
			t.Errorf("redact(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// probeErrText 必须把常见故障翻成可行动的句子。
func TestProxyErrTextClassification(t *testing.T) {
	cases := []struct{ in, must string }{
		{"socks connect: username/password authentication failed", "认证失败"},
		{"dial tcp 127.0.0.1:1: connect: connection refused", "拒绝连接"},
		{"dial tcp: lookup proxy.example: no such host", "解析失败"},
		{"context deadline exceeded", "超时"},
		{"x509: certificate signed by unknown authority", "证书"},
	}
	for _, c := range cases {
		if got := proxyErrText(errString(c.in)); !strings.Contains(got, c.must) {
			t.Errorf("proxyErrText(%q) = %q，期望含 %q", c.in, got, c.must)
		}
	}
}

// ── 小工具 ────────────────────────────────────────────────────────────

// errString 让用例能直接构造一个带指定文本的 error（免去 errors.New 的 import）。
type errString string

func (e errString) Error() string { return string(e) }
