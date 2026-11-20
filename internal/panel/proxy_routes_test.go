package panel

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// proxyTestEnv 一个最小的面板环境：临时 config.json + 一个账号文件 + 池。
type proxyTestEnv struct {
	panel       *Panel
	cfgPath     string
	authDir     string
	pool        *pool.Pool
	accountFile string
}

func newProxyTestEnv(t *testing.T) *proxyTestEnv {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	// 带一个「未知键」，验证写回时不被洗掉。
	if err := os.WriteFile(cfgPath, []byte(`{"listen":":7863","api_key":"k","schedule":{"checkin_hours":[9]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	authDir := filepath.Join(dir, "auths")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	accountFile := filepath.Join(authDir, "workbuddy-u1.json")
	if err := os.WriteFile(accountFile,
		[]byte(`{"auth":{"accessToken":"at"},"account":{"uid":"u1","nickname":"n1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(accountFile)
	a, err := auth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	a.FilePath = accountFile

	pl := pool.New(filepath.Join(dir, "state.json"))
	pl.Add(a)
	t.Cleanup(pl.Close)

	p := New(Config{
		Version:    "test",
		APIKey:     "test-key",
		Pool:       pl,
		Upstream:   &upstream.Client{},
		AuthDir:    authDir,
		ConfigPath: cfgPath,
	})
	return &proxyTestEnv{panel: p, cfgPath: cfgPath, authDir: authDir, pool: pl, accountFile: accountFile}
}

func (e *proxyTestEnv) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	e.panel.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (e *proxyTestEnv) configText(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// 线路表写入：只动 proxies 段，其它键（含未识别的）原样保留。
func TestRoutesSavePreservesOtherConfigKeys(t *testing.T) {
	e := newProxyTestEnv(t)
	code, body := e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"socks5://user:pass@h1.example:1080"}}`)
	if code != 200 {
		t.Fatalf("code=%d body=%v", code, body)
	}
	cfg := e.configText(t)
	for _, must := range []string{`"listen"`, `"api_key"`, `"checkin_hours"`, `"proxies"`, `"hk-1"`} {
		if !strings.Contains(cfg, must) {
			t.Errorf("写回后丢了 %s：\n%s", must, cfg)
		}
	}
}

// 脱敏串原样提交时必须沿用旧密码（改域名不重输密码）。
func TestRoutesSaveKeepsPasswordWhenMasked(t *testing.T) {
	e := newProxyTestEnv(t)
	if code, b := e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"socks5://user:sekret@h1.example:1080"}}`); code != 200 {
		t.Fatalf("first save: %d %v", code, b)
	}
	// 界面回显的就是脱敏串；用户只改了端口。
	if code, b := e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"socks5://user:***@h1.example:2080"}}`); code != 200 {
		t.Fatalf("masked save: %d %v", code, b)
	}
	cfg := e.configText(t)
	if !strings.Contains(cfg, "sekret") {
		t.Fatalf("密码被抹掉了：\n%s", cfg)
	}
	if !strings.Contains(cfg, "2080") {
		t.Fatalf("端口没更新：\n%s", cfg)
	}
}

// 用户名变了却仍用 *** → 必须拒绝（否则存进一个必然认证失败的组合）。
func TestRoutesSaveRejectsChangedUserWithMask(t *testing.T) {
	e := newProxyTestEnv(t)
	e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"socks5://user:sekret@h1.example:1080"}}`)
	code, _ := e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"socks5://other:***@h1.example:1080"}}`)
	if code != 400 {
		t.Fatalf("换了用户名还用 *** 应当 400，实际 %d", code)
	}
}

// 非法地址与非法线路名都要拒。
func TestRoutesSaveRejectsBadInput(t *testing.T) {
	e := newProxyTestEnv(t)
	cases := []struct{ name, body string }{
		{"socks4", `{"routes":{"x":"socks4://h:1080"}}`},
		{"缺端口", `{"routes":{"x":"socks5://h"}}`},
		{"非法线路名", `{"routes":{"a b":"socks5://h:1080"}}`},
		{"空地址", `{"routes":{"x":""}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _ := e.do(t, "PUT", "/panel/api/proxy/routes", c.body); code != 400 {
				t.Fatalf("%s 应当 400，实际 %d", c.name, code)
			}
		})
	}
}

// 读接口必须脱敏。
func TestRoutesListMasksPassword(t *testing.T) {
	e := newProxyTestEnv(t)
	e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"socks5://user:sekret@h1.example:1080"}}`)
	code, body := e.do(t, "GET", "/panel/api/proxy/routes", "")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "sekret") {
		t.Fatalf("列表接口泄漏了密码：%s", raw)
	}
	if !strings.Contains(string(raw), "***") {
		t.Fatalf("列表接口应当回脱敏串：%s", raw)
	}
}

// 账号绑定：写到 auths 文件、内存立即生效、重启（重新 Parse）后仍在。
func TestAccountProxyBindPersistsAndApplies(t *testing.T) {
	e := newProxyTestEnv(t)
	e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"socks5://u:p@h1.example:1080"}}`)

	code, body := e.do(t, "PUT", "/panel/api/accounts/u1/proxy", `{"proxy":"hk-1"}`)
	if code != 200 {
		t.Fatalf("bind: %d %v", code, body)
	}

	// ① 内存立即生效（池内是同一个指针，网关下一次请求就会用新线路）
	if got := e.pool.AuthByUID("u1").ProxyName; got != "hk-1" {
		t.Fatalf("内存未生效：%q", got)
	}
	// ② 落盘
	raw, _ := os.ReadFile(e.accountFile)
	if !strings.Contains(string(raw), `"proxy": "hk-1"`) {
		t.Fatalf("未写进账号文件：\n%s", raw)
	}
	// ③ 重新解析（模拟重启）后仍在
	back, err := auth.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.ProxyName != "hk-1" {
		t.Fatalf("重启后绑定丢失：%q", back.ProxyName)
	}
	// ④ 状态接口回显
	if st, ok := e.pool.Status("u1"); !ok || st.ProxyName != "hk-1" {
		t.Fatalf("Status 未回显 ProxyName：%+v", st)
	}
}

// token 刷新（SaveAtomic）后绑定不能被洗掉——这是最危险的回归点。
func TestAccountProxySurvivesTokenRefresh(t *testing.T) {
	e := newProxyTestEnv(t)
	e.do(t, "PUT", "/panel/api/proxy/routes", `{"routes":{"hk-1":"socks5://u:p@h1.example:1080"}}`)
	e.do(t, "PUT", "/panel/api/accounts/u1/proxy", `{"proxy":"hk-1"}`)

	a := e.pool.AuthByUID("u1")
	a.Lock()
	a.AccessToken = "at-refreshed"
	a.Unlock()
	if err := a.SaveAtomic(); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, _ := os.ReadFile(e.accountFile)
	if !strings.Contains(string(raw), `"proxy": "hk-1"`) {
		t.Fatalf("token 刷新把线路绑定洗掉了：\n%s", raw)
	}
}

// 绑不存在的线路要拒（防止手滑写错后整池失败）。
func TestAccountProxyRejectsUnknownRoute(t *testing.T) {
	e := newProxyTestEnv(t)
	code, _ := e.do(t, "PUT", "/panel/api/accounts/u1/proxy", `{"proxy":"nope"}`)
	if code != 400 {
		t.Fatalf("应当 400，实际 %d", code)
	}
}

// 空值 = 解绑；保留名 __direct__ = 强制直连（不查线路表）。
func TestAccountProxyAcceptsEmptyAndDirect(t *testing.T) {
	e := newProxyTestEnv(t)
	if code, b := e.do(t, "PUT", "/panel/api/accounts/u1/proxy",
		`{"proxy":"`+upstream.DirectRouteName+`"}`); code != 200 {
		t.Fatalf("direct: %d %v", code, b)
	}
	if got := e.pool.AuthByUID("u1").ProxyName; got != upstream.DirectRouteName {
		t.Fatalf("got %q", got)
	}
	if code, b := e.do(t, "PUT", "/panel/api/accounts/u1/proxy", `{"proxy":""}`); code != 200 {
		t.Fatalf("clear: %d %v", code, b)
	}
	if got := e.pool.AuthByUID("u1").ProxyName; got != "" {
		t.Fatalf("解绑后仍为 %q", got)
	}
	raw, _ := os.ReadFile(e.accountFile)
	if strings.Contains(string(raw), `"proxy"`) {
		t.Fatalf("解绑后文件里不该有 proxy 键：\n%s", raw)
	}
}

// 删除仍被使用的线路：保存应成功（不阻断），但账号请求会明确失败。
func TestDeletingBoundRouteIsAllowedButVisible(t *testing.T) {
	e := newProxyTestEnv(t)
	e.do(t, "PUT", "/panel/api/proxy/routes", `{"routes":{"hk-1":"socks5://u:p@h1.example:1080"}}`)
	e.do(t, "PUT", "/panel/api/accounts/u1/proxy", `{"proxy":"hk-1"}`)

	// 线路表清空
	if code, b := e.do(t, "PUT", "/panel/api/proxy/routes", `{"routes":{}}`); code != 200 {
		t.Fatalf("清空线路表应当成功：%d %v", code, b)
	}
	// 账号仍绑着已删除的线路 → 保存本身成功（不阻断），但线路表里确实没有了。
	code2, body2 := e.do(t, "GET", "/panel/api/proxy/routes", "")
	if code2 != 200 {
		t.Fatalf("list: %d", code2)
	}
	if routes, _ := body2["routes"].([]any); len(routes) != 0 {
		t.Fatalf("线路表应为空：%v", routes)
	}
	// 账号绑定仍然在（不清空 = 不偷偷改变出口；发请求时会明确报错）
	if got := e.pool.AuthByUID("u1").ProxyName; got != "hk-1" {
		t.Fatalf("删除线路不该顺手清掉账号绑定：%q", got)
	}
}

// 闭环：读接口返回的脱敏串原样提交回来，必须能还原出原始密码。
//
// 这条是 bug 驱动加的：起初用 url.Redacted()（占位符是 xxxxx），与 proxyMask(***)
// 不一致，且 url.String() 会把 * 编码成 %2A——两种写法都会让「回读还原」静默失效，
// 而这在界面上表现为「保存后密码变成 *** 了」。
func TestMaskedRoundTripRestoresPassword(t *testing.T) {
	e := newProxyTestEnv(t)
	original := "socks5://user:sekret@h1.example:1080"
	if code, b := e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"`+original+`"}}`); code != 200 {
		t.Fatalf("save: %d %v", code, b)
	}

	// 取回列表里的脱敏串
	_, body := e.do(t, "GET", "/panel/api/proxy/routes", "")
	routes, _ := body["routes"].([]any)
	if len(routes) != 1 {
		t.Fatalf("routes=%v", routes)
	}
	masked, _ := routes[0].(map[string]any)["url"].(string)
	if masked == "" || masked == original {
		t.Fatalf("脱敏串不对：%q", masked)
	}
	if !strings.Contains(masked, proxyMask) {
		t.Fatalf("脱敏串里没有 %s：%q", proxyMask, masked)
	}

	// 原样提交回去 → 密码必须回到 sekret
	if code, b := e.do(t, "PUT", "/panel/api/proxy/routes",
		`{"routes":{"hk-1":"`+masked+`"}}`); code != 200 {
		t.Fatalf("masked save: %d %v", code, b)
	}
	if !strings.Contains(e.configText(t), "sekret") {
		t.Fatalf("脱敏串回读后密码丢了：\n%s", e.configText(t))
	}
}
