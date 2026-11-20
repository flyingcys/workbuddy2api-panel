package upstream

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// ── 最小 SOCKS5 服务器（测试夹具）────────────────────────────────────────
//
// 为什么不用现成库：仓库没有 golang.org/x/net 依赖，也不该为测试引入新依赖。
// 这里只实现 CONNECT + RFC 1929 用户名密码认证，够验证「请求是否真的穿过了代理」。
//
// 判据形态很关键：断言**代理端收到了这次 CONNECT**，而不是「客户端构造成功」。
// 后者是假绿——manager 仓库的 Python 侧就有只断言构造成功的用例，实测在
// httpx 0.27 下 socks5h 构造会失败而用例仍然通过。

type socksTarget struct {
	Host string
	Port uint16
	User string
	Pass string
}

type socksServer struct {
	ln       net.Listener
	mu       sync.Mutex
	connects []socksTarget
	closed   atomic.Bool
	// failAuth 为 true 时拒绝所有认证（用来验证「线路本身可用但凭据错」的路径）。
	failAuth bool
}

func newSocksServer(t *testing.T, failAuth bool) *socksServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &socksServer{ln: ln, failAuth: failAuth}
	go s.serve()
	t.Cleanup(func() {
		s.closed.Store(true)
		ln.Close()
	})
	return s
}

func (s *socksServer) addr() string { return s.ln.Addr().String() }

func (s *socksServer) connectsSnapshot() []socksTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]socksTarget(nil), s.connects...)
}

func (s *socksServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *socksServer) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)

	// greeting
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 2}); err != nil { // 只提供用户名密码
		return
	}

	// RFC 1929
	ah := make([]byte, 2)
	if _, err := io.ReadFull(br, ah); err != nil || ah[0] != 1 {
		return
	}
	user := make([]byte, int(ah[1]))
	if _, err := io.ReadFull(br, user); err != nil {
		return
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(br, pl); err != nil {
		return
	}
	pass := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(br, pass); err != nil {
		return
	}
	if s.failAuth {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return
	}

	// request
	rh := make([]byte, 4)
	if _, err := io.ReadFull(br, rh); err != nil || rh[0] != 5 || rh[1] != 1 {
		return
	}
	var host string
	switch rh[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3: // 域名——这条才是「域名交给代理解析」的证据
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	s.mu.Lock()
	s.connects = append(s.connects, socksTarget{
		Host: host, Port: port, User: string(user), Pass: string(pass),
	})
	s.mu.Unlock()

	remote, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(remote, br)
		remote.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(c, remote)
}

// ── 夹具 ──────────────────────────────────────────────────────────────

// routeTestClient 构造一个「HTTP 指向代理」的 Client，与生产 New() 的差别只有
// base 地址（测试里用本地 httptest）。
func routeTestClient(t *testing.T, base string) *Client {
	t.Helper()
	SetRouteTransportFactory(func() *http.Transport { return NewRouteTransport() })
	t.Cleanup(ResetRoutesForTest)
	t.Cleanup(resetRouteClientsForTest)
	return &Client{
		HTTP:          &http.Client{Timeout: 5 * time.Second, Transport: NewRouteTransport()},
		ChatHTTP:      &http.Client{Timeout: 0, Transport: NewRouteTransport()},
		ChatBaseCN:    base,
		BillingBaseCN: base,
		WebBaseCN:     base,
		GlobalEnabled: true,
	}
}

func resetRouteClientsForTest() {
	// 单测之间相互隔离：清掉按线路缓存的 client，避免上一轮的 Transport 被复用。
	routes.mu.Lock()
	for _, tr := range routes.cache {
		tr.CloseIdleConnections()
	}
	routes.cache = map[string]*http.Transport{}
	routes.mu.Unlock()
}

// ── 用例 ──────────────────────────────────────────────────────────────

// 核心判据：绑了线路的账号，请求必须**从代理出去**（代理端看到这次 CONNECT）。
func TestBoundAccountGoesThroughProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":0,"msg":"OK","data":{"ok":true}}`))
	}))
	defer srv.Close()

	socks := newSocksServer(t, false)
	if err := ConfigureRoutes(map[string]string{
		"hk-1": "socks5://user:pass@" + socks.addr(),
	}); err != nil {
		t.Fatalf("configure routes: %v", err)
	}
	c := routeTestClient(t, srv.URL)

	// ReportChatActivity 经 doJSON → do → 线路 client
	a := &auth.Auth{AccessToken: "at", UID: "u1"}
	a.SetProxyName("hk-1")
	if err := c.ReportChatActivity(a, "conv-1", ""); err != nil {
		t.Fatalf("report through proxy: %v", err)
	}

	connects := socks.connectsSnapshot()
	if len(connects) != 1 {
		t.Fatalf("代理收到的 CONNECT 次数 = %d，期望 1（请求没走代理就是这里为 0）", len(connects))
	}
	got := connects[0]
	if got.User != "user" || got.Pass != "pass" {
		t.Errorf("代理收到的凭据 = %q/%q，期望 user/pass", got.User, got.Pass)
	}
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	if got.Host != host || strconv.Itoa(int(got.Port)) != port {
		t.Errorf("代理收到的目标 = %s:%d，期望 %s:%s", got.Host, got.Port, host, port)
	}
}

// 未绑线路的账号必须走共享 client，**不经过代理**（零回归的判据）。
func TestUnboundAccountUsesSharedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":0,"msg":"OK","data":{"ok":true}}`))
	}))
	defer srv.Close()

	socks := newSocksServer(t, false)
	if err := ConfigureRoutes(map[string]string{
		"hk-1": "socks5://user:pass@" + socks.addr(),
	}); err != nil {
		t.Fatalf("configure routes: %v", err)
	}
	c := routeTestClient(t, srv.URL)

	if err := c.ReportChatActivity(&auth.Auth{AccessToken: "at", UID: "u2"}, "conv-2", ""); err != nil {
		t.Fatalf("report: %v", err)
	}
	if n := len(socks.connectsSnapshot()); n != 0 {
		t.Fatalf("未绑线路的账号走了代理（CONNECT=%d）——零回归被破坏", n)
	}
}

// 线路不可用必须明确报错，且**不静默回落到直连**。
func TestUnknownRouteFailsAndDoesNotFallBack(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"code":0,"msg":"OK"}`))
	}))
	defer srv.Close()

	// 线路表里只有 hk-1，账号却绑了 nope。
	if err := ConfigureRoutes(map[string]string{"hk-1": "socks5://u:p@127.0.0.1:1"}); err != nil {
		t.Fatalf("configure routes: %v", err)
	}
	c := routeTestClient(t, srv.URL)

	aBad := &auth.Auth{AccessToken: "at", UID: "u3"}
	aBad.SetProxyName("nope")
	err := c.ReportChatActivity(aBad, "conv-3", "")
	if err == nil {
		t.Fatal("绑了不存在的线路却没报错")
	}
	if !IsRouteUnavailable(err) {
		t.Fatalf("错误类型不是 RouteUnavailableError：%T %v", err, err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("请求静默回落到直连了（目标服务器被打了 %d 次）", n)
	}
}

// 强制直连线路：绑了 __direct__ 的账号即使进程级配了环境代理也必须直连。
func TestDirectRouteBypassesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":0,"msg":"OK"}`))
	}))
	defer srv.Close()

	socks := newSocksServer(t, false)
	if err := ConfigureRoutes(map[string]string{"hk-1": "socks5://u:p@" + socks.addr()}); err != nil {
		t.Fatalf("configure routes: %v", err)
	}
	// 同时把环境代理指向 socks 服务器：__direct__ 必须无视它。
	//
	// ⚠️ 注意本用例**判别不了「误用 ProxyFromEnvironment」**：Go 标准库内嵌的
	// httpproxy 把 loopback 目标硬编码为不走代理（vendor/.../httpproxy/proxy.go
	// useProxy: host=="localhost" 或 ip.IsLoopback() → false），而 httptest 只能
	// 监听 127.0.0.1。也就是说此时无论 Proxy 是 nil 还是 ProxyFromEnvironment，
	// 请求都直连、都成功——变异验证实测「改坏也照样绿」。
	// 「绕过环境代理」这一半由 TestDirectRouteBypassesEnvProxySubprocess 用
	// 非回环地址（127.0.0.2）钉住；本用例只负责「绑 __direct__ 不走线路表」。
	t.Setenv("HTTP_PROXY", "socks5://u:p@"+socks.addr())
	t.Setenv("HTTPS_PROXY", "socks5://u:p@"+socks.addr())
	c := routeTestClient(t, srv.URL)

	a := &auth.Auth{AccessToken: "at", UID: "u4"}
	a.SetProxyName(DirectRouteName)
	if err := c.ReportChatActivity(a, "conv-4", ""); err != nil {
		t.Fatalf("direct route: %v", err)
	}
	if n := len(socks.connectsSnapshot()); n != 0 {
		t.Fatalf("__direct__ 账号仍走了代理（CONNECT=%d）", n)
	}
}

// 每条线路一个 Transport：连接池不能共用（共用会把 A 线路的连接复用给 B 线路）。
func TestEachRouteHasOwnTransport(t *testing.T) {
	if err := ConfigureRoutes(map[string]string{
		"a": "socks5://u:p@127.0.0.1:1111",
		"b": "socks5://u:p@127.0.0.1:2222",
	}); err != nil {
		t.Fatalf("configure routes: %v", err)
	}
	defer ResetRoutesForTest()

	ta, err := routes.transportFor("a")
	if err != nil {
		t.Fatalf("transport a: %v", err)
	}
	tb, err := routes.transportFor("b")
	if err != nil {
		t.Fatalf("transport b: %v", err)
	}
	if ta == tb {
		t.Fatal("两条线路共用了同一个 Transport —— 连接池会串出口")
	}
	// 同一线路重复取必须复用（否则每次请求新建连接池，keepalive 全废）
	if again, _ := routes.transportFor("a"); again != ta {
		t.Fatal("同一线路每次返回新 Transport，连接池会不断分裂")
	}
	// 两者都不能是「无代理」的 Transport
	if ta.Proxy == nil || tb.Proxy == nil {
		t.Fatal("线路 Transport 的 Proxy 为 nil，等于直连")
	}
	direct, err := routes.transportFor(DirectRouteName)
	if err != nil {
		t.Fatalf("direct: %v", err)
	}
	if direct.Proxy != nil {
		t.Fatal("__direct__ 的 Proxy 必须为 nil，否则仍会走环境代理")
	}
}

// socks5h 归一化为 socks5（实测两者 Go 侧行为一致；归一化消除 Go 1.22 版本边界）。
func TestSocks5hNormalizedToSocks5(t *testing.T) {
	for _, raw := range []string{
		"socks5h://u:p@host.example:1080",
		"SOCKS5H://u:p@host.example:1080",
	} {
		u, err := normalizeProxyURL(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if u.Scheme != "socks5" {
			t.Errorf("%s → scheme=%q，期望 socks5", raw, u.Scheme)
		}
	}
	// 明确不支持的协议
	if _, err := normalizeProxyURL("socks4://h:1080"); err == nil {
		t.Error("socks4 应当被拒绝（Go 标准库没有实现）")
	}
	if _, err := normalizeProxyURL("ftp://h:21"); err == nil {
		t.Error("ftp 应当被拒绝")
	}
}

// 地址非法时**整表不生效**（要么全生效、要么全不生效）。
//
// 这条语义是为修一个 fail-open 缺陷而定的：早先是「先应用清理后的表、再报错」，
// 调用方一看有错就 return，跳过了 ResetRouteClients —— 新表已生效、client 缓存
// 还是旧的地址，请求静默从**旧地址**出去，而 UI 显示保存成功。
// 现在出错 = 什么都没变，不存在「一半新一半旧」的中间态。
func TestConfigureRoutesRejectsWholeTableOnInvalidEntry(t *testing.T) {
	defer ResetRoutesForTest()
	if err := ConfigureRoutes(map[string]string{"old": "socks5://u:p@127.0.0.1:1111"}); err != nil {
		t.Fatal(err)
	}
	beforeVer := RouteVersion()

	err := ConfigureRoutes(map[string]string{
		"good": "socks5://u:p@127.0.0.1:1080",
		"bad":  "socks4://u:p@127.0.0.1:1080",
	})
	if err == nil {
		t.Fatal("非法地址没有报错")
	}
	// 整表没动：仍是旧表，版本也没推进
	names := RouteNames()
	if len(names) != 1 || names[0] != "old" {
		t.Fatalf("表被改动了（应当是整表不生效）：%v", names)
	}
	if RouteVersion() != beforeVer {
		t.Errorf("版本被推进了（%d → %d），说明部分生效了", beforeVer, RouteVersion())
	}
	if _, ok := RouteAddress("good"); ok {
		t.Error("非法条目导致整表拒绝，但 good 仍被写进去了")
	}
}

// 保留名不能当成普通线路名保存：否则「配了代理却实际直连」，且看不出来。
func TestConfigureRoutesRejectsDirectReservedName(t *testing.T) {
	defer ResetRoutesForTest()
	if err := ConfigureRoutes(map[string]string{
		DirectRouteName: "socks5://u:p@127.0.0.1:1080",
	}); err == nil {
		t.Fatal("__direct__ 作为线路名应当被拒绝（它的地址会被静默忽略）")
	}
}

// 中文/特殊字符凭据：裸写会被 net/url 拒绝，必须提示编码方式。
func TestRouteErrorDoesNotLeakCredentials(t *testing.T) {
	defer ResetRoutesForTest()
	secret := "sup3rsecret"
	err := ConfigureRoutes(map[string]string{"x": "socks5://user:" + secret + "@127.0.0.1:1080"})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	tr, terr := routes.transportFor("x")
	if terr != nil {
		t.Fatalf("transportFor: %v", terr)
	}
	// Transport 存在即可；真正要断言的是线路名查不到时的错误文本不含地址。
	_ = tr
	_, missingErr := routes.transportFor("nope")
	if missingErr == nil {
		t.Fatal("不存在的线路应当报错")
	}
	if got := missingErr.Error(); strings.Contains(got, secret) {
		t.Fatalf("错误文本泄漏了凭据：%s", got)
	}
}

// RouteUnavailableError 的文本也不能含地址（它可能进日志与 HTTP 响应）。
func TestRouteUnavailableErrorTextIsSafe(t *testing.T) {
	defer ResetRoutesForTest()
	_ = ConfigureRoutes(map[string]string{})
	c := routeTestClient(t, "http://127.0.0.1:1")
	aGhost := &auth.Auth{UID: "u9"}
	aGhost.SetProxyName("ghost")
	_, err := c.clientFor(aGhost, kindShortRPC)
	if err == nil {
		t.Fatal("期望错误")
	}
	if !IsRouteUnavailable(err) {
		t.Fatalf("类型不对：%T", err)
	}
	if strings.Contains(err.Error(), "@") {
		t.Fatalf("错误文本里出现了疑似地址片段：%s", err.Error())
	}
}

// 线路表变更后，旧的 Transport 必须被丢弃（否则新地址不生效）。
func TestConfigureRoutesClearsCache(t *testing.T) {
	defer ResetRoutesForTest()
	_ = ConfigureRoutes(map[string]string{"a": "socks5://u:p@127.0.0.1:1111"})
	first, err := routes.transportFor("a")
	if err != nil {
		t.Fatalf("transportFor: %v", err)
	}
	_ = ConfigureRoutes(map[string]string{"a": "socks5://u:p@127.0.0.1:2222"})
	second, err := routes.transportFor("a")
	if err != nil {
		t.Fatalf("transportFor: %v", err)
	}
	if first == second {
		t.Fatal("换表后仍复用旧 Transport —— 地址变更不会生效")
	}
}

// ── __direct__ 的「绕过环境代理」判据：必须用非回环地址 ──────────────────
//
// 为什么需要子进程：Go 标准库的环境代理是**进程级单次缓存**
// （transport.go 的 envProxyOnce），t.Setenv 在同一进程内改不动它——
// envProxyFunc 第一次调用后就把配置定死了。而 `go test` 进程里别的用例早已
// 触发过它，所以在同一个进程里无法构造「环境里确实有代理」的前提。
//
// 为什么用 127.0.0.2：标准库把 loopback 硬编码为不走代理
// （httpproxy.useProxy：ip.IsLoopback() → false），127.0.0.1 上无论 Proxy 是
// nil 还是 ProxyFromEnvironment 都会直连，判别不了。127.0.0.2 同样是 loopback
// 网段，会被同一条规则绕过——所以目标必须是一个**非回环**地址。
// 这里用 Docker 常见的网关地址段检测不可靠，改为直接问操作系统：若 127.0.0.2
// 以外的非回环地址不可用，用例跳过并说明，不制造假绿。

const directProbeEnv = "WB2A_DIRECT_PROBE_CHILD"

func TestDirectRouteBypassesEnvProxySubprocess(t *testing.T) {
	if os.Getenv(directProbeEnv) == "1" {
		directProbeChild(t)
		return
	}

	// 找一个真实可用的非回环出站地址很难；改用「本机非 loopback 网卡地址」。
	host := firstNonLoopbackIPv4(t)
	if host == "" {
		t.Skip("本机没有非回环 IPv4 网卡，无法构造「环境代理确实生效」的前提")
	}
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Skipf("无法监听 %s：%v", host, err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go serveProbeHTTP(ln)

	// 用一个**关闭的端口**当环境代理：目标本身是活着的（上面已监听），
	// 所以请求若报「连不上 127.0.0.1:1」就证明环境代理确实被采纳了。
	// 比「起一个假代理再猜错误类型」更硬：错误文本里带着代理地址。
	deadProxy := "http://127.0.0.1:1"

	cmd := exec.Command(os.Args[0], "-test.run=^TestDirectRouteBypassesEnvProxySubprocess$", "-test.v")
	cmd.Env = append(os.Environ(),
		directProbeEnv+"=1",
		"WB2A_DIRECT_PROBE_TARGET=http://"+net.JoinHostPort(host, port),
		"WB2A_DIRECT_PROBE_DEAD_PROXY="+deadProxy,
		"HTTP_PROXY="+deadProxy,
		"HTTPS_PROXY="+deadProxy,
		"NO_PROXY=", "no_proxy=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("子进程失败：%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "CHILD-OK") {
		t.Fatalf("子进程没报成功：\n%s", out)
	}
}

// directProbeChild 在子进程里跑：__direct__ 必须不走环境代理，普通线路必须走。
func directProbeChild(t *testing.T) {
	target := os.Getenv("WB2A_DIRECT_PROBE_TARGET")
	deadProxy := os.Getenv("WB2A_DIRECT_PROBE_DEAD_PROXY")
	if target == "" || deadProxy == "" {
		t.Fatal("子进程缺少环境变量")
	}

	cli := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}

	// 先确认前提成立：环境代理确实被采纳了。
	// 判据 = 错误文本里出现代理地址，而不是「随便报了个错」——
	// 目标本身可达，报代理连不上只可能是走了代理。
	if _, err := cli.Get(target); err == nil {
		t.Fatal("环境代理没生效（请求直连成功），本用例的前提不成立")
	} else if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("环境代理未被采纳（错误里没有代理地址）：%v", err)
	}

	// __direct__：Proxy 必须为 nil，请求直连成功。
	direct, err := routes.transportFor(DirectRouteName)
	if err != nil {
		t.Fatalf("direct transport: %v", err)
	}
	if direct.Proxy != nil {
		t.Fatal("__direct__ 的 Proxy 不为 nil")
	}
	directCli := &http.Client{Timeout: 5 * time.Second, Transport: direct}
	resp, err := directCli.Get(target)
	if err != nil {
		t.Fatalf("__direct__ 请求失败：%v", err)
	}
	resp.Body.Close()
	fmt.Println("CHILD-OK")
}

// firstNonLoopbackIPv4 返回本机第一个非回环 IPv4 地址；没有则空串。
func firstNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			return ip4.String()
		}
	}
	return ""
}

// serveProbeHTTP 在父进程里跑一个最小 HTTP 服务（只回 200 ok），供子进程访问。
func serveProbeHTTP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			_, _ = http.ReadRequest(br)
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
		}(c)
	}
}

// 注：这里曾有一版「手工枚举 10 个出站入口」的全覆盖守卫，已删除。
// 变异验证证明它是假绿——把 DesktopChatWithExpert / globalModelsOnce /
// fetchV3ConfigModelMap 改回 c.HTTP.Do，或把 RefreshToken 的账号参数改成 nil，
// 它全部照旧通过（那三个入口根本不在枚举里）。
// 判据换成 egress_gate_test.go 的结构化门禁：源码扫描 + nil 账号扫描。

// ── 线路故障的两种形态都要被归类（C2）────────────────────────────────
//
// 早先只有「线路名不存在 / 地址非法」被包成 RouteUnavailableError；代理本身
// 不可达（端口拒绝、认证失败）是普通 *url.Error，会掉进 handler 的「网络抖动」
// 分支 → 每个候选账号各喂一次连败 → 整池熔断。语义上两者完全同构：换任何账号
// 都是同一条线路、同一个失败。

func TestRouteTransportFailureIsClassified(t *testing.T) {
	defer ResetRoutesForTest()
	SetRouteTransportFactory(func() *http.Transport { return NewRouteTransport() })
	t.Cleanup(func() { SetRouteTransportFactory(nil) })

	// 端口 1 必然拒绝连接
	if err := ConfigureRoutes(map[string]string{"dead": "socks5://u:p@127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	c := &Client{
		HTTP:          &http.Client{Timeout: 2 * time.Second, Transport: NewRouteTransport()},
		BillingBaseCN: "http://127.0.0.1:9", // 目标地址随便，反正连代理就失败
	}
	a := &auth.Auth{UID: "u-dead"}
	a.SetProxyName("dead")

	err := c.ReportChatActivity(a, "conv", "")
	if err == nil {
		t.Fatal("期望连接失败")
	}
	if !IsRouteUnavailable(err) {
		t.Fatalf("代理不可达没有被归类为线路故障（会走换号+罚号）：%T %v", err, err)
	}
	// 错误文本不得泄漏地址里的密码
	if strings.Contains(err.Error(), "u:p@") || strings.Contains(err.Error(), ":p@") {
		t.Errorf("错误文本泄漏了凭据：%s", err)
	}
}

// 认证失败同样归类（需要带认证的 socks 服务器）。
func TestRouteAuthFailureIsClassified(t *testing.T) {
	socks := newSocksServer(t, true) // failAuth
	if err := ConfigureRoutes(map[string]string{"authbad": "socks5://user:pass@" + socks.addr()}); err != nil {
		t.Fatal(err)
	}
	defer ResetRoutesForTest()
	SetRouteTransportFactory(func() *http.Transport { return NewRouteTransport() })
	t.Cleanup(func() { SetRouteTransportFactory(nil) })

	c := &Client{
		HTTP:          &http.Client{Timeout: 3 * time.Second, Transport: NewRouteTransport()},
		BillingBaseCN: "http://127.0.0.1:9",
	}
	a := &auth.Auth{UID: "u-auth"}
	a.SetProxyName("authbad")

	err := c.ReportChatActivity(a, "conv", "")
	if err == nil {
		t.Fatal("认证失败应当报错")
	}
	if !IsRouteUnavailable(err) {
		t.Fatalf("SOCKS 认证失败没有被归类：%T %v", err, err)
	}
	if !strings.Contains(err.Error(), "认证失败") {
		t.Errorf("错误文案不够可行动：%s", err.Error())
	}
}

// ── 换表的原子性（C1 / I5）────────────────────────────────────────────

// 换表后必须重建 client：旧 pair 绑着旧 Transport，不重建就继续从旧地址出去。
func TestRouteVersionAdvancesAndClientRebuilds(t *testing.T) {
	defer ResetRoutesForTest()
	SetRouteTransportFactory(func() *http.Transport { return NewRouteTransport() })
	t.Cleanup(func() { SetRouteTransportFactory(nil) })

	if err := ConfigureRoutes(map[string]string{"r": "socks5://u:p@127.0.0.1:1111"}); err != nil {
		t.Fatal(err)
	}
	c := &Client{HTTP: nil}
	pair1, err := c.routePair("r")
	if err != nil {
		t.Fatal(err)
	}
	v1 := RouteVersion()

	if err := ConfigureRoutes(map[string]string{"r": "socks5://u:p@127.0.0.1:2222"}); err != nil {
		t.Fatal(err)
	}
	if RouteVersion() == v1 {
		t.Error("换表没有推进版本号")
	}
	// 调用方（main / panel）在换表后必须调 ResetRouteClients；这里验证它确实生效
	c.ResetRouteClients()
	pair2, err := c.routePair("r")
	if err != nil {
		t.Fatal(err)
	}
	if pair1 == pair2 {
		t.Fatal("ResetRouteClients 之后仍拿回旧 pair —— 换表不生效")
	}
}

// 聊天路径必须同样归类线路故障（C2 的第二个出站点）。
//
// 这条用例是 bug 驱动的：C2 最初只在 do() 里修，而聊天走的是 chatClient.Do
// （它在循环外解析 client，不走 do），于是聊天仍被当账号抖动 → 换号 + 罚号。
// 只测 do() 的路径无法发现这一点。
func TestChatPathClassifiesRouteFailure(t *testing.T) {
	defer ResetRoutesForTest()
	SetRouteTransportFactory(func() *http.Transport { return NewRouteTransport() })
	t.Cleanup(func() { SetRouteTransportFactory(nil) })

	if err := ConfigureRoutes(map[string]string{"dead": "socks5://u:p@127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	c := &Client{
		HTTP:       &http.Client{Timeout: 2 * time.Second, Transport: NewRouteTransport()},
		ChatHTTP:   &http.Client{Timeout: 0, Transport: NewRouteTransport()},
		ChatBaseCN: "http://127.0.0.1:9",
	}
	a := &auth.Auth{AccessToken: "at", UID: "u-chat"}
	a.SetProxyName("dead")

	rc, _, _, err := c.ChatStreamContext(context.Background(), a, []byte(`{}`), "", ChatMeta{})
	if rc != nil {
		rc.Close()
	}
	if err == nil {
		t.Fatal("期望线路故障")
	}
	if !IsRouteUnavailable(err) {
		t.Fatalf("聊天路径没有归类线路故障（会被当账号抖动换号罚号）：%T %v", err, err)
	}
}

// ── C1/C2：407 只在「这次确实经代理」时才算线路故障 ──────────────────
//
// 同一个错误前提的两个方向：
//
//	C1 漏 —— 聊天路径没有 407 判断，代理认证失败被当 ErrClient 罚号；
//	C2 过宽 —— 绑 __direct__（或无代理）时上游自己回 407，也会被判成线路故障，
//	           于是 407 变成终端错误、永不重试。
func TestProxyAuthOnlyCountsWhenProxied(t *testing.T) {
	// 直连 client：上游自己回 407 → 不该算线路故障
	direct := &http.Client{Transport: &http.Transport{}} // Proxy == nil
	req, _ := http.NewRequest("GET", "http://up.example/", nil)
	if wentThroughProxy(direct, req) {
		t.Error("直连却判定为经代理")
	}

	// 经代理的 client → 算
	u, _ := url.Parse("http://user:pass@proxy.example:8080")
	proxied := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	if !wentThroughProxy(proxied, req) {
		t.Error("经代理却判定为直连")
	}
}

// 绑定 __direct__ 的账号：上游 407 不得被归为线路故障。
func TestDirectRouteDoesNotClassify407AsRouteFailure(t *testing.T) {
	defer ResetRoutesForTest()
	SetRouteTransportFactory(func() *http.Transport { return NewRouteTransport() })
	t.Cleanup(func() { SetRouteTransportFactory(nil) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer srv.Close()

	c := &Client{
		HTTP:          &http.Client{Timeout: 5 * time.Second, Transport: NewRouteTransport()},
		BillingBaseCN: srv.URL,
	}
	a := &auth.Auth{AccessToken: "at", UID: "u"}
	a.SetProxyName(DirectRouteName)

	err := c.ReportChatActivity(a, "conv", "")
	if err == nil {
		t.Fatal("407 应当作为错误返回")
	}
	if IsRouteUnavailable(err) {
		t.Fatalf("直连时上游 407 被误判为线路故障（会导致永不重试）：%v", err)
	}
}
