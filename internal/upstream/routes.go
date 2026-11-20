// routes.go 账号级出口线路表：线路名 → 代理地址，以及每条线路专属的出站 Transport。
//
// 背景：面板此前没有任何账号级代理能力，出站只有 newTransport() 里的
// `Proxy: http.ProxyFromEnvironment`（进程级），多账号共用宿主出口 IP。平台侧
// 「多号同 IP」是最容易关联的特征，所以这里按线路名构造/缓存 Transport。
//
// 三条必须守住的性质（与 workbuddy-manager 的 0007/0013 补丁同一取向）：
//
//  1. **连接池必须分开**：共用一份 Transport 会把 A 线路的空闲连接复用给 B 线路，
//     出口照样会串——看起来「配了」实际「没隔离」，是最坏的一种失败。
//  2. **线路不可用就明确报错**，绝不静默回落到直连或环境代理。静默回落等于
//     「以为隔离了其实没有」，且这种错误没人会发现。
//  3. **不改动共享 Transport**：未绑定线路的账号走原来那份，行为逐字不变（零回归）。
//
// 装配期参数（详见 Client.NewRouteTransport）：本文件只负责「按名字造 Transport」，
// 具体参数由 main 注入——因为 ResponseHeaderTimeout / DNS dialer 是进程装配期
// 决定的，直接调 newTransport() 会拿到默认值，等于给绑线路的账号偷偷换了超时和
// 解析器。
package upstream

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// DirectRouteName 账号级「强制直连」的保留线路名：绕过线路池**和**环境变量代理。
//
// 为什么需要它：进程级配了 HTTP_PROXY 的部署里，「这个号要走直连」否则无解——
// 空名字只能表达「跟随默认」，而默认可能就是那个环境代理。
const DirectRouteName = "__direct__"

// 线路名允许的字符集：会出现在账号文件与界面上，限定为可安全放进 JSON/URL 的集合。
// 与 workbuddy-manager 的 proxyroutes.NAME_RE 保持同一口径（两边可能共用一份配置）。
const routeNameMaxLen = 32

// routeTable 线路表 + 每条线路的 Transport 缓存。
//
// table 与 cache 分开：清表时两个都要重置，但 cache 的键比 table 多一个
// DirectRouteName（保留名不需要出现在线路表里）。
type routeTable struct {
	mu    sync.RWMutex
	table map[string]string
	cache map[string]*http.Transport

	// newTransport 由 main 注入的 Transport 构造器（已带好装配期参数：超时、DNS）。
	// 未注入时回落 newTransport()——那是「测试裸用/装配未接线」的安全网，生产必须注入。
	newTransport func() *http.Transport
}

var routes = &routeTable{
	table: map[string]string{},
	cache: map[string]*http.Transport{},
}

// SetRouteTransportFactory 注入线路 Transport 的构造器。
//
// main 必须在装配完共享 Transport（改好 ResponseHeaderTimeout、装好 DNS dialer）
// 之后调用，并传入「用同一份参数新建一个 Transport」的闭包。这样线路 Transport
// 与共享 Transport 的参数永远一致——将来加第三个装配期参数时只改 main 一处。
func SetRouteTransportFactory(fn func() *http.Transport) {
	routes.mu.Lock()
	defer routes.mu.Unlock()
	routes.newTransport = fn
	// 已缓存的 Transport 是用旧构造器造的，必须丢弃（否则新旧参数并存）。
	for name, tr := range routes.cache {
		tr.CloseIdleConnections()
		delete(routes.cache, name)
	}
}

// ConfigureRoutes 注入「线路名 → 代理地址」表（启动时与保存配置时各调一次；传 nil 清空）。
//
// 地址非法时**返回 error 而不是静默丢弃**：启动期宁可带着一条错误日志起来，
// 也要让人看见「这条线路配错了」；保存期由调用方直接拒绝落盘。
func ConfigureRoutes(table map[string]string) error {
	clean := make(map[string]string, len(table))
	var bad []string
	for name, addr := range table {
		n := strings.TrimSpace(name)
		v := strings.TrimSpace(addr)
		if n == "" || v == "" {
			continue
		}
		if _, err := normalizeProxyURL(v); err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", n, err))
			continue
		}
		clean[n] = v
	}

	routes.mu.Lock()
	defer routes.mu.Unlock()
	// 换表必须清缓存：地址改了要继续用旧代理连接就是串出口。
	for _, tr := range routes.cache {
		tr.CloseIdleConnections()
	}
	routes.table = clean
	routes.cache = map[string]*http.Transport{}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("出口线路地址无效：%s", strings.Join(bad, "；"))
	}
	return nil
}

// RouteNames 已配置的线路名（升序；供启动日志与面板下拉）。
func RouteNames() []string {
	routes.mu.RLock()
	defer routes.mu.RUnlock()
	out := make([]string, 0, len(routes.table))
	for name := range routes.table {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// RouteAddress 返回线路名对应的地址（脱敏由调用方做）；第二条返回是否配置过。
func RouteAddress(name string) (string, bool) {
	routes.mu.RLock()
	defer routes.mu.RUnlock()
	addr, ok := routes.table[name]
	return addr, ok
}

// normalizeProxyURL 校验并归一化代理地址。
//
//	`socks5h://` 与 `socks5://` 归一成 `socks5://`：实测（Go 1.25，自建
//	SOCKS5 服务器抓包）两者行为完全一致——都以 atyp=3 把**域名**交给代理解析，
//	本地不做 DNS。归一化消除了 Go 1.22 及更早不认识 socks5h 的版本边界
//	（那些版本会当成 http 代理去 `lookup socks5h` 而失败）。
//
// `socks4` 不支持：Go 标准库没有实现。
func normalizeProxyURL(raw string) (*url.URL, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, fmt.Errorf("代理地址为空")
	}
	u, err := url.Parse(v)
	if err != nil {
		// url.Parse 的原始错误里会带完整地址（含密码）。这里只报「格式错误」，
		// 由调用方在需要的场合另行脱敏——但错误文本本身不得含凭据。
		return nil, fmt.Errorf("代理地址格式错误（凭据含中文或特殊字符时需要百分号编码）")
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5h":
		u.Scheme = "socks5"
	case "socks5", "http", "https":
		// 原样
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q（需要 http / https / socks5 / socks5h）", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("代理地址缺少主机名")
	}
	if u.Port() == "" {
		return nil, fmt.Errorf("代理地址缺少端口")
	}
	return u, nil
}

// ValidateRouteName 线路名合法性（与 workbuddy-manager 同口径，便于两边共用配置）。
func ValidateRouteName(name string) error { return validateRouteName(name) }

// NormalizeProxyURLString 校验并归一化代理地址，返回字符串形式（面板保存用）。
//
// 错误文本不含原始地址：地址里可能有密码，这条错误会进 HTTP 响应与日志。
func NormalizeProxyURLString(raw string) (string, error) {
	u, err := normalizeProxyURL(raw)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// validateRouteName 线路名合法性（与 manger 同口径，便于两边共用配置）。
func validateRouteName(name string) error {
	if name == "" {
		return fmt.Errorf("线路名不能为空")
	}
	if len(name) > routeNameMaxLen {
		return fmt.Errorf("线路名最多 %d 个字符", routeNameMaxLen)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return fmt.Errorf("线路名只能包含字母、数字与 . _ -")
		}
	}
	return nil
}

// transportFor 返回线路名对应的出站 Transport。
//
//	空名      → 共享 Transport（调用方另行处理，见 Client.clientFor）
//	保留直连名 → 无代理 Transport（Proxy == nil，绕过环境变量）
//	已配置    → 该线路专属 Transport（按名缓存，连接池与其它线路隔离）
//	未配置    → error（调用方据此返回 ErrRouteUnavailable，**不静默直连**）
func (t *routeTable) transportFor(name string) (*http.Transport, error) {
	if name == DirectRouteName {
		return t.transportDirect()
	}

	t.mu.RLock()
	addr, known := t.table[name]
	cached := t.cache[name]
	t.mu.RUnlock()

	if !known {
		return nil, &routeError{name: name, reason: "线路不存在"}
	}
	if cached != nil {
		return cached, nil
	}

	u, err := normalizeProxyURL(addr)
	if err != nil {
		return nil, &routeError{name: name, reason: err.Error()}
	}

	tr := t.build()
	tr.Proxy = http.ProxyURL(u)

	t.mu.Lock()
	defer t.mu.Unlock()
	// 双检：并发首次构造时只保留一个，其余丢弃（否则连接池会分裂）。
	if again := t.cache[name]; again != nil {
		tr.CloseIdleConnections()
		return again, nil
	}
	if t.cache == nil {
		t.cache = map[string]*http.Transport{}
	}
	t.cache[name] = tr
	return tr, nil
}

// transportDirect 强制直连的 Transport：Proxy == nil 才是真正绕开环境代理。
//
// 注意 `Proxy: nil` 与 `Proxy` 返回 nil URL 不同：前者根本不查代理，
// 后者仍会走 ProxyFromEnvironment 的判断链。这里必须是前者。
func (t *routeTable) transportDirect() (*http.Transport, error) {
	t.mu.RLock()
	cached := t.cache[DirectRouteName]
	t.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	tr := t.build()
	tr.Proxy = nil

	t.mu.Lock()
	defer t.mu.Unlock()
	if again := t.cache[DirectRouteName]; again != nil {
		tr.CloseIdleConnections()
		return again, nil
	}
	if t.cache == nil {
		t.cache = map[string]*http.Transport{}
	}
	t.cache[DirectRouteName] = tr
	return tr, nil
}

// build 用注入的构造器造一个新 Transport；未注入时回落默认（仅测试/未接线）。
func (t *routeTable) build() *http.Transport {
	t.mu.RLock()
	fn := t.newTransport
	t.mu.RUnlock()
	if fn != nil {
		return fn()
	}
	return newTransport()
}

// routeError 线路解析失败。实现 error 且**不包含代理地址**（避免凭据进日志）。
type routeError struct {
	name   string
	reason string
}

func (e *routeError) Error() string {
	return fmt.Sprintf("出口线路 %q 不可用：%s", e.name, e.reason)
}

// TransportForRoute 返回线路名对应的出站 Transport（供「登录流程」这类
// 没有账号上下文的调用方使用）。
//
// 与 clientFor 的区别：这里不做「空名回落共享 client」的处理——调用方明确要
// 某条线路，查不到就该报错。
func TransportForRoute(name string) (*http.Transport, error) {
	return routes.transportFor(strings.TrimSpace(name))
}

// NewRouteTransport 构造一个**不带代理**的出站 Transport，参数与共享 Transport
// 同源（newTransport）。专供线路 Transport 使用：调用方（cmd/server/main.go）在
// 本函数返回后按装配期配置补齐 ResponseHeaderTimeout / DialContext，再交给
// SetRouteTransportFactory。
//
// 为什么不直接让调用方用 newTransport()：newTransport 是本包私有函数，而线路
// Transport 的构造必须发生在 main（那里才知道 config 的装配期参数）。对外只暴露
// 「造一个参数同源的 Transport」这一件事，本包的加固参数就不会漏。
func NewRouteTransport() *http.Transport {
	return newTransport()
}

// ResetRoutesForTest 清空线路表与缓存（仅测试用；生产没有「清空线路」的路径）。
func ResetRoutesForTest() {
	routes.mu.Lock()
	defer routes.mu.Unlock()
	for _, tr := range routes.cache {
		tr.CloseIdleConnections()
	}
	routes.table = map[string]string{}
	routes.cache = map[string]*http.Transport{}
	routes.newTransport = nil
}
