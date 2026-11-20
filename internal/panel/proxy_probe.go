// proxy_probe.go 「测试出口」：经指定线路发一次轻请求，回出口 IP 与归属地。
//
// 为什么必须有这个能力：配住宅代理时最该确认的就是「出口到底落在哪」。
// 没有它，用户只能配完去发一条真实聊天，从错误里猜是线路不通、认证失败，
// 还是出口落在了意料之外的国家。
//
// 两条设计约束：
//
//  1. **失败原因原样回给界面**：连不上 / 认证失败 / 超时是三件不同的事，
//     对应三种不同的修法，折叠成「代理不可用」等于让用户自己猜。
//  2. **探测不经账号**：它验证的是「这条线路本身通不通」，与哪个账号无关。
package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// ProbeURLDefault 默认的出口信息查询端点。
//
// 选 ipinfo.io/json：免费、无需 key、返回稳定 JSON。出口检查服务各区域可达性
// 差别很大，所以做成可配置（Panel.Config.ProbeURL），不写死。
const ProbeURLDefault = "https://ipinfo.io/json"

// probeTimeout 探测总时长上限。比普通请求短：用户在等一个即时反馈。
const probeTimeout = 8 * time.Second

// probeResult 一次探测的结果（字段名与前端逐个对应）。
type probeResult struct {
	OK       bool   `json:"ok"`
	MS       int    `json:"ms"`
	ExitIP   string `json:"exit_ip,omitempty"`
	ExitInfo string `json:"exit_info,omitempty"`
	Error    string `json:"error,omitempty"`
	Notice   string `json:"notice,omitempty"`
}

// probeRouteHandler POST /panel/api/proxy/probe
//
// body: {"name":"hk-1"} —— 必须已在线路表里（不接受任意地址）。
//
// 不接受任意地址是刻意的：否则这个接口变成一个开放探测口，登录用户填个内网
// 地址就能让面板去打 169.254.169.254 之类的元数据服务。
func (p *Panel) probeRouteHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求失败："+err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "缺少线路名")
		return
	}

	table, err := p.loadRouteTable()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取线路表失败："+err.Error())
		return
	}
	raw, ok := table[name]
	if !ok {
		writeErr(w, http.StatusNotFound, "线路不存在")
		return
	}

	target := p.cfg.ProbeURL
	if target == "" {
		target = ProbeURLDefault
	}
	writeJSON(w, http.StatusOK, probeThroughRoute(r.Context(), raw, target))
}

// probeThroughRoute 用指定线路发一次探测请求。不经过任何账号。
func probeThroughRoute(ctx context.Context, rawURL, target string) probeResult {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return probeResult{Error: "线路地址格式错误（凭据含特殊字符时需要百分号编码）"}
	}

	// 不在上游路线缓存里取 Transport：探测是独立的、用完即弃，避免与真实请求
	// 共用连接池互相干扰（测试把池里的连接打到一半，下一发真实请求会撞上）。
	tr := upstream.NewRouteTransport()
	tr.Proxy = http.ProxyURL(u)
	client := &http.Client{Timeout: probeTimeout, Transport: tr}
	defer tr.CloseIdleConnections()

	started := time.Now()
	ms := func() int { return int(time.Since(started) / time.Millisecond) }

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return probeResult{MS: ms(), Error: err.Error()}
	}
	req.Header.Set("User-Agent", "workbuddy2api-panel-probe")

	resp, err := client.Do(req)
	if err != nil {
		return probeResult{MS: ms(), Error: proxyErrText(err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return probeResult{MS: ms(), Error: "出口返回 HTTP " + strconv.Itoa(resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return probeResult{MS: ms(), Error: "读取响应失败：" + err.Error()}
	}

	var doc struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Org      string `json:"org"`
		Query    string `json:"query"`       // ip-api.com
		Country2 string `json:"countryCode"` // ip-api.com
	}
	_ = json.Unmarshal(body, &doc)

	ip := firstNonEmpty(doc.IP, doc.Query)
	if ip == "" {
		// 解析不出 IP 不算失败（出口可能是个只回纯文本的检查服务），但要如实说。
		return probeResult{MS: ms(), OK: true,
			Notice: "已连通，但没能从响应里解析出出口 IP —— 检查探测端点是否返回 JSON"}
	}
	return probeResult{
		MS:       ms(),
		OK:       true,
		ExitIP:   ip,
		ExitInfo: strings.Join(nonEmpty(doc.Country, doc.Region, doc.City, doc.Org), " · "),
	}
}

// proxyErrText 把底层错误翻成可行动的句子。
//
// 不直接透传 err.Error()：里面可能带完整代理地址，而地址里有密码。
func proxyErrText(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "username/password authentication failed"):
		return "代理认证失败：检查地址里的用户名和密码（特殊字符需要百分号编码）"
	case strings.Contains(s, "connection refused"):
		return "代理端口拒绝连接：确认地址、端口和代理进程是否在运行"
	case strings.Contains(s, "no such host"), strings.Contains(s, "lookup "):
		return "代理域名解析失败：检查地址拼写"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline exceeded"):
		return "连接代理超时：检查网络可达性与代理地址"
	case strings.Contains(s, "context canceled"):
		return "已取消"
	case strings.Contains(s, "certificate"):
		return "TLS 证书校验失败：出口可能在做中间人（企业网络 / 透明代理）"
	}
	return redactUserinfo(s)
}

// redactUserinfo 把形如 scheme://user:pass@host 的凭据段替换掉。
func redactUserinfo(s string) string {
	const marker = "://"
	for {
		i := strings.Index(s, marker)
		if i < 0 {
			return s
		}
		rest := s[i+len(marker):]
		at := strings.Index(rest, "@")
		if at < 0 {
			return s
		}
		// 只有 userinfo 段里出现 ':' 才视为凭据，避免误伤正常的 host@path 文本
		if !strings.Contains(rest[:at], ":") {
			return s
		}
		s = s[:i+len(marker)] + "***@" + rest[at+1:]
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func nonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}
