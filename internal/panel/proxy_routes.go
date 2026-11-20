// routes.go 面板「设置 → 代理」接口：线路表增删改 + 账号出口绑定。
//
// 两处配置分属不同的存放位置：
//
//	· 线路表（线路名 → 代理地址）→ config.json 的 `proxies` 段
//	· 账号绑定（线路名）        → auths/workbuddy-<uid>.json 顶层 `proxy`
//
// 凭据只进不出：读接口一律回脱敏串（密码显示为 ***）；编辑时提交的仍是脱敏串
// 就沿用原密码（改域名不必重输密码）；日志与错误文本只出现线路名，不出现地址。
package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// proxyMask 脱敏占位符（与 workbuddy-manager 同一口径，便于共用配置）。
const proxyMask = "***"

// routeView 线路的单条视图（地址已脱敏）。
type routeView struct {
	Name     string `json:"name"`
	URL      string `json:"url"`       // 脱敏后的地址
	HasCreds bool   `json:"has_creds"` // 地址里带用户名/密码
	// Accounts 绑在这条线路上的账号数（删除前的影响面提示）。
	Accounts int `json:"accounts"`
}

// routesHandler GET /panel/api/proxy/routes
func (p *Panel) routesHandler(w http.ResponseWriter, r *http.Request) {
	table, err := p.loadRouteTable()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取线路表失败："+err.Error())
		return
	}
	bound := p.boundRouteCounts()

	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]routeView, 0, len(names))
	for _, name := range names {
		masked, hasCreds := maskProxyURL(table[name])
		out = append(out, routeView{
			Name:     name,
			URL:      masked,
			HasCreds: hasCreds,
			Accounts: bound[name],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"routes": out,
		// 保留名与它的语义，前端据此在账号下拉里展示「强制直连」。
		"direct_name": upstream.DirectRouteName,
		// 是否可写（ConfigPath 未注入时只读展示）。
		"writable": p.cfg.ConfigPath != "",
	})
}

// routesSaveHandler PUT /panel/api/proxy/routes
//
// body: {"routes": {"hk-1": "socks5://user:pass@host:1080", ...}}
// 提交的地址里若含 *** 则沿用已存的密码；整表替换（与前端表格编辑一致）。
func (p *Panel) routesSaveHandler(w http.ResponseWriter, r *http.Request) {
	if p.cfg.ConfigPath == "" {
		writeErr(w, http.StatusNotImplemented, "未配置 config.json 路径，线路表不可写")
		return
	}
	var body struct {
		Routes map[string]string `json:"routes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求失败："+err.Error())
		return
	}

	old, err := p.loadRouteTable()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取现有线路表失败："+err.Error())
		return
	}

	next := make(map[string]string, len(body.Routes))
	for name, raw := range body.Routes {
		n := strings.TrimSpace(name)
		if err := upstream.ValidateRouteName(n); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("线路名 %q 不合法：%v", n, err))
			return
		}
		v := strings.TrimSpace(raw)
		if v == "" {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("线路 %q 的地址为空", n))
			return
		}
		// 脱敏串还原：界面回显的就是 ***，用户没改密码时提交回来的仍是它。
		if strings.Contains(v, proxyMask) {
			prev := old[n]
			if prev == "" {
				writeErr(w, http.StatusBadRequest,
					fmt.Sprintf("线路 %q 的地址里还有 %s，但服务端没有已保存的密码可还原，请粘贴完整地址", n, proxyMask))
				return
			}
			merged, merr := mergeMaskedProxy(v, prev)
			if merr != nil {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("线路 %q：%v", n, merr))
				return
			}
			v = merged
		}
		// 保留名：transportFor 对它走 transportDirect()，表里的地址会被静默忽略。
		// 必须在**落盘之前**挡住 —— ConfigureRoutes 也会拒，但那时文件已经写过了，
		// 一次误操作会把整张表（含正常线路）从「全部生效」打成「全部不生效」。
		if n == upstream.DirectRouteName {
			writeErr(w, http.StatusBadRequest,
				fmt.Sprintf("%s 是保留名（表示「强制直连」），不能当作线路名", n))
			return
		}
		norm, nerr := upstream.NormalizeProxyURLString(v)
		if nerr != nil {
			// 注意：这里的错误文本不含完整地址（NormalizeProxyURLString 保证）。
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("线路 %q 地址无效：%v", n, nerr))
			return
		}
		next[n] = norm
	}

	// **先试热生效，成功才落盘**。
	//
	// 反过来（先落盘再热生效）有个实测过的坏结果：ConfigureRoutes 拒绝时文件已经
	// 写进去，下次启动整表不生效（它是「要么全生效、要么全不生效」的），而面板
	// 返回 500 让人以为「保存失败了」。一次误操作就把正常线路一起打掉。
	// 这个顺序下，任何拒绝都发生在文件被碰之前。
	if err := upstream.ConfigureRoutes(next); err != nil {
		writeErr(w, http.StatusBadRequest, "线路表未生效（配置未改动）："+err.Error())
		return
	}
	if err := p.writeRouteTable(next); err != nil {
		// 热生效了但落盘失败：把内存表退回去，避免「本次运行生效、重启后还原」。
		_ = upstream.ConfigureRoutes(old)
		p.cfg.Upstream.ResetRouteClients()
		writeErr(w, http.StatusInternalServerError, "写入配置失败（线路表已回滚）："+err.Error())
		return
	}
	p.cfg.Upstream.ResetRouteClients()
	// 登录 client 持有的是已解析的 *http.Transport，换表后必须重建 ——
	// 否则「在代理页删掉一条线路」之后，登录流程仍然从那条（已删除的）线路出去，
	// 且发生在账号还不存在、无法用账号诊断的时刻。
	if err := p.rebuildLoginProxy(); err != nil {
		// 登录线路失效不该让整个保存失败（线路表已落盘并生效），但**必须回落**：
		// rebuildLoginProxy 失败时若不显式清空，loginHTTP 会继续用那条已删除线路的
		// Transport —— 正是 I6 要防的「登录仍从已删除的线路出去」。
		_ = SetLoginProxy("")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "count": len(next),
			"login_proxy_warning": err.Error() + "（登录流程已回落默认出口）",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(next)})
}

// accountsHandler 的扩展：返回每个账号当前绑定的线路名 + 可用线路列表。
// 账号列表本身由 overview 返回（Pool.List），这里只补线路相关字段。
func (p *Panel) routeBindings() map[string]string {
	out := map[string]string{}
	for _, st := range p.cfg.Pool.List() {
		if st.ProxyName != "" {
			out[st.UID] = st.ProxyName
		}
	}
	return out
}

// boundRouteCounts 每条线路被多少个账号绑定（删除前的影响面）。
func (p *Panel) boundRouteCounts() map[string]int {
	counts := map[string]int{}
	for _, name := range p.routeBindings() {
		counts[name]++
	}
	return counts
}

// accountProxyHandler PUT /panel/api/accounts/{uid}/proxy
//
// body: {"proxy": "hk-1"} —— 空串 = 跟随默认出口；"__direct__" = 强制直连。
func (p *Panel) accountProxyHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	a := p.cfg.Pool.AuthByUID(uid)
	if a == nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}

	var body struct {
		Proxy *string `json:"proxy"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "解析请求失败："+err.Error())
		return
	}
	if body.Proxy == nil {
		writeErr(w, http.StatusBadRequest, "缺少 proxy 字段")
		return
	}
	name := strings.TrimSpace(*body.Proxy)

	// 校验：必须是空 / 保留直连名 / **生效表**里存在的名字。
	//
	// 必须查生效表（upstream.RouteAddress）而不是直读 config.json：非法条目会被
	// ConfigureRoutes 整表拒绝，此时文件里有、内存表里没有。查文件会放行一个
	// 「绑定成功但请求立刻失败」的状态，并把用户引向线路故障的罚号链。
	if name != "" && name != upstream.DirectRouteName {
		if err := upstream.ValidateRouteName(name); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("线路名不合法：%v", err))
			return
		}
		if _, ok := upstream.RouteAddress(name); !ok {
			writeErr(w, http.StatusBadRequest,
				fmt.Sprintf("线路 %q 不存在或未生效（先在「设置 → 代理」里添加并保存）", name))
			return
		}
	}

	// 记下原值：写盘失败要**回滚到原值**，不是回滚到空。
	// 回滚成空串会让本次运行走默认出口、磁盘仍是旧线路 —— 重启后又变回去，
	// 两个方向都不对且难以察觉。
	prev := a.ProxyNameValue()
	a.SetProxyName(name)

	// 落盘：改的是 ProxyName，但 SaveAtomic 会整份重写，所以必须持有完整凭证。
	if err := a.SaveAtomic(); err != nil {
		a.SetProxyName(prev)
		writeErr(w, http.StatusInternalServerError, "写入账号文件失败："+err.Error())
		return
	}
	// 绑定变了，旧的线路 client 缓存可能不再适用（线路名 → client 的映射按名缓存，
	// 名不变时复用是对的；这里只在名称变化时清一次，避免长期运行后字典膨胀）。
	p.cfg.Upstream.ResetRouteClients()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "uid": uid, "proxy": name})
}

// ── 配置读写（只动 proxies 段，保留其它键）───────────────────────────────

// loadRouteTable 读 config.json 的 proxies 段。
func (p *Panel) loadRouteTable() (map[string]string, error) {
	raw, err := os.ReadFile(p.cfg.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]string{}
	seg, ok := doc["proxies"]
	if !ok {
		return out, nil
	}
	if err := json.Unmarshal(seg, &out); err != nil {
		return nil, fmt.Errorf("proxies 段格式不对：%w", err)
	}
	if out == nil {
		out = map[string]string{}
	}
	return out, nil
}

// writeRouteTable 只替换 proxies 段，其余键原样保留。
//
// 为什么不走 SaveConfig 闭包：那条路径要求提交**完整配置**并做 schema 校验，
// 而这里只改一个段。但保留未知键的原则必须一致——所以这里也是「读原 map →
// 改一个键 → 写回」，而不是结构体序列化。
func (p *Panel) writeRouteTable(table map[string]string) error {
	path := p.cfg.ConfigPath
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	doc := map[string]json.RawMessage{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("现有配置不是合法 JSON：%w", err)
		}
	}
	if len(table) == 0 {
		delete(doc, "proxies") // 空表就把键删掉，保持文件干净
	} else {
		seg, err := json.Marshal(table)
		if err != nil {
			return err
		}
		doc["proxies"] = seg
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// 单文件 bind mount 无法 rename 覆盖（EBUSY）：与 saveConfig 的处理一致。
		f, oerr := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
		if oerr != nil {
			_ = os.Remove(tmp)
			return oerr
		}
		_, werr := f.Write(append(out, '\n'))
		cerr := f.Close()
		if werr != nil {
			return fmt.Errorf("写入失败（完整内容保留在 %s）：%w", tmp, werr)
		}
		_ = os.Remove(tmp)
		return cerr
	}
	return nil
}

// ── 地址脱敏与还原 ────────────────────────────────────────────────────

// maskProxyURL 把密码替换为 ***。返回 (脱敏串, 是否带凭据)。
func maskProxyURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		// 解析不了也要**藏住**：这条路径处理的是从 config.json 直接读出的值
		// （写入口会校验，但读入口不校验），原样返回等于把明文密码发给浏览器。
		// 用粗粒度打码：保留 scheme（便于识别协议），其余全部遮掉。
		return maskRawProxy(raw), true
	}
	if u.User == nil {
		return raw, false
	}
	if _, hasPass := u.User.Password(); !hasPass {
		return raw, false
	}
	// 用 *** 而不是 url.Redacted() 的 xxxxx：面板把脱敏串原样提交回来时靠
	// proxyMask 识别「密码没改」，两处必须是同一个标记。
	//
	// 不走 url.String()：它会把 * 百分号编码成 %2A，前端拿到的就不是 *** 了，
	// 回读识别随之失效。这里手工拼——用户名保留原编码，主机端口本就不含特殊字符。
	user := u.User.Username()
	hostPart := u.Host
	out := u.Scheme + "://"
	if enc := (&url.URL{User: url.User(user)}).String(); enc != "" {
		// 取 "scheme://user@" 里的 user 段，确保与原串同样的编码口径
		if i := strings.Index(enc, "://"); i >= 0 {
			rest := enc[i+3:]
			if j := strings.LastIndex(rest, "@"); j >= 0 {
				user = rest[:j]
			}
		}
	}
	out += user + ":" + proxyMask + "@" + hostPart
	return out, true
}

// maskRawProxy 粗粒度打码：解析不出结构时，按 scheme://***@host 的形态藏。
//
// 解析失败常见于凭据里有未编码的特殊字符（`p ss`、`p%zz`）——恰恰是最危险的
// 明文形态，因为写入口会拒绝它，于是它只可能来自手改 config.json，必须照样遮。
func maskRawProxy(raw string) string {
	v := strings.TrimSpace(raw)
	scheme := "proxy"
	if i := strings.Index(v, "://"); i > 0 {
		scheme = v[:i]
		v = v[i+3:]
	}
	host := v
	if at := strings.LastIndex(v, "@"); at >= 0 {
		host = v[at+1:]
	}
	// 连 host 都可能有敏感信息（内网域名），只留 scheme 更稳妥；但如果能确定
	// 有 userinfo，host 部分对排查是必要的（确认填的是哪台机器），故保留。
	if strings.Contains(v, "@") {
		return scheme + "://***@" + host
	}
	return scheme + "://***"
}

// mergeMaskedProxy 把提交串里的 *** 用已存的密码替换。
//
// 要求「用户名也一致」：用户名不同说明用户换了一整套凭据却漏填密码，
// 沿用旧密码会得到一个必然认证失败的组合，不如直接报错。
func mergeMaskedProxy(submitted, stored string) (string, error) {
	su, err := url.Parse(submitted)
	if err != nil {
		return "", fmt.Errorf("地址格式错误（凭据含中文或特殊字符时需要百分号编码）")
	}
	st, err := url.Parse(stored)
	if err != nil || st.User == nil {
		return "", fmt.Errorf("已保存的地址无法还原密码")
	}
	if su.User == nil {
		return "", fmt.Errorf("提交的地址缺少凭据")
	}
	storedUser := st.User.Username()
	storedPass, _ := st.User.Password()
	if su.User.Username() != storedUser {
		return "", fmt.Errorf("用户名与已保存的不一致，请粘贴完整地址（含密码）")
	}
	if storedPass == "" {
		return "", fmt.Errorf("已保存的地址没有密码可还原")
	}
	su.User = url.UserPassword(storedUser, storedPass)
	return su.String(), nil
}

// accountProxyView 账号的线路绑定（供 overview 内嵌）。
func (p *Panel) accountProxyView(a *auth.Auth) string {
	if a == nil {
		return ""
	}
	return a.ProxyNameValue()
}
