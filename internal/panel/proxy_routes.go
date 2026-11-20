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
		norm, nerr := upstream.NormalizeProxyURLString(v)
		if nerr != nil {
			// 注意：这里的错误文本不含完整地址（NormalizeProxyURLString 保证）。
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("线路 %q 地址无效：%v", n, nerr))
			return
		}
		next[n] = norm
	}

	if err := p.writeRouteTable(next); err != nil {
		writeErr(w, http.StatusInternalServerError, "写入配置失败："+err.Error())
		return
	}
	// 立即热生效（写盘成功之后）。
	if err := upstream.ConfigureRoutes(next); err != nil {
		// 上面的校验已经挡掉非法地址，走到这里说明是并发/IO 异常；配置已落盘，
		// 必须如实告知而不是假装成功。
		writeErr(w, http.StatusInternalServerError, "线路表已写入，但热生效失败："+err.Error())
		return
	}
	p.cfg.Upstream.ResetRouteClients()

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

	// 校验：必须是空 / 保留直连名 / 线路表里存在的名字。
	if name != "" && name != upstream.DirectRouteName {
		table, err := p.loadRouteTable()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "读取线路表失败："+err.Error())
			return
		}
		if _, ok := table[name]; !ok {
			writeErr(w, http.StatusBadRequest,
				fmt.Sprintf("线路 %q 不存在（先在「设置 → 代理」里添加）", name))
			return
		}
	}

	// 改内存里的**同一个** *auth.Auth（Pool.AuthByUID 返回池内指针）→ 立即热生效。
	a.Lock()
	a.ProxyName = name
	a.Unlock()

	// 落盘：改的是 ProxyName，但 SaveAtomic 会整份重写，所以必须持有完整凭证。
	// 失败要回滚内存（否则出现「本次运行生效、重启后还原」的幻觉）。
	if err := a.SaveAtomic(); err != nil {
		a.Lock()
		a.ProxyName = ""
		a.Unlock()
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
	if err != nil || u.User == nil {
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
	a.Lock()
	defer a.Unlock()
	return a.ProxyName
}
