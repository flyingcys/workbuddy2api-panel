// config.go 面板配置页接口：读取当前配置、校验并保存（热生效 + 重启项标注）。
//
// 分工：cmd/server 持有 Config 类型与校验逻辑（Load/normalize），此处只做
// HTTP 编排——GET 回显、POST 透传给注入的 SaveConfig 闭包（由 main 完成
// "校验 → 落盘 → 热应用 → 返回需重启字段列表"）。
package panel

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

// getConfig 返回当前配置文件内容与路径（前端按 schema 渲染表单）。
func (p *Panel) getConfig(w http.ResponseWriter, r *http.Request) {
	if p.cfg.LoadConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	cfg, err := p.cfg.LoadConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"path":   p.cfg.ConfigPath,
		"config": redactConfigProxies(cfg),
	})
}

// saveConfig 保存配置：body 直接是配置 JSON（前端按 schema 组装完整对象）。
// SaveConfig 闭包内部完成校验+落盘+热应用；校验失败返回 400 且不写盘。
func (p *Panel) saveConfig(w http.ResponseWriter, r *http.Request) {
	if p.cfg.SaveConfig == nil {
		writeErr(w, http.StatusNotImplemented, "config api not available")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	restartRequired, err := p.cfg.SaveConfig(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if restartRequired == nil {
		restartRequired = []string{}
	}
	log.Printf("panel: 配置已保存（热生效完成；需重启字段 %d 个）", len(restartRequired))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"restart_required": restartRequired,
	})
}

// redactConfigProxies 把配置里的代理密码打成 *** 再回给浏览器。
//
// 为什么必须在这里做：`GET /panel/api/config` 返回的是整个 Config 结构体，
// 新增的 Proxies 段直接带着明文密码。而「凭据只进不出」是这个功能写在文件头的
// 硬约束——线路页（/proxy/routes）做脱敏、配置页漏掉，等于绕过去了。
//
// 做法是走 JSON 中转再改一段：Config 的具体类型由 main 注入（any），
// 这里不能直接断言字段。
func redactConfigProxies(cfg any) any {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return cfg
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return cfg
	}
	seg, ok := doc["proxies"]
	if !ok {
		return cfg
	}
	var table map[string]string
	if err := json.Unmarshal(seg, &table); err != nil {
		return cfg
	}
	for name, addr := range table {
		masked, _ := maskProxyURL(addr)
		table[name] = masked
	}
	redacted, err := json.Marshal(table)
	if err != nil {
		return cfg
	}
	doc["proxies"] = redacted
	out, err := json.Marshal(doc)
	if err != nil {
		return cfg
	}
	return json.RawMessage(out)
}
