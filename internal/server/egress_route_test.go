package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// N1 判据：refresh 前置分支遇到线路故障时，必须**跳过该号继续轮转**，
// 而不是 break 整池失败。
//
// 早先 chat 的 ChatStreamContext 分支改成了 continue，refresh 分支仍是 break，
// 结果是同一种失败原因走不同路径给用户两种答案：refresh 前置返回 503
// 「没有可用账号」且健康号一次都没被尝试。
func TestChatRefreshRouteFailureSkipsToHealthyAccount(t *testing.T) {
	// refresh 端点必须返回**刷新响应**而不是 SSE：假上游按路径区分。
	// （第一版这里一律回 sseOK，导致 a2 的 refresh 解析失败 → 被当账号错误，
	// 用例红得莫名其妙。夹具的错，不是实现的错。）
	up := newFakeUpstream(t, func(string) (int, string, bool) {
		return 200, sseOK, true
	})
	up.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v2/plugin/auth/token/refresh" {
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				// doJSON 会解外层信封（{code,msg,data}），refresh 的 token 在 data 里。
				// 少了这层包装会走到 "refresh_failed: no accessToken"，
				// 被当成账号错误 —— 夹具的错，不是实现的错（调试花了些时间）。
				Body: io.NopCloser(strings.NewReader(
					`{"code":0,"msg":"OK","data":{"accessToken":"at-new","refreshToken":"rt-new","expiresIn":3600}}`)),
				Request: r,
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader(sseOK)),
			Request:    r,
		}, nil
	})}
	// 让 a1 绑一条**不存在的线路**：refresh 会经 clientFor 解析线路 →
	// 直接返回 RouteUnavailableError，不需要真的发请求。
	// 这是最贴近生产的构造（用户手写线路名写错就是这个形态）。
	if err := upstream.ConfigureRoutes(map[string]string{}); err != nil {
		t.Fatal(err)
	}
	bad := &auth.Auth{UID: "a1", AccessToken: "at1", RefreshToken: "rt1", ExpiresAt: 0}
	bad.SetProxyName("no-such-route")

	// a1 / a2 都已过期（ExpiresAt=0 → NeedsRefresh 恒真），逼出 refresh 前置分支。
	p := testPoolWith(
		bad,
		&auth.Auth{UID: "a2", AccessToken: "at2", RefreshToken: "rt2", ExpiresAt: 0},
	)
	h := NewHandler(Config{Pool: p, Upstream: up})

	body := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("健康号没被尝试（code=%d body=%s）—— refresh 分支仍在 break",
			rec.Code, rec.Body.String())
	}
	// a1 不该被罚：它是线路问题，不是账号问题
	st, ok := p.Status("a1")
	if !ok {
		t.Fatal("a1 不在池里")
	}
	if st.Cooling {
		t.Errorf("a1 被冷却了（线路故障不该罚号）")
	}
	if st.ErrTotal != 0 {
		t.Errorf("a1 errTotal=%d，期望 0", st.ErrTotal)
	}
}
