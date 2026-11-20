// route_error.go 线路配置错误的独立错误类型。
//
// 为什么要独立成类型而不是普通 error：网关的失败处理把「非 *Error 的传输层错误」
// 当作**账号抖动**处理（换号 + NoteFailures），连续失败会把整池账号喂进熔断。
// 线路名写错 / 线路被删 / 地址非法是**配置问题**——换任何账号都是同一结果，
// 罚号只会把好号白白烧掉，客户端最后拿到的是 503 而不是「线路配错了」。
//
// 所以 handler 必须能一眼认出这一类错误：不换号、不罚号、直接把原因报给调用方。
package upstream

import (
	"errors"
	"fmt"
)

// RouteUnavailableError 账号绑定的出口线路不可用（不存在 / 地址非法 / 被删）。
//
// 错误文本**不含代理地址**：地址里有密码，这条错误可能进日志、进 HTTP 响应。
type RouteUnavailableError struct {
	Account string // 账号标签（logfmt.Label 的结果，可为空）
	Name    string // 线路名（名字本身不含凭据）
	Err     error  // 底层原因（来自 routeError / normalizeProxyURL）
}

func (e *RouteUnavailableError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("账号 %s出口线路不可用：%v", e.Account, e.Err)
	}
	return fmt.Sprintf("账号 %s出口线路 %q 不可用", e.Account, e.Name)
}

func (e *RouteUnavailableError) Unwrap() error { return e.Err }

// IsRouteUnavailable 判断错误是否是线路配置问题（handler 用来跳过换号/罚号）。
func IsRouteUnavailable(err error) bool {
	var target *RouteUnavailableError
	return errors.As(err, &target)
}
