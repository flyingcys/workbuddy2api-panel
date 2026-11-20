package upstream

import (
	"net/http"
	"sync"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// ProxyName 的并发访问：面板换绑（写）与网关出站 / 状态快照（读）同时发生。
//
// 为什么单独一条：这个字段是运行期可改的，而读点遍布热路径。用 a.mu 保护它的
// 话会和 token 刷新争同一把锁；裸读则是数据竞争（-race 实测会报）。
// 断言的是「跑 -race 不报」，本用例在非 race 模式下只是并发冒烟。
func TestRaceProxyNameAccess(t *testing.T) {
	defer ResetRoutesForTest()
	SetRouteTransportFactory(func() *http.Transport { return NewRouteTransport() })
	t.Cleanup(func() { SetRouteTransportFactory(nil) })
	_ = ConfigureRoutes(map[string]string{"a": "socks5://u:p@127.0.0.1:1111"})

	a := &auth.Auth{UID: "u"}
	c := &Client{HTTP: nil}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			a.SetProxyName("a")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = c.clientFor(a, kindShortRPC)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = a.ProxyNameValue()
		}
	}()
	wg.Wait()
}
