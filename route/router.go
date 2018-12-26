package route

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xkeyideal/oreo/vestigo"
)

type RouteData struct {
	Url     string            `json:"url"`
	UrlDesc string            `json:"urlDesc"`
	Methods []RouteMethodData `json:"methods"`
}

type RouteMethodData struct {
	Enable     bool   `json:"enable"`
	Method     string `json:"method"`
	MethodDesc string `json:"methodDesc"`
}

type RouteType interface {
	//添加一个路由，并标注该路由属于哪个组
	AddRoute(groupName string, routes []RouteData) error

	// url + method 启用数据权限
	EnableRouteDataAuth(groupName string, url, method string) error

	// url + method 停用数据权限
	DisableRouteDataAuth(groupName string, url, method string) error

	//删除一个路由和method
	DeleteRouteByMethod(groupName string, url, method string) error

	//删除一个路由
	DeleteRoute(groupName string, url string) error

	//从DB中加载所有路由至内存中
	LoadRoutesFromDb(groupName string) error

	//定时重新加载DB中的路由
	ReloadRoutesFromDb(groupName string, duration time.Duration, done chan struct{})

	//获取某个组的所有路由
	getRouter(groupName string) (router *vestigo.Router, err error)

	//匹配路由
	Match(groupName, method, url string) (string, bool)

	//打印所有路由
	PrintAllRoutes()
}

func routeCheck(routes []RouteData) error {
	for _, route := range routes {
		url := strings.TrimSpace(strings.ToLower(route.Url))

		err := routeRuleCheck(url)
		if err != nil {
			return err
		}

		for _, m := range route.Methods {
			method := strings.TrimSpace(strings.ToUpper(m.Method))
			if !isValidMethod(method) {
				return errors.New((fmt.Sprintf("Can't support method: %s", method)))
			}
		}
	}

	return nil
}

func routeRangeHandler(key, value interface{}) bool {
	router, ok := value.(*vestigo.Router)
	if !ok {
		return false
	}

	for _, route := range router.GetAllRoutes() {
		fmt.Println(key, " --> ", route)
	}

	return true
}
