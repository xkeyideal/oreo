package route

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xkeyideal/oreo/authoperate"
	"github.com/xkeyideal/oreo/vestigo"
)

type SingletonRoute struct {
	router *sync.Map
	auth   *authoperate.Authorization
}

func NewSingletonRoute(auth *authoperate.Authorization) *SingletonRoute {
	return &SingletonRoute{
		router: new(sync.Map),
		auth:   auth,
	}
}

func (r *SingletonRoute) AddRoute(groupName string, routes []RouteData) error {
	err := routeCheck(routes)
	if err != nil {
		return err
	}

	dbRoutes, oldUrls, err := r.auth.RouterGetInfoAndUrls()
	if err != nil {
		return err
	}

	// 将用户传递的route与数据库已有的route去重
	addRoutes := []authoperate.RouterInfo{}
	addUrls := []string{}
	for _, route := range routes {
		uri := strings.TrimSpace(strings.ToLower(route.Url))
		ri := authoperate.RouterInfo{
			Uri:       uri,
			Desc:      route.UrlDesc,
			GroupName: groupName,
			MethodMap: make(map[string]authoperate.VerifyData),
		}
		exist := false

		for _, dbRoute := range dbRoutes {
			// 如果url在数据库中已经存在
			if uri == dbRoute.Uri {
				// 循环遍历url下拥有的method
				has := false
				for _, marr := range route.Methods {
					method := strings.TrimSpace(strings.ToUpper(marr.Method))
					num, _ := r.auth.MethodToNumString(method)
					if _, ok := dbRoute.MethodMap[num]; !ok {
						// 不在db中的才会添加到db中
						ri.MethodMap[method] = authoperate.VerifyData{
							Enable:     marr.Enable,
							MethodDesc: marr.MethodDesc,
						}
						has = true
					}
				}

				if has {
					ri.Desc = dbRoute.Desc
					addRoutes = append(addRoutes, ri)
				}
				exist = true
				break
			}
		}

		if !exist {
			addUrls = append(addUrls, uri)
			for _, marr := range route.Methods {
				method := strings.TrimSpace(strings.ToUpper(marr.Method))
				ri.MethodMap[method] = authoperate.VerifyData{
					Enable:     marr.Enable,
					MethodDesc: marr.MethodDesc,
				}
			}
			addRoutes = append(addRoutes, ri)
		}
	}

	// 只需要对新增的url进行判断是否存在冲突，不需要管method
	for _, url := range addUrls {
		conflictUrl, ok := routeConflictCheck(oldUrls, url)
		if !ok {
			return errors.New(fmt.Sprintf("Url: %s confict with Exist Url: %s", url, conflictUrl))
		}
		oldUrls = append(oldUrls, url)
	}

	//入库
	err = r.auth.RouterUpsertBatch(addRoutes)
	if err != nil {
		return err
	}

	//添加至现有路由列表中
	vestigoRouter, err := r.getRouter(groupName)
	if err != nil {
		vestigoRouter = vestigo.NewRouter()

		for _, route := range addRoutes {
			for method, _ := range route.MethodMap {
				vestigoRouter.Add(method, route.Uri, func(w http.ResponseWriter, req *http.Request) {})
			}
		}

		r.router.Store(groupName, vestigoRouter)

		return nil
	}

	for _, route := range addRoutes {
		for method, _ := range route.MethodMap {
			vestigoRouter.Add(method, route.Uri, func(w http.ResponseWriter, req *http.Request) {})
		}
	}

	return nil
}

func (r *SingletonRoute) EnableRouteDataAuth(groupName string, url, method string) error {
	method = strings.TrimSpace(strings.ToUpper(method))
	if !isValidMethod(method) {
		return errors.New((fmt.Sprintf("Can't support method: %s", method)))
	}

	url = strings.TrimSpace(strings.ToLower(url))

	return r.auth.RouterVerifyData(url, method, true)
}

func (r *SingletonRoute) DisableRouteDataAuth(groupName string, url, method string) error {
	method = strings.TrimSpace(strings.ToUpper(method))
	if !isValidMethod(method) {
		return errors.New((fmt.Sprintf("Can't support method: %s", method)))
	}

	url = strings.TrimSpace(strings.ToLower(url))

	return r.auth.RouterVerifyData(url, method, false)
}

func (r *SingletonRoute) DeleteRouteByMethod(groupName string, url, method string) error {
	method = strings.TrimSpace(strings.ToUpper(method))
	if !isValidMethod(method) {
		return errors.New((fmt.Sprintf("Can't support method: %s", method)))
	}

	url = strings.TrimSpace(strings.ToLower(url))

	//从库中删除，然后reload库中该key的所有routes
	err := r.auth.RouterDelMethod(url, method)
	if err != nil {
		return err
	}

	return r.LoadRoutesFromDb(groupName)
}

func (r *SingletonRoute) DeleteRoute(groupName string, url string) error {
	url = strings.TrimSpace(strings.ToLower(url))

	//从库中删除，然后reload库中该key的所有routes
	err := r.auth.RouterRemove(url)
	if err != nil {
		return err
	}

	return r.LoadRoutesFromDb(groupName)
}

func (r *SingletonRoute) getRouter(groupName string) (router *vestigo.Router, err error) {
	v, ok := r.router.Load(groupName)

	if ok {
		if router, ok := v.(*vestigo.Router); ok {
			return router, nil
		}
		return nil, errors.New("Not vestigo.Router Type")
	}

	return nil, errors.New(fmt.Sprintf("%s can't find router", groupName))
}

func (r *SingletonRoute) Match(groupName, method, url string) (string, bool) {
	method = strings.TrimSpace(strings.ToUpper(method))
	if !isValidMethod(method) {
		return "", false
	}

	url = strings.TrimSpace(strings.ToLower(url))

	router, err := r.getRouter(groupName)
	if err != nil {
		return "", false
	}

	req, _ := http.NewRequest(method, url, nil)

	template, matched := router.Match(req)
	return template, matched
}

func (r *SingletonRoute) LoadRoutesFromDb(groupName string) error {
	routes, err := r.auth.RouterGetMethod()

	if err != nil {
		return err
	}

	router := vestigo.NewRouter()
	for _, route := range routes {
		for _, method := range route.Methods {
			router.Add(method, route.Uri, func(w http.ResponseWriter, req *http.Request) {})
		}
	}

	r.router.Store(groupName, router)

	return nil

}

func (r *SingletonRoute) ReloadRoutesFromDb(groupName string, duration time.Duration, done chan struct{}) {
}

func (r *SingletonRoute) PrintAllRoutes() {
	r.router.Range(routeRangeHandler)
}
