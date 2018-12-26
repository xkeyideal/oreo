package route

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xkeyideal/oreo/authoperate"
	"github.com/xkeyideal/oreo/vestigo"
)

type ConcurrencyRoute struct {
	routers []*sync.Map
	index   int32

	auth *authoperate.Authorization
}

func NewConcurrencyRoute(auth *authoperate.Authorization) *ConcurrencyRoute {
	routers := make([]*sync.Map, 2)
	for i := 0; i < 2; i++ {
		routers[i] = new(sync.Map)
	}

	return &ConcurrencyRoute{
		routers: routers,
		index:   0,
		auth:    auth,
	}
}

func (r *ConcurrencyRoute) AddRoute(groupName string, routes []RouteData) error {
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
	return r.auth.RouterUpsertBatch(addRoutes)
}

func (r *ConcurrencyRoute) EnableRouteDataAuth(groupName string, url, method string) error {
	method = strings.TrimSpace(strings.ToUpper(method))
	if !isValidMethod(method) {
		return errors.New((fmt.Sprintf("Can't support method: %s", method)))
	}

	url = strings.TrimSpace(strings.ToLower(url))

	return r.auth.RouterVerifyData(url, method, true)
}

func (r *ConcurrencyRoute) DisableRouteDataAuth(groupName string, url, method string) error {
	method = strings.TrimSpace(strings.ToUpper(method))
	if !isValidMethod(method) {
		return errors.New((fmt.Sprintf("Can't support method: %s", method)))
	}

	url = strings.TrimSpace(strings.ToLower(url))

	return r.auth.RouterVerifyData(url, method, false)
}

func (r *ConcurrencyRoute) DeleteRouteByMethod(groupName string, url, method string) error {
	method = strings.TrimSpace(strings.ToUpper(method))
	if !isValidMethod(method) {
		return errors.New((fmt.Sprintf("Can't support method: %s", method)))
	}

	url = strings.TrimSpace(strings.ToLower(url))

	//从库中删除
	return r.auth.RouterDelMethod(url, method)
}

func (r *ConcurrencyRoute) DeleteRoute(groupName string, url string) error {
	url = strings.TrimSpace(strings.ToLower(url))

	//从库中删除
	return r.auth.RouterRemove(url)
}

func (r *ConcurrencyRoute) getRouter(groupName string) (router *vestigo.Router, err error) {
	index := atomic.LoadInt32(&r.index)

	v, ok := r.routers[index].Load(groupName)

	if ok {
		if router, ok := v.(*vestigo.Router); ok {
			return router, nil
		}
		return nil, errors.New("Not vestigo.Router Type")
	}

	return nil, errors.New(fmt.Sprintf("%s can't find router", groupName))
}

func (r *ConcurrencyRoute) Match(groupName, method, url string) (string, bool) {
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

func (r *ConcurrencyRoute) LoadRoutesFromDb(groupName string) error {

	oldIndex := atomic.LoadInt32(&r.index)
	newIndex := 1 - oldIndex

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

	r.routers[newIndex].Store(groupName, router)

	atomic.StoreInt32(&r.index, newIndex)
	r.routers[oldIndex] = new(sync.Map)

	return nil
}

func (r *ConcurrencyRoute) ReloadRoutesFromDb(groupName string, duration time.Duration, done chan struct{}) {
	ticker := time.NewTicker(duration)

	for {
		select {
		case <-ticker.C:
			r.LoadRoutesFromDb(groupName)
		case <-done:
			goto exit
		}
	}

exit:
	ticker.Stop()
}

func (r *ConcurrencyRoute) PrintAllRoutes() {
	index := atomic.LoadInt32(&r.index)

	r.routers[index].Range(routeRangeHandler)
}
