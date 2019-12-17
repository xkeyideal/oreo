package route

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xkeyideal/oreo/vestigo"
)

func charCheck(c rune) bool {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '/' || c == ':' || c == '*' || c == '_' || c == '-' {
		return true
	}
	return false
}

//目前仅支持 [GET|PUT|POST|DELETE]
func isValidMethod(method string) bool {
	return vestigo.ValidMethod(method)
}

/*
	路由的规则必须明确最后是否加'/'，否则路由Find的结果完全是不同的，统一规定不能加/
*/
func routeRuleCheck(fullroute string) error {
	route := strings.TrimSpace(fullroute)
	routeLen := len(route)
	if routeLen == 0 {
		return errors.New("route is null")
	}

	if routeLen == 1 {
		return errors.New("route can't be '/'")
	}

	if route[0] != '/' {
		return errors.New("route first character must be '/'")
	}

	if route[routeLen-1] == '/' {
		return errors.New("route last character mustn't be '/'")
	}

	for _, runeChar := range route {
		if charCheck(runeChar) == false {
			return errors.New(fmt.Sprintf("route [%s] just support [a-zA-Z0-9-/_*:]", fullroute))
		}
	}

	preIndex := 0
	for preIndex < routeLen {
		if route[preIndex] != '/' {
			break
		}
		preIndex++
	}

	//说明有多个或者没有/，例如： //name, name
	if preIndex != 1 {
		return errors.New("route prefix should just one '/'")
	}

	sufIndex := routeLen - 1
	for sufIndex >= 0 {
		if route[sufIndex] != '/' {
			break
		}
		sufIndex--
	}

	//路由的尾部只有有一个'/',或者没有
	if sufIndex < routeLen-2 {
		return errors.New("route suffix should just one '/'")
	}

	routeParams := strings.Split(strings.Trim(route, "/"), "/")

	if len(routeParams) == 0 {
		return errors.New("route error")
	}

	for index, param := range routeParams {
		paramLen := len(param)
		if paramLen == 0 {
			return errors.New("route param is empty")
		}
		//解析每个param
		if param[0] == ':' { //wildcard
			for i := 1; i < paramLen-1; i++ {
				ch := param[i]
				if ch == ':' || ch == '*' {
					return errors.New("route wildcard have too many ':' or '*'")
				}
			}
			if paramLen == 1 {
				return errors.New("route wildcard is empty")
			}

			//param name should be unique
			for j := 0; j < index; j++ {
				if param == routeParams[j] {
					return errors.New("params in route has duplicate names")
				}
			}
		} else if param[0] == '*' {
			for i := 1; i < paramLen-1; i++ {
				ch := param[i]
				if ch == '*' || ch == ':' {
					return errors.New("route wildcard have too many ':' or '*'")
				}
			}
			if paramLen == 1 {
				return errors.New("route wildcard is empty")
			}

			//param name should be unique
			if index != len(routeParams)-1 {
				return errors.New("route * wildcard must be last")
			}
		} else { //static
			for _, ch := range param {
				if ch == ':' || ch == '*' {
					return errors.New("route static has : or *")
				}
			}
		}
	}

	return nil
}

const (
	paramType    = 1
	staticType   = 2
	matchallType = 3
)

type paramNode struct {
	pType  int
	pValue string
}

// /user/:name/value
func routeParamSplit(fullroute string) ([]paramNode, bool) {
	route := strings.ToLower(strings.Trim(strings.TrimSpace(fullroute), "/"))
	routeParams := strings.Split(route, "/")

	nodes := []paramNode{}

	matchall := false
	lenparams := len(routeParams)
	if lenparams == 0 {
		return nodes, matchall
	}

	for _, param := range routeParams {
		if param[0] == ':' { //wildcard
			nodes = append(nodes, paramNode{
				pType:  paramType,
				pValue: param[1:len(param)],
			})
		} else if param[0] == '*' {
			matchall = true
			nodes = append(nodes, paramNode{
				pType:  matchallType,
				pValue: param[1:len(param)],
			})
		} else {
			nodes = append(nodes, paramNode{
				pType:  staticType,
				pValue: param,
			})
		}
	}
	return nodes, matchall
}

/*
	routes:
		/users/:id/comments
		/:resourceName/:id
	example:
			/users/1/comments
			/boozers/1
			/users/1
		success:
			/users/1/comments
			/boozers/1
		fail:
			/users/1

	/users/1 失败的原因是route规则是static优先
	但是这两个路由理论上不应该属于冲突路由，这种情况只能让用户去规避
*/
func routeConflictCheck(oldRoutes []string, newRoute string) (string, bool) {
	newRouteNodes, newmatchall := routeParamSplit(newRoute)
	newRouteNodeLen := len(newRouteNodes)

	//循环对老的路由进行模式匹配，来判断新增的路由是否会有冲突
	for _, oldRoute := range oldRoutes {

		oldRouteNodes, oldmatchall := routeParamSplit(oldRoute)
		oldRouteNodeLen := len(oldRouteNodes)

		//如果老路由和新路由都没有*通配符，那么长度不等，肯定是合法的
		if !newmatchall && !oldmatchall {
			if oldRouteNodeLen != newRouteNodeLen {
				continue
			}
		}

		//如果有*通配符，也只可能出现在最后一个param
		//如果都没有*通配符，那么只需要匹配静态与:通配符即可
		if !newmatchall && !oldmatchall {
			i := 0
			for i < oldRouteNodeLen {
				oldRouteNode := oldRouteNodes[i]
				newRouteNode := newRouteNodes[i]
				if oldRouteNode.pType == staticType {
					//都是静态,但字符串的值不一样，那么就肯定是合法的,继续检测下一个oldRoute
					//如果newRouteNode是动态的，那么肯定能匹配上，那么继续下一个node
					if newRouteNode.pType == staticType {
						if oldRouteNode.pValue != newRouteNode.pValue {
							break
						}
					}
				}
				i++
				//如果oldRouteNode是:通配符，那么无论newRouteNode是:通配符还是静态都能匹配上
			}
			//完全匹配上，说明有冲突
			if i >= oldRouteNodeLen {
				return oldRoute, false
			}
		} else if !newmatchall && oldmatchall {
			//新路由没有*通配符而老路由有
			i := 0
			for i < oldRouteNodeLen {
				oldRouteNode := oldRouteNodes[i]
				if oldRouteNode.pType == staticType {
					if i >= newRouteNodeLen { //新路由已经结束了，那么未匹配上
						break
					}
					newRouteNode := newRouteNodes[i]
					//都是静态,但字符串的值不一样，那么就肯定是合法的,继续检测下一个oldRoute
					//如果newRouteNode是动态的，那么肯定能匹配上，那么继续下一个node
					if newRouteNode.pType == staticType {
						if oldRouteNode.pValue != newRouteNode.pValue {
							break
						}
					}
				} else if oldRouteNode.pType == paramType {
					//如果oldRouteNode是:通配符，那么无论newRouteNode是:通配符还是静态都能匹配上
				} else { //如果oldRouteNode是*通配符,只要新路由尚未结束都能匹配上
					if i < newRouteNodeLen {
						return oldRoute, false
					}
				}
				i++
			}
		} else if newmatchall && !oldmatchall {
			//新路由有*通配符而老路由没有
			i := 0
			for i < newRouteNodeLen {
				newRouteNode := newRouteNodes[i]
				if newRouteNode.pType == staticType {
					if i >= oldRouteNodeLen {
						break
					}
					oldRouteNode := oldRouteNodes[i]
					if oldRouteNode.pType == staticType {
						if newRouteNode.pValue != oldRouteNode.pValue {
							break
						}
					}
				} else if newRouteNode.pType == paramType {

				} else {
					if i < oldRouteNodeLen {
						return oldRoute, false
					}
				}
				i++
			}
		} else {
			//新路由和老路由都有*通配符
			//算法: 由于*只能在最后一个，因此只需要匹配前面len-1个，最短的是否相同，如果相同那么就能匹配上
			shortParamRouteNodes := newRouteNodes[:newRouteNodeLen-1]
			longParamRouteNodes := oldRouteNodes[:oldRouteNodeLen-1]

			if newRouteNodeLen > oldRouteNodeLen {
				shortParamRouteNodes, longParamRouteNodes = longParamRouteNodes, shortParamRouteNodes
			}

			i := 0
			for i < len(shortParamRouteNodes) {
				shortNode := shortParamRouteNodes[i]
				longNode := longParamRouteNodes[i]
				if shortNode.pType == staticType {
					if longNode.pType == staticType {
						if longNode.pValue != shortNode.pValue {
							break
						}
					}
				}
				i++
			}

			//前len(shortParamRouteNodes)都能匹配上，由于最后一个是*通配符，那么肯定能匹配上
			if i >= len(shortParamRouteNodes) {
				return oldRoute, false
			}
		}
	}

	return "", true
}
