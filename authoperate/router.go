package authoperate

import (
	"fmt"
	"path"
	"sort"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

var routerIndex mgo.Index = mgo.Index{
	Key:    []string{"uri", "groupName"},
	Unique: true,
	Name:   "uri_groupName",
}

type RouterInfo struct {
	Uri       string                `json:"uri" bson:"uri"`
	Desc      string                `json:"desc" bson:"desc"`
	GroupName string                `json:"groupName" bson:"groupName"`
	MethodMap map[string]VerifyData `json:"methodMap" bson:"methodMap"` //key是数字
}

type VerifyData struct {
	Enable     bool   `json:"enable" bson:"enable"`
	MethodDesc string `json:"methodDesc" bson:"methodDesc"`
}

type RouterMethod struct {
	Uri     string
	Methods []string
}

type routerView struct {
	Uri string
}

type RouteMethod struct {
	Method string `json:"method"`
	Desc   string `json:"desc"`
	Enable bool   `json:"enable"`
}

type RouteListView struct {
	Uri     string        `json:"uri"`
	Desc    string        `json:"desc"`
	Methods []RouteMethod `json:"methods"`
}

func (auth *Authorization) RouterUpdateUriDesc(uri, desc string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	u := bson.M{
		"$set": bson.M{"desc": desc},
	}

	return coll.Update(bson.M{"uri": uri, "groupName": auth.groupName}, u)
}

func (auth *Authorization) RouterUpdateMethodDesc(uri, method, desc string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	num, _ := auth.MethodToNumString(method)
	q := bson.M{
		"uri":       uri,
		"groupName": auth.groupName,
	}
	u := bson.M{
		"$set": bson.M{
			fmt.Sprintf("methodMap.%s.methodDesc", num): desc,
		},
	}

	return coll.Update(q, u)
}

func (auth *Authorization) RouterUpsertBatch(infos []RouterInfo) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	for _, info := range infos {
		if !path.IsAbs(info.Uri) {
			return fmt.Errorf("invalid uri: %s", info.Uri)
		}
		info.GroupName = auth.groupName

		query := bson.M{
			"uri":       info.Uri,
			"groupName": auth.groupName,
		}

		set := bson.M{
			"desc": info.Desc,
		}

		for method, p := range info.MethodMap {
			num, _ := auth.MethodToNumString(method)
			set[fmt.Sprintf("methodMap.%s", num)] = p
		}

		update := bson.M{
			"$set": set,
		}

		if _, err := coll.Upsert(query, update); err != nil {
			return fmt.Errorf("upsert router exception: %s", err.Error())
		}
	}

	return nil
}

func (auth *Authorization) RouterGetInfo() ([]RouterInfo, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	query := bson.M{
		"groupName": auth.groupName,
	}

	routers := []RouterInfo{}
	if err := coll.Find(query).All(&routers); err != nil {
		return nil, fmt.Errorf("query router err: %s", err.Error())
	}

	return routers, nil
}

func (auth *Authorization) RouterGetInfoAndUrls() ([]RouterInfo, []string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	query := bson.M{
		"groupName": auth.groupName,
	}

	routers := []RouterInfo{}
	if err := coll.Find(query).All(&routers); err != nil {
		return nil, nil, fmt.Errorf("query router err: %s", err.Error())
	}

	urls := []string{}

	for _, router := range routers {
		urls = append(urls, router.Uri)
	}

	return routers, urls, nil
}

func (auth *Authorization) RouterGetMethod() ([]RouterMethod, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	query := bson.M{
		"groupName": auth.groupName,
	}

	routers := []RouterInfo{}
	if err := coll.Find(query).Select(bson.M{"uri": 1, "methodMap": 1}).All(&routers); err != nil {
		return nil, fmt.Errorf("query router err: %s", err.Error())
	}

	routerMethod := []RouterMethod{}

	for _, router := range routers {
		methods := []string{}
		for k, _ := range router.MethodMap {
			methods = append(methods, auth.NumStringToMethod(k))
		}
		r := RouterMethod{
			Uri:     router.Uri,
			Methods: methods,
		}
		routerMethod = append(routerMethod, r)
	}

	return routerMethod, nil
}

func (auth *Authorization) RouterInfoByUri(uri string) (RouteListView, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return RouteListView{}, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"uri":       uri,
	}

	router := RouterInfo{}
	if err := coll.Find(query).One(&router); err != nil {
		return RouteListView{}, fmt.Errorf("query router by uri err: %s", err.Error())
	}

	methods := []RouteMethod{}
	for m, v := range router.MethodMap {
		method := auth.NumStringToMethod(m)
		methods = append(methods, RouteMethod{
			Method: method,
			Desc:   v.MethodDesc,
			Enable: v.Enable,
		})
	}
	return RouteListView{
		Uri:     router.Uri,
		Desc:    router.Desc,
		Methods: methods,
	}, nil

}

func (auth *Authorization) RouterGetInfoReg(uri string) ([]RouteListView, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"uri": bson.RegEx{
			Pattern: uri,
			Options: "i",
		},
	}

	routers := []RouterInfo{}
	if err := coll.Find(query).All(&routers); err != nil {
		return nil, fmt.Errorf("query router by uri regex err: %s", err.Error())
	}

	routeList := []RouteListView{}
	for _, router := range routers {
		methods := []RouteMethod{}
		for m, v := range router.MethodMap {
			method := auth.NumStringToMethod(m)
			methods = append(methods, RouteMethod{
				Method: method,
				Desc:   v.MethodDesc,
				Enable: v.Enable,
			})
		}
		routeList = append(routeList, RouteListView{
			Uri:     router.Uri,
			Desc:    router.Desc,
			Methods: methods,
		})
	}

	sort.Slice(routeList, func(i, j int) bool { return routeList[i].Uri < routeList[j].Uri })

	return routeList, nil
}

func (auth *Authorization) RouterRemove(uri string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"uri":       uri,
	}

	if err := coll.Remove(query); err != nil {
		return fmt.Errorf("remove router : %s ; err: %s", uri, err.Error())
	}

	return nil
}

func (auth *Authorization) RouterDelMethod(uri, method string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	methodNum, err := auth.MethodToNumString(method)
	if err != nil {
		return err
	}

	query := bson.M{
		"groupName": auth.groupName,
		"uri":       uri,
	}

	update := bson.M{
		"$unset": bson.M{
			fmt.Sprintf("methodMap.%s", methodNum): 1,
		},
	}

	if err := coll.Update(query, update); err != nil {
		return fmt.Errorf("router delete method  %s , err %s", uri, err.Error())
	}

	return nil
}

func (auth *Authorization) RouterVerifyData(uri, method string, enable bool) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(routerCollName)

	method, err = auth.MethodToNumString(method)
	if err != nil {
		return err
	}

	query := bson.M{
		"uri":                                     uri,
		"groupName":                               auth.groupName,
		fmt.Sprintf("%s.%s", "methodMap", method): bson.M{"$exists": true},
	}

	set := bson.M{
		"$set": bson.M{
			fmt.Sprintf("methodMap.%s.enable", method): enable,
		},
	}

	err = coll.Update(query, set)
	if err != nil {
		return fmt.Errorf("set verify data exception: %s", err.Error())
	}

	return auth.roleRefreshRouterMap(uri, method, enable)
}

func (auth *Authorization) RouterList(enable bool) ([]RouteListView, error) {
	routers, err := auth.RouterGetInfo()
	if err != nil {
		return nil, err
	}

	routeList := []RouteListView{}
	for _, router := range routers {
		methods := []RouteMethod{}
		for m, v := range router.MethodMap {
			method := auth.NumStringToMethod(m)
			rm := RouteMethod{
				Method: method,
				Desc:   v.MethodDesc,
				Enable: v.Enable,
			}
			if enable {
				if v.Enable {
					methods = append(methods, rm)
				}
			} else {
				methods = append(methods, rm)
			}
		}
		if len(methods) > 0 {
			routeList = append(routeList, RouteListView{
				Uri:     router.Uri,
				Desc:    router.Desc,
				Methods: methods,
			})
		}
	}

	sort.Slice(routeList, func(i, j int) bool { return routeList[i].Uri < routeList[j].Uri })

	return routeList, nil
}

func (auth *Authorization) RouterVerifyDataEnsure() (map[string]map[string]bool, error) {
	routers, err := auth.RouterGetInfo()
	if err != nil {
		return nil, err
	}
	//uri 下哪些方法具有数据权限
	routerMap := map[string]map[string]bool{}
	for _, router := range routers {
		ms := map[string]bool{}
		for k, v := range router.MethodMap {
			if v.Enable {
				method := auth.NumStringToMethod(k)
				ms[method] = v.Enable
			}
		}
		if len(ms) > 0 {
			routerMap[router.Uri] = ms
		}
	}

	return routerMap, nil
}
