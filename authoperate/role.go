package authoperate

import (
	"fmt"
	"sort"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

var roleIndex mgo.Index = mgo.Index{
	Key:    []string{"roleName", "groupName"},
	Unique: true,
	Name:   "roleName_groupName",
}

type RoleInfo struct {
	RoleName  string          `json:"roleName" bson:"roleName"`
	Desc      string          `json:"desc" bson:"desc"`
	GroupName string          `json:"groupName" bson:"groupName"`
	IsDefault bool            `json:"isDefault" bson:"isDefault"` //默认角色
	UserIds   []string        `json:"userIds" bson:"userIds"`
	RouterMap map[string]bool `json:"routerMap" bson:"routerMap"` //key  1_/oreo/_uri, 每个method单独存储
	Address   []Address       `json:"address" bson:"address"`
	Type      int             `json:"type" bson:"type"` //角色的类型
}

type UpsertRoleInfo struct {
	RoleName  string    `json:"roleName"`
	Type      int       `json:"type"`
	Desc      string    `json:"desc"`
	IsDefault bool      `json:"isDefault"`
	AddrList  []Address `json:"addrList"`
}

type Address struct {
	Uri         string `json:"uri" bson:"uri"`
	MethodValue int    `json:"methodValue" bson:"methodValue"` //这里是所有method对应的整型值之和
}

type RoleRouteMethodInfo struct {
	Method     string `json:"method"`
	MethodDesc string `json:"methodDesc"`
	Enable     bool   `json:"enable"`
	IsDelete   bool   `json:"isDelete"`
}

type RoleRouteInfo struct {
	Uri      string                `json:"uri"`
	UriDesc  string                `json:"uriDesc"`
	IsDelete bool                  `json:"isDelete"`
	Methods  []RoleRouteMethodInfo `json:"methods"`
}

type RoleListView struct {
	RoleName  string          `json:"roleName"`
	Desc      string          `json:"desc"`
	IsDefault bool            `json:"isDefault"`
	Type      int             `json:"type"`
	Users     []UserDetail    `json:"users"`
	Routers   []RoleRouteInfo `json:"routers"`
}

func (auth *Authorization) RoleUpdateTypeDesc(roleName, roleDesc string, typ int) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	return coll.Update(bson.M{"groupName": auth.groupName, "roleName": roleName}, bson.M{"$set": bson.M{"type": typ, "desc": roleDesc}})
}

func (auth *Authorization) RoleEnableDataAuthRouteByUserId(userId string) ([]string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"userIds":   bson.M{"$in": []string{userId}},
	}
	infos := []RoleInfo{}
	err = coll.Find(q).Select(bson.M{"routerMap": 1}).All(&infos)
	if err != nil {
		return nil, err
	}

	enableDataRoutes := []string{}
	set := make(map[string]struct{})
	for _, info := range infos {
		for k, v := range info.RouterMap {
			if v {
				if _, ok := set[k]; !ok {
					enableDataRoutes = append(enableDataRoutes, k)
					set[k] = struct{}{}
				}
			}
		}
	}

	return enableDataRoutes, nil
}

func (auth *Authorization) RoleUpsert(info UpsertRoleInfo) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	routerMap, err := auth.routerMapByReqAddr(info.AddrList)
	if err != nil {
		return err
	}

	doc := bson.M{
		"roleName":  info.RoleName,
		"desc":      info.Desc,
		"routerMap": routerMap,
		"address":   info.AddrList,
		"type":      info.Type,
		"isDefault": info.IsDefault,
	}

	//如果是超管角色不能自动设为默认角色
	if info.Type == superAdminRoleType {
		doc["isDefault"] = false
	} else {
		// 如果非超管外没有其他角色，那么该角色则设定为默认角色
		if count, err := coll.Find(bson.M{"type": bson.M{"$ne": superAdminRoleType}}).Count(); err != nil {
			return fmt.Errorf("calc count err %s", err.Error())
		} else {
			if count <= 0 {
				doc["isDefault"] = true
			}
		}
	}

	query := bson.M{
		"roleName":  info.RoleName,
		"groupName": auth.groupName,
	}

	update := bson.M{
		"$set": doc,
	}

	if _, err := coll.Upsert(query, update); err != nil {
		return fmt.Errorf("role upsert exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) RoleRemove(roleName string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	coll := session.DB(auth.dataBaseName).C(roleCollName)

	query := bson.M{
		"roleName":  roleName,
		"groupName": auth.groupName,
	}

	if err := coll.Remove(query); err != nil {
		return fmt.Errorf("role remove exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) RoleRouteDiff(roleName string) ([]RouteListView, error) {
	oreoRoutes, err := auth.RouterList(false)
	if err != nil {
		return nil, err
	}

	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"roleName":  roleName,
	}

	role := RoleInfo{}
	err = coll.Find(q).Select(bson.M{"address": 1}).One(&role)
	if err != nil {
		return nil, err
	}

	set := make(map[string]struct{})
	for _, addr := range role.Address {
		ms := auth.MethodValueToMethods(addr.MethodValue)
		for _, m := range ms {
			key := fmt.Sprintf("%s%s", addr.Uri, auth.NumStringToMethod(m))
			set[key] = struct{}{}
		}
	}

	diffRoutes := []RouteListView{}
	for _, route := range oreoRoutes {
		routeMethods := []RouteMethod{}
		for _, method := range route.Methods {
			if _, ok := set[fmt.Sprintf("%s%s", route.Uri, method.Method)]; !ok {
				routeMethods = append(routeMethods, method)
			}
		}
		if len(routeMethods) > 0 {
			diffRoutes = append(diffRoutes, RouteListView{
				Uri:     route.Uri,
				Desc:    route.Desc,
				Methods: routeMethods,
			})
		}
	}

	sort.Slice(diffRoutes, func(i, j int) bool { return diffRoutes[i].Uri < diffRoutes[j].Uri })

	return diffRoutes, nil
}

func (auth *Authorization) RoleInfoList(roleName string) ([]RoleListView, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	q := bson.M{
		"groupName": auth.groupName,
	}

	if roleName != "" {
		q["roleName"] = roleName
	}

	roles := []RoleInfo{}
	err = coll.Find(q).All(&roles)
	if err != nil {
		return nil, fmt.Errorf("query role info exception %s", err.Error())
	}

	routerInfos, err := auth.RouterGetInfo()
	if err != nil {
		return nil, err
	}

	users, err := auth.UserGetInfo()
	if err != nil {
		return nil, err
	}

	roleListView := []RoleListView{}
	for _, role := range roles {
		routers := auth.routerDetailReqAddr(routerInfos, role.Address)
		users := auth.userDetail(users, role.UserIds)

		roleListView = append(roleListView, RoleListView{
			RoleName:  role.RoleName,
			Desc:      role.Desc,
			IsDefault: role.IsDefault,
			Type:      role.Type,
			Routers:   routers,
			Users:     users,
		})
	}

	return roleListView, nil
}

func (auth *Authorization) RoleAddUser(roleName string, userIds []string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	coll := session.DB(auth.dataBaseName).C(roleCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"roleName":  roleName,
	}

	update := bson.M{
		"$addToSet": bson.M{
			"userIds": bson.M{
				"$each": userIds,
			},
		},
	}

	if err := coll.Update(query, update); err != nil {
		return fmt.Errorf("add user exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) RoleRemoveUser(roleName string, userIds []string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	coll := session.DB(auth.dataBaseName).C(roleCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"roleName":  roleName,
	}

	update := bson.M{
		"$pull": bson.M{
			"userIds": bson.M{
				"$in": userIds,
			},
		},
	}

	if err := coll.Update(query, update); err != nil {
		return fmt.Errorf("remove user exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) RoleSetDefault(roleName string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	coll := session.DB(auth.dataBaseName).C(roleCollName)

	query := bson.M{
		"isDefault": true,
		"groupName": auth.groupName,
	}

	update := bson.M{
		"$set": bson.M{
			"isDefault": false,
		},
	}
	if err := coll.Update(query, update); err != nil {
		if err != mgo.ErrNotFound {
			return fmt.Errorf("default role set true to false exception %s", err.Error())
		}
	}

	query1 := bson.M{
		"roleName":  roleName,
		"groupName": auth.groupName,
	}
	update1 := bson.M{
		"$set": bson.M{
			"isDefault": true,
		},
	}

	if err := coll.Update(query1, update1); err != nil {
		return fmt.Errorf("default role set false to true exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) routerMapByReqAddr(addrList []Address) (map[string]bool, error) {
	routerInfo, err := auth.RouterGetInfo()
	if err != nil {
		return nil, err
	}

	routerMap := make(map[string]bool)

	for _, addr := range addrList {
		for _, router := range routerInfo {
			if router.Uri == addr.Uri {
				ms := auth.MethodValueToMethods(addr.MethodValue)
				for _, m := range ms {
					if router.MethodMap[m].Enable {
						routerMap[fmt.Sprintf("%s%s%s", m, splitString, addr.Uri)] = true
					} else {
						routerMap[fmt.Sprintf("%s%s%s", m, splitString, addr.Uri)] = false
					}
				}
				break
			}
		}
	}

	return routerMap, nil
}

func (auth *Authorization) routerDetailReqAddr(routerInfos []RouterInfo, addrList []Address) []RoleRouteInfo {
	uriSet := make(map[string]int)
	uriMethodSet := make(map[string]struct{})
	for i, info := range routerInfos {
		uriSet[info.Uri] = i
		for k, _ := range info.MethodMap {
			uriMethodSet[fmt.Sprintf("%s%s", info.Uri, k)] = struct{}{}
		}
	}

	routers := []RoleRouteInfo{}

	for _, addr := range addrList {

		rri := RoleRouteInfo{
			Uri:      addr.Uri,
			UriDesc:  "Unknown",
			IsDelete: true,
			Methods:  []RoleRouteMethodInfo{},
		}
		ms := auth.MethodValueToMethods(addr.MethodValue)
		for _, m := range ms {
			rri.Methods = append(rri.Methods, RoleRouteMethodInfo{
				Method:     auth.NumStringToMethod(m),
				MethodDesc: "Unknown",
				IsDelete:   true,
			})
		}

		//在router表中该uri未被删除
		if index, ok := uriSet[addr.Uri]; ok {
			rri.UriDesc = routerInfos[index].Desc
			rri.IsDelete = false
			for i, m := range ms {
				//method未被删除
				if _, ok := uriMethodSet[fmt.Sprintf("%s%s", addr.Uri, m)]; ok {
					methodInfo := routerInfos[index].MethodMap[m]
					rri.Methods[i].MethodDesc = methodInfo.MethodDesc
					rri.Methods[i].Enable = methodInfo.Enable
					rri.Methods[i].IsDelete = false
				}
			}
		}

		routers = append(routers, rri)
	}

	sort.Slice(routers, func(i, j int) bool { return routers[i].Uri < routers[j].Uri })

	return routers
}

func (auth *Authorization) userDetail(users []UserInfo, userIds []string) []UserDetail {

	userMap := map[string]string{}
	for _, user := range users {
		userMap[user.UserId] = user.Name
	}

	userDetail := []UserDetail{}
	for _, userId := range userIds {
		if v, ok := userMap[userId]; ok {
			d := UserDetail{
				UserId: userId,
				Name:   v,
			}
			userDetail = append(userDetail, d)
		}
	}

	return userDetail
}

func (auth *Authorization) roleRefreshRouterMap(url, method string, enable bool) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	key := fmt.Sprintf("routerMap.%s%s%s", method, splitString, url)

	q := bson.M{
		"groupName": auth.groupName,
		key:         bson.M{"$exists": true},
	}

	u := bson.M{
		"$set": bson.M{key: enable},
	}

	_, err = coll.UpdateAll(q, u)
	return err
}

type RoleUserListView struct {
	RoleName  string          `json:"roleName"`
	Desc      string          `json:"desc"`
	IsDefault bool            `json:"isDefault"`
	Type      int             `json:"type"`
	Routers   []RoleRouteInfo `json:"routers"`
}

func (auth *Authorization) UserOwnRolenames(userId string) ([]string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"userIds":   bson.M{"$in": []string{userId}},
	}

	roles := []RoleInfo{}
	err = coll.Find(q).Select(bson.M{"roleName": 1}).All(&roles)
	if err != nil {
		return nil, err
	}

	roleNames := []string{}
	for _, role := range roles {
		roleNames = append(roleNames, role.RoleName)
	}
	return roleNames, nil
}

func (auth *Authorization) UserOwnRoles(userId string) ([]RoleUserListView, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"userIds":   bson.M{"$in": []string{userId}},
	}

	roles := []RoleInfo{}
	err = coll.Find(q).All(&roles)
	if err != nil {
		return nil, err
	}

	routerInfos, err := auth.RouterGetInfo()
	if err != nil {
		return nil, err
	}

	roleViews := []RoleUserListView{}
	for _, role := range roles {
		routers := auth.routerDetailReqAddr(routerInfos, role.Address)
		roleViews = append(roleViews, RoleUserListView{
			RoleName:  role.RoleName,
			Desc:      role.Desc,
			IsDefault: role.IsDefault,
			Type:      role.Type,
			Routers:   routers,
		})
	}
	return roleViews, nil
}

func (auth *Authorization) UserOwnRoleTypes(userId string) ([]int, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"userIds":   bson.M{"$in": []string{userId}},
	}

	roles := []RoleInfo{}
	err = coll.Find(q).Select(bson.M{"type": 1}).All(&roles)
	if err != nil {
		return nil, err
	}

	typ := []int{}
	for _, role := range roles {
		typ = append(typ, role.Type)
	}

	return typ, nil
}

func (auth *Authorization) UserGrantRoute(userId string) (map[string]int, bool, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, false, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	roles := []RoleInfo{}
	q := bson.M{
		"groupName": auth.groupName,
		"userIds":   bson.M{"$in": []string{userId}},
	}

	err = coll.Find(q).Select(bson.M{"address": 1, "type": 1}).All(&roles)
	if err != nil {
		return nil, false, err
	}

	isAdmin := false
	grantRoutes := make(map[string]int)
	for _, role := range roles {
		if role.Type == superAdminRoleType {
			isAdmin = true
		}
		for _, addr := range role.Address {
			if _, ok := grantRoutes[addr.Uri]; !ok {
				grantRoutes[addr.Uri] = addr.MethodValue
			} else {
				grantRoutes[addr.Uri] |= addr.MethodValue
			}
		}
	}

	return grantRoutes, isAdmin, nil
}

func (auth *Authorization) QueryRoleAuth(url, method, userId string) (bool, bool, bool) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return false, false, false
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(roleCollName)

	num, err := auth.MethodToNumString(method)

	if err != nil {
		return false, false, false
	}

	key := fmt.Sprintf("routerMap.%s%s%s", num, splitString, url)

	roles := []RoleInfo{}
	q := bson.M{
		"groupName": auth.groupName,
		"userIds":   bson.M{"$in": []string{userId}},
		key:         bson.M{"$exists": true},
	}
	err = coll.Find(q).Select(bson.M{"routerMap": 1, "type": 1}).All(&roles)

	if err != nil {
		return false, false, false
	}

	//userId拥有的角色中不存在该路由+method
	if len(roles) == 0 {
		return false, false, false
	}

	existDataAuth := false
	for _, role := range roles {
		// 如果该用户拥有超管角色，那么不需要判断是否拥有数据权限
		if role.Type == superAdminRoleType {
			return true, true, false
		} else {
			existDataAuth = role.RouterMap[fmt.Sprintf("%s%s%s", num, splitString, url)]
		}
	}

	return false, true, existDataAuth
}
