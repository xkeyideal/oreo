package authoperate

import (
	"fmt"
	"sort"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

var signIndex mgo.Index = mgo.Index{
	Key:    []string{"userId", "signKey", "groupName"},
	Unique: true,
	Name:   "userId_signKey_groupName",
}

/*
	超级管理员和SignKey创建者本人不会存在该table中
*/
type SignInfo struct {
	SignKey       string         `json:"signKey" bson:"signKey"`           // 签名 + 工号  可以理解成 这个人拥有这个签名的哪些数据权限
	CreateUserId  string         `json:"createUserId" bson:"createUserId"` //signKey的真实创建者
	UserId        string         `json:"userId" bson:"userId"`
	GroupName     string         `json:"groupName" bson:"groupName"`
	VerifyDataUri map[string]int `json:"verifyDataUri" bson:"verifyDataUri"` // key uri value 就是 1 2 4 8 和 用 $bitsAllSet 计算
}

type UpsertSignInfo struct {
	SignKey  string    `json:"signKey"`
	UserId   string    `json:"userId"`
	AddrList []Address `json:"addrList"`
}

type SignListView struct {
	OwnerId   string     `json:"ownerId"`
	Name      string     `json:"name"`
	SignKey   string     `json:"signKey"`
	SignViews []SignView `json:"signViews"`
}

type SignView struct {
	UserId  string          `json:"userId"`
	Name    string          `json:"name"`
	Routers []RoleRouteInfo `json:"routers"`
}

func (auth *Authorization) SignDiffGlobalDataAuthRoute(signKey, userId string) ([]RouteListView, error) {
	dataAuthRoutes, err := auth.RouterList(true)
	if err != nil {
		return nil, err
	}

	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(signCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"signKey":   signKey,
		"userId":    userId,
	}

	sign := SignInfo{}
	err = coll.Find(q).One(&sign)
	if err != nil {
		return nil, err
	}

	set := make(map[string]struct{})
	for uri, methodValue := range sign.VerifyDataUri {
		ms := auth.MethodValueToMethods(methodValue)
		for _, m := range ms {
			key := fmt.Sprintf("%s%s", uri, auth.NumStringToMethod(m))
			set[key] = struct{}{}
		}
	}

	diffRoutes := []RouteListView{}
	for _, route := range dataAuthRoutes {
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

func (auth *Authorization) SignPatchVerifyData(signKey string, userIds []string, urlMethod map[string]int) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(signCollName)

	for _, userId := range userIds {
		q := bson.M{
			"groupName": auth.groupName,
			"signKey":   signKey,
			"userId":    userId,
		}

		sign := SignInfo{}
		err := coll.Find(q).One(&sign)
		if err != nil {
			return err
		}

		for uri, methodValue := range urlMethod {
			if mv, ok := sign.VerifyDataUri[uri]; ok {
				sign.VerifyDataUri[uri] = mv | methodValue
			} else {
				sign.VerifyDataUri[uri] = methodValue
			}
		}

		err = coll.Update(q, bson.M{"$set": bson.M{"verifyDataUri": sign.VerifyDataUri}})
		if err != nil {
			return err
		}
	}

	return nil
}

func (auth *Authorization) SignRemoveVerifyData(signKey string, userIds []string, urlMethod map[string]int) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(signCollName)

	for _, userId := range userIds {
		q := bson.M{
			"groupName": auth.groupName,
			"signKey":   signKey,
			"userId":    userId,
		}

		sign := SignInfo{}
		err := coll.Find(q).One(&sign)
		if err != nil {
			return err
		}

		for uri, methodValue := range sign.VerifyDataUri {
			if mv, ok := urlMethod[uri]; ok {
				newmv := methodValue ^ mv
				if newmv > 0 {
					sign.VerifyDataUri[uri] = newmv
				} else {
					delete(sign.VerifyDataUri, uri)
				}
			}
		}

		err = coll.Update(q, bson.M{"$set": bson.M{"verifyDataUri": sign.VerifyDataUri}})
		if err != nil {
			return err
		}
	}

	return nil
}

func (auth *Authorization) userSignKeyInsert(info SignInfo) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(signCollName)

	return coll.Insert(info)
}

func (auth *Authorization) QuerySignAuth(signKey, url, method, userId string) bool {

	num := auth.methodString2Num(method)

	if num <= 0 {
		return false
	}

	session, err := auth.mongoFactory.Get()
	if err != nil {
		return false
	}
	defer auth.mongoFactory.Put(session)

	userColl := session.DB(auth.dataBaseName).C(userCollName)

	//先判断该signKey是否是该用户创建的,如果是，直接就有数据权限
	q := bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
		fmt.Sprintf("signKey.%s", signKey): bson.M{"$exists": true},
	}
	cnt, err := userColl.Find(q).Count()

	if err != nil {
		return false
	}

	if cnt > 0 {
		return true
	}

	//再判断数据权限
	signColl := session.DB(auth.dataBaseName).C(signCollName)

	q = bson.M{
		"groupName": auth.groupName,
		"signKey":   signKey,
		"userId":    userId,
		fmt.Sprintf("verifyDataUri.%s", url): bson.M{"$bitsAllSet": num},
	}

	n, err := signColl.Find(q).Count()

	if err != nil {
		return false
	}

	if n <= 0 {
		return false
	}

	return true
}

func (auth *Authorization) SignUpsert(info UpsertSignInfo) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	userColl := session.DB(auth.dataBaseName).C(userCollName)

	//为了拿到signKey的真实创建者
	userInfo := UserInfo{}
	q := bson.M{
		"groupName":                             auth.groupName,
		fmt.Sprintf("signKey.%s", info.SignKey): bson.M{"$exists": true},
	}
	err = userColl.Find(q).One(&userInfo)
	if err != nil {
		return err
	}

	coll := session.DB(auth.dataBaseName).C(signCollName)

	ensureUri, err := auth.RouterVerifyDataEnsure()
	if err != nil {
		return err
	}

	//验证添加的路由地址是否拥有数据权限
	vdu := map[string]int{}
	for _, addr := range info.AddrList {
		methodNumInt := 0
		ms := auth.MethodValueToMethods(addr.MethodValue)
		if verifyMethods, ok := ensureUri[addr.Uri]; ok {
			for _, m := range ms {
				if _, ok := verifyMethods[auth.NumStringToMethod(m)]; ok {
					methodNumInt += auth.NumStringToNum(m)
				}
			}
		}
		if methodNumInt > 0 {
			vdu[addr.Uri] = methodNumInt
		}
	}

	if len(vdu) <= 0 {
		return nil
		//return fmt.Errorf("invalid address, please ensure your router address have data verify")
	}

	doc := SignInfo{
		SignKey:       info.SignKey,
		CreateUserId:  userInfo.UserId,
		UserId:        info.UserId,
		GroupName:     auth.groupName,
		VerifyDataUri: vdu,
	}

	query := bson.M{
		"userId":    info.UserId,
		"signKey":   info.SignKey,
		"groupName": auth.groupName,
	}

	update := bson.M{
		"$set": doc,
	}

	if _, err := coll.Upsert(query, update); err != nil {
		return fmt.Errorf("sign upsert exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) SignRemove(signKey, userId string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(signCollName)

	query := bson.M{
		"signKey": signKey,
		"userId":  userId,
	}

	if err := coll.Remove(query); err != nil {
		return fmt.Errorf("remove sign exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) SignGetInfo(signKey string) (SignListView, error) {
	signListView := SignListView{}

	session, err := auth.mongoFactory.Get()
	if err != nil {
		return signListView, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(signCollName)

	signs := []SignInfo{}

	query := bson.M{
		"groupName": auth.groupName,
		"signKey":   signKey,
	}

	err = coll.Find(query).All(&signs)
	if err != nil {
		return signListView, fmt.Errorf("query sign exception %s", err.Error())
	}

	routerInfos, err := auth.RouterGetInfo()
	if err != nil {
		return signListView, err
	}

	name, ownerId, err := auth.FindSignKeyOwner(signKey)
	if err != nil {
		return signListView, err
	}

	users, err := auth.UserGetInfo()
	if err != nil {
		return signListView, err
	}

	userMap := make(map[string]string, len(users))
	for _, user := range users {
		userMap[user.UserId] = user.Name
	}

	signListView.OwnerId = ownerId
	signListView.Name = name
	signListView.SignKey = signKey

	signViews := []SignView{}

	for _, sign := range signs {
		addrList := []Address{}
		for k, v := range sign.VerifyDataUri {
			d := Address{
				Uri:         k,
				MethodValue: v,
			}
			addrList = append(addrList, d)
		}

		routers := auth.routerDetailReqAddr(routerInfos, addrList)

		signViews = append(signViews, SignView{
			UserId:  sign.UserId,
			Name:    userMap[sign.UserId],
			Routers: routers,
		})
	}
	signListView.SignViews = signViews

	return signListView, nil
}

// 由于自己创建的signKey不需要给自己授权，如果signKey是copyUserId自己创建的，需要将所有已开启数据权限的路由和方法给pastUserId
func (auth *Authorization) SignCopy(signKey, copyUserId string, pastUserIds []string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	userColl := session.DB(auth.dataBaseName).C(userCollName)

	//先判断该signKey是否是该用户创建的,如果是,需要查询所有已开启数据权限的路由和方法
	q := bson.M{
		"groupName": auth.groupName,
		"userId":    copyUserId,
		fmt.Sprintf("signKey.%s", signKey): bson.M{"$exists": true},
	}
	cnt, err := userColl.Find(q).Count()

	if err != nil {
		return err
	}

	signColl := session.DB(auth.dataBaseName).C(signCollName)

	if cnt > 0 { //是自己创建的
		ensuerUri, err := auth.RouterVerifyDataEnsure()
		if err != nil {
			return err
		}

		vdu := make(map[string]int)
		for uri, methods := range ensuerUri {
			methodNumInt := 0
			for m, _ := range methods {
				methodNumInt += auth.NumStringToNum(m)
			}
			if methodNumInt > 0 {
				vdu[uri] = methodNumInt
			}
		}

		for _, pastUserId := range pastUserIds {
			sign := SignInfo{
				SignKey:       signKey,
				UserId:        pastUserId,
				GroupName:     auth.groupName,
				VerifyDataUri: vdu,
			}

			if err := signColl.Insert(sign); err != nil {
				return fmt.Errorf("copy sign info exception %s", err.Error())
			}
		}
	} else { //不是自己创建的

		query := bson.M{
			"groupName": auth.groupName,
			"userId":    copyUserId,
			"signKey":   signKey,
		}

		sign := SignInfo{}

		if err := signColl.Find(query).One(&sign); err != nil {
			return fmt.Errorf("copy sign info exception %s", err.Error())
		}

		for _, pastUserId := range pastUserIds {
			newSign := SignInfo{
				SignKey:       signKey,
				UserId:        pastUserId,
				GroupName:     auth.groupName,
				VerifyDataUri: sign.VerifyDataUri,
			}

			if err := signColl.Insert(newSign); err != nil {
				return fmt.Errorf("copy sign info exception %s", err.Error())
			}
		}
	}

	return nil
}

type UserSignList struct {
	OwnSigns   []OwnSign   `json:"ownSigns"`
	GrantSigns []GrantSign `json:"grantSigns"`
}

type GrantSign struct {
	SignKey string          `json:"signKey"`
	Desc    string          `json:"desc"`
	OwnUser string          `json:"ownUser"`
	OwnName string          `json:"ownName"`
	Routers []RoleRouteInfo `json:"routers"`
}

type OwnSign struct {
	SignKey string `json:"signKey"`
	Desc    string `json:"desc"`
}

func (auth *Authorization) UserOwnSigns(userId string) (UserSignList, error) {
	userSignList := UserSignList{}
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return userSignList, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(signCollName)

	//查询userId拥有哪些signKey，但并不代表该signKey是userId创建的
	infos := []SignInfo{}
	err = coll.Find(bson.M{"userId": userId, "groupName": auth.groupName}).All(&infos)
	if err != nil {
		return userSignList, err
	}

	//拿到这些SignKey的真实创建者
	createUserIds := []string{userId}
	for _, info := range infos {
		createUserIds = append(createUserIds, info.CreateUserId)
	}

	userColl := session.DB(auth.dataBaseName).C(userCollName)

	//查询所有的User，这里明确了signKey是哪个userId创建的
	userInfos := []UserInfo{}
	err = userColl.Find(bson.M{"groupName": auth.groupName, "userId": bson.M{"$in": createUserIds}}).All(&userInfos)
	if err != nil {
		return userSignList, err
	}

	type userSign struct {
		userId string
		name   string
		desc   string
	}

	allSignDescs := make(map[string]userSign)
	ownSigns := []OwnSign{}
	for _, user := range userInfos {
		for sign, desc := range user.SignKey {
			allSignDescs[sign] = userSign{
				userId: user.UserId,
				name:   user.Name,
				desc:   desc,
			}
		}
		if user.UserId == userId {
			for sign, desc := range user.SignKey {
				ownSigns = append(ownSigns, OwnSign{
					SignKey: sign,
					Desc:    desc,
				})
			}
		}
	}

	userSignList.OwnSigns = ownSigns

	//获取所有路由
	routerInfos, err := auth.RouterGetInfo()
	if err != nil {
		return userSignList, err
	}

	grantSigns := []GrantSign{}
	for _, info := range infos {
		addrs := []Address{}
		for uri, methodValue := range info.VerifyDataUri {
			addrs = append(addrs, Address{
				Uri:         uri,
				MethodValue: methodValue,
			})
		}
		routers := auth.routerDetailReqAddr(routerInfos, addrs)
		us := allSignDescs[info.SignKey]
		grantSigns = append(grantSigns, GrantSign{
			SignKey: info.SignKey,
			Desc:    us.desc,
			OwnUser: us.userId,
			OwnName: us.name,
			Routers: routers,
		})
	}
	userSignList.GrantSigns = grantSigns

	return userSignList, nil
}
