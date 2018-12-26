package authoperate

import (
	"fmt"
	"sort"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

var userIndex mgo.Index = mgo.Index{
	Key:    []string{"userId", "groupName"},
	Unique: true,
	Name:   "userId_groupName",
}

// 用于创建用户的signKey
type UserInfo struct {
	Id        bson.ObjectId     `json:"_id" bson:"_id,omitempty"` //可以不传
	Name      string            `json:"name" bson:"name"`
	UserId    string            `json:"userId" bson:"userId"`
	GroupName string            `json:"groupName" bson:"groupName"`
	SignKey   map[string]string `json:"signKey" bson:"signKey"` //key是signKey，value是signKey的描述
}

type AddUser struct {
	Name   string `json:"name"`
	UserId string `json:"userId"`
}

type UserDetail struct {
	UserId string `json:"userId"`
	Name   string `json:"name"`
}

func (auth *Authorization) UserTransferSignKey(signKey, signDesc, srcUserId, destUserId string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	userColl := session.DB(auth.dataBaseName).C(userCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"userId":    srcUserId,
	}

	u := bson.M{
		"$unset": bson.M{fmt.Sprintf("signKey.%s", signKey): 1},
	}

	// 先删除srcUserId的此signKey
	err = userColl.Update(q, u)
	if err != nil {
		return err
	}

	q = bson.M{
		"groupName": auth.groupName,
		"userId":    destUserId,
	}

	u = bson.M{
		"$set": bson.M{fmt.Sprintf("signKey.%s", signKey): signDesc},
	}

	// 再将此signKey转移给destUserId
	err = userColl.Update(q, u)
	if err != nil {
		return err
	}

	signColl := session.DB(auth.dataBaseName).C(signCollName)

	q = bson.M{
		"groupName": auth.groupName,
		"signKey":   signKey,
	}

	u = bson.M{
		"$set": bson.M{
			"createUserId": destUserId,
		},
	}

	// 最后将sign表中，所有此signKey的CreateUserId修改为destUserId
	_, err = signColl.UpdateAll(q, u)

	return err
}

func (auth *Authorization) GetAllUsers() ([]UserDetail, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	users := []UserInfo{}
	err = coll.Find(bson.M{"groupName": auth.groupName}).Select(bson.M{"userId": 1, "name": 1}).All(&users)
	if err != nil {
		return nil, err
	}

	userDetails := []UserDetail{}
	for _, user := range users {
		userDetails = append(userDetails, UserDetail{
			UserId: user.UserId,
			Name:   user.Name,
		})
	}

	sort.Slice(userDetails, func(i, j int) bool { return userDetails[i].UserId < userDetails[j].UserId })

	return userDetails, nil
}

func (auth *Authorization) GetAllUserSign() (map[string]string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	users := []UserInfo{}
	err = coll.Find(bson.M{"groupName": auth.groupName}).All(&users)
	if err != nil {
		return nil, err
	}

	userSigns := make(map[string]string)

	for _, user := range users {
		userId := user.UserId
		for signKey, _ := range user.SignKey {
			userSigns[signKey] = userId
		}
	}

	return userSigns, nil
}

func (auth *Authorization) UserCheckExist(userId string) bool {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return false
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	cnt, err := coll.Find(bson.M{"groupName": auth.groupName, "userId": userId}).Count()

	if err != nil {
		return false
	}

	return cnt > 0
}

func (auth *Authorization) UserAddInfo(info AddUser) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	signKey := bson.NewObjectId().Hex()
	privateKey := make(map[string]string)
	privateKey[signKey] = "用户私有签名"

	doc := UserInfo{
		Name:      info.Name,
		UserId:    info.UserId,
		GroupName: auth.groupName,
		SignKey:   privateKey,
	}

	if err := coll.Insert(doc); err != nil {
		return fmt.Errorf("add user exception %s", err.Error())
	}

	// 将用户添加至默认角色
	roleColl := session.DB(auth.dataBaseName).C(roleCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"isDefault": true,
	}

	update := bson.M{
		"$addToSet": bson.M{
			"userIds": bson.M{
				"$each": []string{info.UserId},
			},
		},
	}

	if err := roleColl.Update(query, update); err != nil {
		return fmt.Errorf("add user to default role exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) UserAdd(info AddUser) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	doc := UserInfo{
		Name:      info.Name,
		UserId:    info.UserId,
		GroupName: auth.groupName,
		SignKey:   map[string]string{},
	}

	if err := coll.Insert(doc); err != nil {
		return fmt.Errorf("add user exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) UserGetInfo() ([]UserInfo, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)

	coll := session.DB(auth.dataBaseName).C(userCollName)

	query := bson.M{
		"groupName": auth.groupName,
	}

	users := []UserInfo{}

	if err := coll.Find(query).Select(bson.M{"userId": 1, "name": 1}).All(&users); err != nil {
		return nil, fmt.Errorf("query users exception %s", err.Error())
	}

	return users, nil
}

func (auth *Authorization) UserGetInfoOne(userId string) (UserInfo, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return UserInfo{}, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
	}

	user := UserInfo{}

	if err := coll.Find(query).One(&user); err != nil {
		return UserInfo{}, fmt.Errorf("query user exception %s", err.Error())
	}

	return user, nil
}

func (auth *Authorization) UserGetInfoReg(userId string) ([]UserInfo, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"userId": bson.RegEx{
			Options: "i",
			Pattern: userId,
		},
	}

	users := []UserInfo{}

	if err := coll.Find(query).All(&users); err != nil {
		return nil, fmt.Errorf("query users exception %s", err.Error())
	}

	return users, nil
}

func (auth *Authorization) UserCreateDataSignKey(userId, uri, method string) (map[string]string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)

	userColl := session.DB(auth.dataBaseName).C(userCollName)

	//先查询自己创建的signKey
	q := bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
	}

	userInfo := UserInfo{}
	err = userColl.Find(q).Select(bson.M{"signKey": 1}).One(&userInfo)
	if err != nil {
		return nil, err
	}

	createSigns := make(map[string]string)
	//先组织出自己创建的signKey和signDesc
	for signKey, desc := range userInfo.SignKey {
		createSigns[signKey] = desc
	}

	signColl := session.DB(auth.dataBaseName).C(signCollName)

	num := auth.methodString2Num(method)

	q = bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
		fmt.Sprintf("verifyDataUri.%s", uri): bson.M{"$bitsAllSet": num},
	}

	signInfos := []SignInfo{}
	err = signColl.Find(q).All(&signInfos)

	if err != nil {
		return nil, err
	}

	if len(signInfos) == 0 { //该路由和方法不存在signKey
		return createSigns, nil
	}

	//拿到这些SignKey的真实创建者
	createUserIds := []string{}
	for _, info := range signInfos {
		createUserIds = append(createUserIds, info.CreateUserId)
	}

	//查询所有的User，这里明确了signKey是哪个userId创建的,从而拿到这些SignKey的描述信息
	userInfos := []UserInfo{}
	err = userColl.Find(bson.M{"groupName": auth.groupName, "userId": bson.M{"$in": createUserIds}}).All(&userInfos)
	if err != nil {
		return nil, err
	}

	//拿到所有signKey的描述
	allSignDescs := make(map[string]string)
	for _, user := range userInfos {
		for sign, desc := range user.SignKey {
			allSignDescs[sign] = desc
		}
	}

	for _, sign := range signInfos {
		createSigns[sign.SignKey] = allSignDescs[sign.SignKey]
	}

	return createSigns, nil
}

func (auth *Authorization) UserOwnSignsByUri(userId, uri, method string) ([]string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	q := bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
	}

	user := UserInfo{}
	err = coll.Find(q).One(&user)
	if err != nil {
		return nil, err
	}

	signKeys := []string{}
	for k, _ := range user.SignKey {
		signKeys = append(signKeys, k)
	}

	signColl := session.DB(auth.dataBaseName).C(signCollName)

	mnum := auth.methodString2Num(method)
	mnum |= 1 //默认把GET方法的SignKey也给出
	q = bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
		fmt.Sprintf("verifyDataUri.%s", uri): bson.M{"$bitsAnySet": mnum},
	}

	signs := []SignInfo{}
	err = signColl.Find(q).Select(bson.M{"signKey": 1}).All(&signs)
	if err != nil {
		return nil, err
	}

	for _, sign := range signs {
		signKeys = append(signKeys, sign.SignKey)
	}

	return signKeys, nil
}

func (auth *Authorization) FindSignKeyOwner(signKey string) (string, string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return "", "", err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	q := bson.M{
		"groupName":                        auth.groupName,
		fmt.Sprintf("signKey.%s", signKey): bson.M{"$exists": true},
	}

	user := UserInfo{}
	err = coll.Find(q).Select(bson.M{"name": 1, "userId": 1}).One(&user)

	return user.Name, user.UserId, err
}

func (auth *Authorization) UserUpdateSignKey(userId, signKey, signDesc string) error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
		fmt.Sprintf("signKey.%s", signKey): bson.M{"$exists": true},
	}

	update := bson.M{
		"$set": bson.M{
			fmt.Sprintf("signKey.%s", signKey): signDesc,
		},
	}

	if err := coll.Update(query, update); err != nil {
		return fmt.Errorf("update signKey exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) UserCreateSignKey(userId, signDesc string) (string, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return "", err
	}
	defer auth.mongoFactory.Put(session)
	coll := session.DB(auth.dataBaseName).C(userCollName)

	query := bson.M{
		"groupName": auth.groupName,
		"userId":    userId,
	}

	//每个人创建signKey 必须有限制，因为sign一旦创建不允许删除
	user, err := auth.UserGetInfoOne(userId)
	if err != nil {
		return "", err
	}

	if len(user.SignKey) > SignKeyLimit {
		return "", fmt.Errorf("sign key length limit %d", SignKeyLimit)
	}

	signKey := bson.NewObjectId().Hex()
	update := bson.M{
		"$set": bson.M{
			fmt.Sprintf("signKey.%s", signKey): signDesc,
		},
	}

	if err := coll.Update(query, update); err != nil {
		return "", fmt.Errorf("add signKey exception %s", err.Error())
	}

	return signKey, nil

	// 2017-10-16
	// 当新增signKey成功后,不需要将自己的userid和signkey添加到sign表中，如果该signkey是自己添加的，就默认他有该数据权限
}
