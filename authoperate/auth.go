package authoperate

import (
	"fmt"
	"strings"

	"github.com/xkeyideal/oreo/mongo"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type Authorization struct {
	groupName    string
	dataBaseName string

	mongoFactory *mongo.MongoFactory
}

const (
	roleCollName   = "TC_OREO_ROLES"
	groupCollName  = "TC_OREO_GROUP"
	routerCollName = "TC_OREO_ROUTER"
	signCollName   = "TC_OREO_SIGN"
	userCollName   = "TC_OREO_USER"

	SignKeyLimit       = 50
	splitString        = "_/oreo/_"
	superAdminRoleType = 1
)

var groupIndex mgo.Index = mgo.Index{
	Key:    []string{"groupName"},
	Unique: true,
	Name:   "groupName",
}

type GroupInfo struct {
	GroupName  string `json:"groupName" bson:"groupName"`
	GroupToken string `json:"groupToken" bson:"groupToken"`
}

func NewAuthorization(groupName, db string, mf *mongo.MongoFactory) (*Authorization, error) {

	auth := &Authorization{
		groupName:    groupName,
		dataBaseName: db,
		mongoFactory: mf,
	}

	if err := auth.initCollIndex(); err != nil {
		return nil, err
	}

	if err := auth.initGroup(); err != nil {
		return nil, err
	}

	return auth, nil
}

func (auth *Authorization) methodString2Num(method string) int {
	val := 0
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case "GET":
		val = 1
	case "POST":
		val = 2
	case "PUT":
		val = 4
	case "DELETE":
		val = 8
	}
	return val
}

func (auth *Authorization) initGroup() error {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return err
	}
	defer auth.mongoFactory.Put(session)

	coll := session.DB(auth.dataBaseName).C(groupCollName)

	count, err := coll.Find(bson.M{"groupName": auth.groupName}).Count()
	if err != nil {
		return fmt.Errorf(" Init group exception %s", err.Error())
	}

	if count == 1 {
		return nil
	}

	d := GroupInfo{
		GroupName:  auth.groupName,
		GroupToken: bson.NewObjectId().Hex(),
	}

	if err := coll.Insert(d); err != nil {
		return fmt.Errorf(" Init group exception %s", err.Error())
	}

	return nil
}

func (auth *Authorization) GetGroupInfo() ([]GroupInfo, error) {
	session, err := auth.mongoFactory.Get()
	if err != nil {
		return nil, err
	}
	defer auth.mongoFactory.Put(session)

	coll := session.DB(auth.dataBaseName).C(groupCollName)

	groups := []GroupInfo{}

	if err := coll.Find(bson.M{}).All(&groups); err != nil {
		return nil, fmt.Errorf("query groups info exception %s", err.Error())
	}

	return groups, nil
}

func (auth *Authorization) MethodToNumString(method string) (string, error) {
	//upper := strings.ToUpper(method)  说不用转，直接比，不是大写就返回。
	var numStr string
	var err error

	switch method {
	case "GET":
		numStr = "1"
	case "POST":
		numStr = "2"
	case "PUT":
		numStr = "4"
	case "DELETE":
		numStr = "8"
	default:
		err = fmt.Errorf("%s invlid method, only support GET POST PUT DELETE", method)
	}

	return numStr, err
}

func (auth *Authorization) NumStringToMethod(numStr string) string {
	var upperMethod string

	switch numStr {
	case "1":
		upperMethod = "GET"
	case "2":
		upperMethod = "POST"
	case "4":
		upperMethod = "PUT"
	case "8":
		upperMethod = "DELETE"
	default:
		upperMethod = "Unknown"
	}

	return upperMethod
}

func (auth *Authorization) NumStringToNum(numStr string) int {
	var num int

	switch numStr {
	case "1":
		num = 1
	case "2":
		num = 2
	case "4":
		num = 4
	case "8":
		num = 8
	}

	return num
}

func (auth *Authorization) MethodValueToMethods(value int) []string {
	sm := []int{1, 2, 4, 8}
	ms := []string{}
	for _, v := range sm {
		if value&v > 0 {
			ms = append(ms, fmt.Sprintf("%d", v))
		}
	}
	return ms
}

func (auth *Authorization) initCollIndex() error {
	if err := auth.mongoFactory.CreateIndex(auth.dataBaseName, roleCollName, roleIndex); err != nil {
		return err
	}

	if err := auth.mongoFactory.CreateIndex(auth.dataBaseName, userCollName, userIndex); err != nil {
		return err
	}

	if err := auth.mongoFactory.CreateIndex(auth.dataBaseName, routerCollName, routerIndex); err != nil {
		return err
	}

	if err := auth.mongoFactory.CreateIndex(auth.dataBaseName, signCollName, signIndex); err != nil {
		return err
	}

	if err := auth.mongoFactory.CreateIndex(auth.dataBaseName, groupCollName, groupIndex); err != nil {
		return err
	}

	return nil
}
