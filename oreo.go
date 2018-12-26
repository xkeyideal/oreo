package oreo

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xkeyideal/oreo/authoperate"
	"github.com/xkeyideal/oreo/mongo"
	"github.com/xkeyideal/oreo/route"
)

type Oreo struct {
	auth         *authoperate.Authorization
	mongoFactory *mongo.MongoFactory
	route        route.RouteType
	groupName    string
	done         chan struct{}
}

func NewOreo(groupName string, singleton bool, cacheInterval time.Duration,
	mgoDsn, db string, maxOpenConn int, connTimeout time.Duration) (*Oreo, error) {

	oreo := &Oreo{
		groupName: groupName,
		done:      make(chan struct{}),
	}

	mgoFactory, err := mongo.NewMongoFactory(mgoDsn, maxOpenConn, connTimeout)

	if err != nil {
		return nil, err
	}

	oreo.mongoFactory = mgoFactory

	auth, err := authoperate.NewAuthorization(groupName, db, oreo.mongoFactory)

	if err != nil {
		return nil, err
	}

	oreo.auth = auth

	if singleton {
		oreo.route = route.NewSingletonRoute(auth)
	} else {
		oreo.route = route.NewConcurrencyRoute(auth)
	}

	oreo.route.LoadRoutesFromDb(groupName)

	if !singleton {
		go oreo.route.ReloadRoutesFromDb(groupName, cacheInterval, oreo.done)
	}

	return oreo, nil
}

func (oreo *Oreo) Stop() {
	close(oreo.done)
	oreo.mongoFactory.Close()
}

/******************Auth********************/
// 查询用户有路由权限的路由和方法
func (oreo *Oreo) QueryUserGrantRoute(userId string) (map[string]int, bool, error) {
	return oreo.auth.UserGrantRoute(userId)
}

// 根据UserId,Uri,Method查出其可以用于创建数据的signKey
func (oreo *Oreo) QueryUserCreateDataSignKey(url, method, userId string) (map[string]string, error) {
	rawurl, ok := oreo.route.Match(oreo.groupName, method, url)
	if !ok {
		return nil, errors.New(fmt.Sprintf("[%s %s] - 路由未匹配成功", url, method))
	}

	return oreo.auth.UserCreateDataSignKey(userId, rawurl, method)
}

// 根据UserId,Uri,Method查出其有权限的signKey
func (oreo *Oreo) QueryUserSignByUrl(url, method, userId string) ([]string, error) {
	rawurl, ok := oreo.route.Match(oreo.groupName, method, url)
	if !ok {
		return nil, errors.New(fmt.Sprintf("[%s %s] - 路由未匹配成功", url, method))
	}

	return oreo.auth.UserOwnSignsByUri(userId, rawurl, method)
}

// 查询权限
func (oreo *Oreo) CheckUserAuth(url, method, userId, signKey string) (bool, bool, string) {
	method = strings.TrimSpace(strings.ToUpper(method))

	rawurl, ok := oreo.route.Match(oreo.groupName, method, url)
	if !ok {
		return false, false, fmt.Sprintf("[%s %s] - 路由未匹配成功", method, url)
	}
	isAdmin, roleAuth, existDataAuth := oreo.auth.QueryRoleAuth(rawurl, method, userId)

	//没有角色权限直接返回
	if !roleAuth {
		return isAdmin, false, fmt.Sprintf("[%s]没有路由[%s %s]的角色权限", userId, method, rawurl)
	}

	//不需要判断数据权限
	if !existDataAuth {
		return isAdmin, roleAuth, ""
	}

	dataAuth := oreo.auth.QuerySignAuth(signKey, rawurl, method, userId)

	if !dataAuth {
		return isAdmin, false, fmt.Sprintf("[%s %s]没有[%s %s]数据权限", userId, signKey, method, rawurl)
	}

	return isAdmin, true, ""
}

func (oreo *Oreo) PrintRoutes() {
	oreo.route.PrintAllRoutes()
}

/******************User********************/

//获取所有用户，仅返回用户名和工号
func (oreo *Oreo) GetAllUsers() ([]authoperate.UserDetail, error) {
	return oreo.auth.GetAllUsers()
}

// 添加用户，会默认创建一个signkey
func (oreo *Oreo) AddUser(userId, name string) error {
	info := authoperate.AddUser{
		UserId: userId,
		Name:   name,
	}
	return oreo.auth.UserAddInfo(info)
}

// 判断用户是否存在
func (oreo *Oreo) CheckUserExist(userId string) bool {
	return oreo.auth.UserCheckExist(userId)
}

// 添加用户，不加入到默认角色里
func (oreo *Oreo) AddUserNoRole(userId, name string) error {
	info := authoperate.AddUser{
		UserId: userId,
		Name:   name,
	}
	return oreo.auth.UserAdd(info)
}

// 查询所有用户创建的signKey
func (oreo *Oreo) GetAllSign() (map[string]string, error) {
	return oreo.auth.GetAllUserSign()
}

// 根据Id正则查询用户信息列表
func (oreo *Oreo) GetUserByIdRegex(userId string) ([]authoperate.UserInfo, error) {
	return oreo.auth.UserGetInfoReg(userId)
}

// 获取userId拥有的signKey与描述信息，不仅仅包含该userId所创建的，还包括他人之前赋予给他的
func (oreo *Oreo) UserOwnSigns(userId string) (authoperate.UserSignList, error) {
	return oreo.auth.UserOwnSigns(userId)
}

// 获取userId拥有的角色信息
func (oreo *Oreo) UserOwnRoles(userId string) ([]authoperate.RoleUserListView, error) {
	return oreo.auth.UserOwnRoles(userId)
}

// 获取userId拥有的角色类型
func (oreo *Oreo) UserOwnRoleTypes(userId string) ([]int, error) {
	return oreo.auth.UserOwnRoleTypes(userId)
}

// 用户添加自己的signKey
func (oreo *Oreo) CreateUserSignKey(userId, signDesc string) (string, error) {
	return oreo.auth.UserCreateSignKey(userId, signDesc)
}

//更新用户的某个signKey的描述
func (oreo *Oreo) UpdateUserSignKey(userId, signKey, signDesc string) error {
	return oreo.auth.UserUpdateSignKey(userId, signKey, signDesc)
}

// 转让某人的signKey给他人
func (oreo *Oreo) UserTransferSignKey(signKey, signDesc, srcUserId, destUserId string) error {
	return oreo.auth.UserTransferSignKey(signKey, signDesc, srcUserId, destUserId)
}

/******************Role********************/

// 添加角色，目前url+methodValue是一改全改，不会做merge操作的增量修改
func (oreo *Oreo) AddRole(roleName, roleDesc string, roleType int, isDefault bool, urlMethod map[string]int) error {
	addrs := []authoperate.Address{}

	for url, methodValue := range urlMethod {
		addrs = append(addrs, authoperate.Address{
			Uri:         strings.TrimSpace(strings.ToLower(url)),
			MethodValue: methodValue,
		})
	}

	roleInfo := authoperate.UpsertRoleInfo{
		RoleName:  roleName,
		Desc:      roleDesc,
		AddrList:  addrs,
		Type:      roleType,
		IsDefault: isDefault,
	}

	return oreo.auth.RoleUpsert(roleInfo)
}

// 添加用户为某个角色
func (oreo *Oreo) AddRoleUsers(roleName string, userIds []string) error {
	return oreo.auth.RoleAddUser(roleName, userIds)
}

// 删除角色
func (oreo *Oreo) RemoveRole(roleName string) error {
	return oreo.auth.RoleRemove(roleName)
}

// 查询用户拥有的角色名称，仅返回角色名称
func (oreo *Oreo) UserOwnRolenames(userId string) ([]string, error) {
	return oreo.auth.UserOwnRolenames(userId)
}

// 删除角色中的用户
func (oreo *Oreo) RemoveRoleUsers(roleName string, userIds []string) error {
	return oreo.auth.RoleRemoveUser(roleName, userIds)
}

// 角色拥有的路由和方法与全局路由和方法的diff
func (oreo *Oreo) RoleRouteDiff(roleName string) ([]authoperate.RouteListView, error) {
	return oreo.auth.RoleRouteDiff(roleName)
}

// 查询角色名称角色信息，不传为查询所有
func (oreo *Oreo) GetRoleList(roleName string) ([]authoperate.RoleListView, error) {
	return oreo.auth.RoleInfoList(roleName)
}

// 设置默认角色
func (oreo *Oreo) SetDefaultRole(roleName string) error {
	return oreo.auth.RoleSetDefault(roleName)
}

// 更新角色的类型
func (oreo *Oreo) UpdateRoleTypeDesc(roleName string, roleDesc string, roleType int) error {
	return oreo.auth.RoleUpdateTypeDesc(roleName, roleDesc, roleType)
}

/******************Route********************/

// 添加路由, 会自动merge数据库中已经存在的url+method，但存在的不会修改其enable和desc属性
func (oreo *Oreo) AddRoute(routes []route.RouteData) error {
	return oreo.route.AddRoute(oreo.groupName, routes)
}

// 更新路由的描述信息
func (oreo *Oreo) UpdateRouteDesc(url, desc string) error {
	url = strings.ToLower(strings.TrimSpace(url))
	return oreo.auth.RouterUpdateUriDesc(url, desc)
}

// 更新路由下Method的描述信息
func (oreo *Oreo) UpdateRouteMethodDesc(url, method, desc string) error {
	url = strings.ToLower(strings.TrimSpace(url))
	method = strings.ToUpper(strings.TrimSpace(method))
	return oreo.auth.RouterUpdateMethodDesc(url, method, desc)
}

// url + method 启用数据权限
func (oreo *Oreo) EnableRouteDataAuth(url, method string) error {
	return oreo.route.EnableRouteDataAuth(oreo.groupName, url, method)
}

// url + method 停用数据权限
func (oreo *Oreo) DisableRouteDataAuth(url, method string) error {
	return oreo.route.DisableRouteDataAuth(oreo.groupName, url, method)
}

//删除一个路由和method
func (oreo *Oreo) DeleteRouteByMethod(url, method string) error {
	return oreo.route.DeleteRouteByMethod(oreo.groupName, url, method)
}

// 删除路由
func (oreo *Oreo) DeleteRoute(url string) error {
	return oreo.route.DeleteRoute(oreo.groupName, url)
}

// 查询路由列表
func (oreo *Oreo) GetRouteList() ([]authoperate.RouteListView, error) {
	return oreo.auth.RouterList(false)
}

// 根据url查询路由信息
func (oreo *Oreo) GetRouteByUrl(url string) (authoperate.RouteListView, error) {
	url = strings.ToLower(strings.TrimSpace(url))
	return oreo.auth.RouterInfoByUri(url)
}

// 根据url正则查询路由信息
func (oreo *Oreo) GetRouteByUrlRegex(url string) ([]authoperate.RouteListView, error) {
	url = strings.ToLower(strings.TrimSpace(url))
	return oreo.auth.RouterGetInfoReg(url)
}

// 获取哪些路由有数据权限
func (oreo *Oreo) GetDataAuthRoutes() ([]authoperate.RouteListView, error) {
	return oreo.auth.RouterList(true)
}

/******************Sign********************/

// 添加Sign，目前url+methodValue是一改全改，不会做merge操作的增量更新
func (oreo *Oreo) AddSign(signKey, userId string, urlMethod map[string]int) error {

	addrs := []authoperate.Address{}

	for url, methodValue := range urlMethod {
		addrs = append(addrs, authoperate.Address{
			Uri:         url,
			MethodValue: methodValue,
		})
	}

	signInfo := authoperate.UpsertSignInfo{
		SignKey:  signKey,
		UserId:   userId,
		AddrList: addrs,
	}

	return oreo.auth.SignUpsert(signInfo)
}

// 删除Sign
func (oreo *Oreo) RemoveSign(signKey, userId string) error {
	return oreo.auth.SignRemove(signKey, userId)
}

// 通过signKey查询sign信息
func (oreo *Oreo) GetSignByKey(signKey string) (authoperate.SignListView, error) {
	return oreo.auth.SignGetInfo(signKey)
}

// 复制sign
func (oreo *Oreo) CopyUserSign(signKey, srcUserId string, destUserIds []string) error {
	return oreo.auth.SignCopy(signKey, srcUserId, destUserIds)
}

// 为批量用户新增数据权限的url和method
func (oreo *Oreo) AppendUserSign(signKey string, userIds []string, urlMethod map[string]int) error {
	return oreo.auth.SignPatchVerifyData(signKey, userIds, urlMethod)
}

// 为批量用户删除数据权限的url和method
func (oreo *Oreo) RemoveUserSign(signKey string, userIds []string, urlMethod map[string]int) error {
	return oreo.auth.SignRemoveVerifyData(signKey, userIds, urlMethod)
}

// 单个用户拥有的某个signKey包含的路由和方法与全局开启数据权限的路由和方法的diff
func (oreo *Oreo) UserSignDiffGlobal(signKey, userId string) ([]authoperate.RouteListView, error) {
	return oreo.auth.SignDiffGlobalDataAuthRoute(signKey, userId)
}
