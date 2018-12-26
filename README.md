# oreo

说到权限很多人都会想到RBAC，ACL等等，这些方案都是十分成熟的权限管理方案，最早写PHP用yii2框架的时候，就自带了rbac权限管理，也对rbac比较熟悉，但今天想说的不仅仅局限于路由权限。

## RBAC权限管理

关于rbac权限管理gg可以出一堆文章，基于角色的访问控制，把一堆路由分配给一个角色，然后把一堆角色分配给项目中的某个人，此人即拥有这些路由的访问权限。

这里只对rbac做出简单的说明，此处不多说。

现在的矛盾来了，如果两个人People_A和People_B分别属于两个项目组Team_A, Team_B，同时这两个项目组分别拥有一条数据Data_A, Data_B，此数据有如下两条路由：

> * 1. GET /project/data 查询数据详情
> * 2. PUT /project/data 修改数据详情

People_A和People_B都拥有上述两个路由的权限，那么怎么区分二者只能操作各自组的数据Data_A和Data_B？

这里答案还是挺简单的，**人**与**数据**同时绑定了**项目组**，只需要判断**人**操作的**数据**是否同时属于一个**项目组**即可！！！ 

问题是否就这么简单呢？

再进一步的需求： People_A需要拥有Team_B的Data_B数据的上述两条数据权限，又该如何解决？

这个问题也比较简单，可以修改我们的业务逻辑。每个人可以属于多个组，即将People_A加入Team_B组，那么只需要在做Data_B的权限判断是判断People_A所在的所有组，只要一个组与Data_B是在一个组即可！！！

好开心呀，上述问题都解决了，是否就完了呢？

需求又来了，People_A只能拥有Team_B的Data_B数据的查询数据详情路由(GET /project/data)的权限，即People_A只能查看Data_B数据，不能修改。 这个需求如何搞？

好像现有的解决方案没法整呀！

下面进入正题，新鲜出炉的一套权限解决方案，也是我们项目经过多次权限的折腾最终总结出来的。

## 新权限的特点

>* 1. 路由权限的管理还是使用的RBAC
>* 2. 每条路由除了拥有路由权限，还拥有数据权限
>* 3. 为解决数据权限，每个用户可创建一个数据权限的key，我们叫做signKey
>* 4. 项目中启用数据权限的路由所操作的数据，都需要分配一个signKey
>* 5. signKey的创建者，只需要将他人加入到signKey的授权人中，并再给其分配相关数据权限的路由

说了上述几点，可能由于文字功底不足，完全听不懂，举个形象的栗子：
signKey就是一个QQ群，创建此signKey的就是群主，群主可以将数据上传到该群中，然后再拉一些人到此群中，那么这些人就能够对这些数据进行操作。同时给每个人分配的路由不一样，那么每个人对数据的操作权限也不一样，可以控制到部分人能够访问和修改数据，部分人只能访问数据而不能修改数据。

Talk is cheap, show me your code!

下面具体从数据结构层面分析，如下代码全部是golang编写，下述数据结构适用于mongodb的存储。

## 路由数据结构

```go
type RouteInfo struct {
	Uri       string        //路由        
	Desc      string        //路由的描述        
	GroupName string        //项目组  
	MethodMap map[string]VerifyData  //key是方法对应的数字
}

type VerifyData struct {
	Enable     bool   // 方法是否启用数据权限
	MethodDesc string // 方法的描述
}
```

为方便存储和在进行数据权限判断时能够使用二进制操作，所有方法全部对应相应的整型值:

```json
GET    --> 1
POST   --> 2
PUT    --> 4
DELETE --> 8
```

路由表存储所有项目应该有的路由和方法。

## 角色数据结构

```go
type RoleInfo struct {
	RoleName  string         // 角色名称
	Desc      string         // 角色描述
	GroupName string         // 项目组
	IsDefault bool           // 默认角色
	UserIds   []string       // 角色的拥有者
	RouterMap map[string]bool //key  method_uri(: 1_/project/data),value 是否开启数据权限
	Address   []Address       // 存一份冗余数据，在做操作的时候很有用途
	Type      int             //角色的类型
}

type Address struct {
	Uri         string  //路由
	MethodValue int     //这里是所有method对应的整型值之和
}
```

角色表就是用来实现RBAC的，创建角色时将路由表中的路由添加进来，然后再加人，即可实现完整的RBAC功能。但为了判断数据权限，RouterMap字段的value是bool值，如果该路由需要进行数据权限判断，那么此人拥有路由权限还不能操作数据，还需要进行数据权限判断。当然超级管理员无需此约束！！！

## 用户数据结构

```go
type UserInfo struct {
	Name      string            // 用户名字
	UserId    string            // 用户工号
	GroupName string            // 项目组
	SignKey   map[string]string //key是signKey，value是signKey的描述
}
```

用户表存储最基本的用户信息，其他各类用户的信息在项目中进行存储。SignKey字段就是用户创建的signKey。

## SignKey数据结构

```go
type SignInfo struct {
	SignKey       string        // 签名
	UserId        string        // 工号
	GroupName     string        // 项目组
	VerifyDataUri map[string]int  // key uri, value 是方法的整型值的和
}
```

SignKey与UserId组成唯一索引，一个SignKey可以分配给多个UserId，但VerifyDataUri的不同，就能够区分不同用户拥有不同的数据权限。

对于SignKey解决数据权限的栗子：

- 现有如下三个路由和方法开启了数据权限， `GET /project/querydata`(**查询数据**), `POST /project/updatedata`(**修改数据**) 和 `DELETE /project/deletedata`(**删除数据**)。

- 现有三个用户 `PeopleA`, `PeopleB`, `PeopleC`。

- 现`PeopleA` 创建了一个`signKey`叫做 `PeopleA_SignKey_1`，同时`PeopleA` 创建了一条数据`Data1`并且绑定了 `PeopleA_SignKey_1`，那么自然`PeopleA`能够通过上述三个路由对`Data1`数据进行**查询**，**修改**，**删除**操作，当`PeopleB`和`PeopleC`不能操作数据`Data1`，因为这三个路由开启了数据权限。

- 现`PeopleA`需要让`PeopleB`仅能够**查看**`Data1`数据，`PeopleC`能够**查看**和**修改**`Data1`数据，该如何操作呢？

- `PeopleA`仅需要将(`PeopleA_SignKey_1`、`GET /project/querydata`)授权给`PeopleB`即可；
`PeopleA`需要将(`PeopleA_SignKey_1`、`GET /project/querydata`和`POST /project/updatedata`)授权给`PeopleC`即可；
此时即可符合上述需求。

- 上述问题会自发地引出下一个问题，即上述`PeopleA`创建的`PeopleA_SignKey_1`的signKey只是自己绑定路由和方法后授权给`PeopleB`和`PeopleC`的，那么`PeopleA`创建的`PeopleA_SignKey_1`能够让另外一个人授权给`PeopleB`和`PeopleC`吗？

- 答案是肯定的，此时假设授权signKey的路由为 `PUT /oreo/auth/grantsign`，并且该路由和方法开启了数据权限，现`PeopleA`需要`PeopleD`的协助，使`PeopleD`能够帮助自己将`PeopleA_SignKey_1`授权给他人。

- 此时`PeopleA`只需要将(`PeopleA_SignKey_1`、`PUT /oreo/auth/grantsign`)授权给`PeopleD`即可，此时`PeopleD`就可以协助管理`PeopleA_SignKey_1`了。

- 此时经过上述操作后`PeopleD`能够**查询**，**修改**或**删除**数据`Data1`吗？
- 答案是否，因为`PeopleA` 没有将相关的路由和方法绑定`PeopleA_SignKey_1`授权给`PeopleD`。

- 此时经过上述操作后，若`PeopleA`又创建了一个`PeopleA_SignKey_2`的signKey，`PeopleD`能够协助管理吗？
- 答案也是否，因为`PeopleA` 没有绑定管理`PeopleA_SignKey_2`的路由和方法给`PeopleD`。 

整个权限的设计思路和数据结构即说明结束了，下面需要解决另一个问题。

现在许多路由都是动态路由，什么是动态路由：

>* 项目定义路由： GET /project/:name/*path
>* 用户实际访问请求： GET /project/xkeyideal/usr/local/lib
>* 访问请求是能够匹配上项目定义的路由

此时的问题就是如何用户访问请求能够成功匹配上项目定义的路由？

解决方案有两个：
>* 1. 简单粗暴，不允许在项目定义动态匹配的字段，全部都是明确的，任何参数都通过Query或Body传参。此方法是最佳方案，不会出错，也无需大动干戈。
>* 2. 必须支持动态匹配字段（为啥要装逼？？？），自己写动态匹配代码，golang有开源库的实现[vestigo](https://github.com/husobee/vestigo)

最后简单给出，我们实现方案简单的权限判断流程图：
![权限判断流程图](https://github.com/xkeyideal/oreo/blob/master/image.jpeg)

图上的说明应该能看懂，这里仅仅是我们的权限判断流程，需要采用者，可以结合上述思路进行扩展。
