package oreoauth

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func OreoAuthRouter(router *gin.Engine, prefix string, mw ...gin.HandlerFunc) {
	group := router.Group(fmt.Sprintf("%s/oreo/auth", prefix), mw...)
	{
		//route相关api
		//group.GET("/route/print", printRoutes) //打印内存中所有的路由数据，仅供测试使用
		group.GET("/route", routeLists)      //路由列表
		group.POST("/route", addRoutes)      //添加路由
		group.PUT("/route", updateRouteDesc) //修改路由的描述
		group.DELETE("/route", delRoute)     //删除路由

		group.GET("/route/method", dataAuthMethod)    //查询拥有数据权限的路由和method
		group.PUT("/route/method", enableDataAuth)    //启用路由method的数据权限
		group.POST("route/method", disableDataAuth)   //停用路由method的数据权限
		group.DELETE("/route/method", delRouteMethod) //删除路由下的某个Method

		group.PUT("/route/method/desc", updateRouteMethodDesc) //修改路由下某个Method的描述

		group.GET("/route/info", queryRouteInfo) //查询某个url的路由信息，支持正则查询

		//role相关api
		group.GET("/role", roleRouteDiff) //角色拥有的路由和方法与全局路由和方法的diff
		group.POST("/role", addRole)      //添加角色
		group.DELETE("/role", delRole)    //删除角色

		group.GET("/role/user", queryUserRole) //查询用户拥有的角色，仅返回角色名称
		group.POST("/role/user", addRoleUser)  //向角色添加用户
		group.PUT("/role/user", delRoleUser)   //删除角色中的用户

		group.GET("/role/info", queryRoleInfo)       //查询角色信息
		group.PUT("/role/info", setDefaultRole)      //设置默认角色
		group.POST("/role/info", updateRoleTypeDesc) //更新角色的类型和角色的描述

		//user相关api
		group.GET("/user", queryUserInfo)       //查询用户信息
		group.PUT("/user", queryUserInfoSimple) //查询所有用户信息，仅返回userId和name
		//group.POST("/user", addUser)      //添加用户

		group.GET("/user/sign", userOwnSign)    //查询用户拥有的signKey信息
		group.POST("/user/sign", addUserSign)   //用户添加自己signKey
		group.PUT("/user/sign", updateUserSign) //用户修改自己signKey的描述

		/*
			此api放在sdk中有安全风险，原则上用户只能将自己的signKey转移给别人，当然超级管理员除外，
			否则应该判断，系统的当前登录者与需要转移的signKey传参的所谓创建者是否是一致的，否则即会出现系统安全漏洞
		*/
		//group.POST("/user/sign/transfer", transferSign) // 将signKey转给他人

		group.GET("/user/role", userOwnRole) //查询用户拥有的角色信息

		//sign相关api
		group.GET("/sign", querySign)  //查询signKey已授权给的用户和相关路由方法
		group.POST("/sign", addSign)   //授权signKey给他人
		group.PUT("/sign", copySign)   //复制sign给他人
		group.DELETE("/sign", delSign) //删除已授权signKey的人

		group.GET("/sign/users", signDiffGlobal) //某人拥有的signKey授权的路由与方法与所有开启数据权限路由和方法的diff
		group.PUT("/sign/users", appendSignUri)  //为批量用户追加signKey的Uri Method
		group.POST("/sign/users", removeSignUri) //为批量用户删除signKey的Uri Method
	}
}
