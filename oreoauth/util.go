package oreoauth

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	JSON_MARSHAL   = 10000
	JSON_UNMARSHAL = 10001
	HTTP_BODY_ERR  = 10002
	OREO_AUTH_ERR  = 10003
)

var errCodeMsg = map[int]string{
	JSON_MARSHAL:   "[JSON 序列化异常]: ",
	JSON_UNMARSHAL: "[JSON 反序列化异常]: ",

	HTTP_BODY_ERR: "[HTTP BODY读取异常]: ",
	OREO_AUTH_ERR: "[权限接口处理异常]: ",
}

func setStrResp(httpCode, code int, msg, result string, c *gin.Context) {

	m := msg

	if v, ok := errCodeMsg[code]; ok {
		m = fmt.Sprintf("%s%s", v, msg)
	}

	c.JSON(httpCode, gin.H{
		"code":   code,
		"msg":    m,
		"result": result,
	})
}

func methodString2Num(method string) int {
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

func PermissionFilter(c *gin.Context) {
	userId := c.Request.Header.Get("userId")
	signKey := c.Request.Header.Get("signKey")

	uri := c.Request.URL.Path
	//fmt.Println(uri, c.Request.Method)

	_, ok, err := LibraOreoAuth.CheckUserAuth(uri, c.Request.Method, userId, signKey)
	//fmt.Println(userId, isAdmin, ok)

	if !ok {
		c.JSON(0, gin.H{
			"code": 401,
			"msg":  err,
		})
		c.Abort()
		return
	}

	c.Next()
}
