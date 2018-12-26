package oreoauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func roleRouteDiff(c *gin.Context) {
	roleName := strings.TrimSpace(c.Query("roleName"))

	dr, err := LibraOreoAuth.RoleRouteDiff(roleName)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(dr)

	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func addRole(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	role := AuthRole{}
	err = json.Unmarshal(bytes, &role)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	urlMethodVal := make(map[string]int)
	for url, methods := range role.UrlMethods {
		methodVal := 0
		for _, method := range methods {
			methodVal += methodString2Num(method)
		}

		if methodVal > 0 {
			url = strings.ToLower(strings.TrimSpace(url))
			urlMethodVal[url] = methodVal
		}
	}

	err = LibraOreoAuth.AddRole(role.RoleName, role.RoleDesc, role.RoleType, role.IsDefault, urlMethodVal)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusCreated, 0, "OK", "", c)
}

func delRole(c *gin.Context) {
	roleName := strings.TrimSpace(c.Query("roleName"))

	err := LibraOreoAuth.RemoveRole(roleName)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func queryUserRole(c *gin.Context) {
	userId := strings.TrimSpace(c.Query("userId"))

	roleNames, err := LibraOreoAuth.UserOwnRolenames(userId)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(roleNames)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func addRoleUser(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	roleUser := AuthRoleUser{}
	err = json.Unmarshal(bytes, &roleUser)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.AddRoleUsers(roleUser.RoleName, roleUser.RoleUsers)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusCreated, 0, "OK", "", c)
}

func delRoleUser(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	roleUser := AuthRoleUser{}
	err = json.Unmarshal(bytes, &roleUser)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.RemoveRoleUsers(roleUser.RoleName, roleUser.RoleUsers)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func queryRoleInfo(c *gin.Context) {
	roleName := strings.TrimSpace(c.Query("roleName"))

	rl, err := LibraOreoAuth.GetRoleList(roleName)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(rl)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func setDefaultRole(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	roleInfo := AuthRoleInfo{}
	err = json.Unmarshal(bytes, &roleInfo)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.SetDefaultRole(roleInfo.RoleName)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func updateRoleTypeDesc(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	roleInfo := AuthRoleInfo{}
	err = json.Unmarshal(bytes, &roleInfo)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.UpdateRoleTypeDesc(roleInfo.RoleName, roleInfo.RoleDesc, roleInfo.RoleType)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}
