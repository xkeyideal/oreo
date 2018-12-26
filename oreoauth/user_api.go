package oreoauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func queryUserInfo(c *gin.Context) {
	userId := strings.TrimSpace(c.Query("userId"))

	ul, err := LibraOreoAuth.GetUserByIdRegex(userId)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(ul)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func queryUserInfoSimple(c *gin.Context) {
	ul, err := LibraOreoAuth.GetAllUsers()
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(ul)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func addUser(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	user := AuthUser{}
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.AddUser(user.UserId, user.Name)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusCreated, 0, "OK", "", c)
}

func userOwnSign(c *gin.Context) {
	userId := strings.TrimSpace(c.Query("userId"))

	ul, err := LibraOreoAuth.UserOwnSigns(userId)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(ul)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func userOwnRole(c *gin.Context) {
	userId := strings.TrimSpace(c.Query("userId"))

	ul, err := LibraOreoAuth.UserOwnRoles(userId)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(ul)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func addUserSign(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	userSign := AuthUserSign{}
	err = json.Unmarshal(bytes, &userSign)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	signKey, err := LibraOreoAuth.CreateUserSignKey(userSign.UserId, userSign.SignDesc)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusCreated, 0, "OK", signKey, c)
}

func updateUserSign(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	userSign := AuthUserSign{}
	err = json.Unmarshal(bytes, &userSign)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.UpdateUserSignKey(userSign.UserId, userSign.SignKey, userSign.SignDesc)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}
