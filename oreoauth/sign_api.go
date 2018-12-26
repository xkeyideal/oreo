package oreoauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func querySign(c *gin.Context) {
	signKey := strings.TrimSpace(c.Query("signKey"))

	sl, err := LibraOreoAuth.GetSignByKey(signKey)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(sl)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func addSign(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	sign := AuthSign{}
	err = json.Unmarshal(bytes, &sign)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	urlMethodVal := make(map[string]int)
	for url, methods := range sign.UrlMethods {
		methodVal := 0
		for _, method := range methods {
			methodVal += methodString2Num(method)
		}

		if methodVal > 0 {
			url = strings.ToLower(strings.TrimSpace(url))
			urlMethodVal[url] = methodVal
		}
	}

	err = LibraOreoAuth.AddSign(sign.SignKey, sign.UserId, urlMethodVal)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusCreated, 0, "OK", "", c)
}

func copySign(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	sign := AuthSignCopy{}
	err = json.Unmarshal(bytes, &sign)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.CopyUserSign(sign.SignKey, sign.SrcUserId, sign.DestUserIds)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func delSign(c *gin.Context) {
	userId := strings.TrimSpace(c.Query("userId"))
	signKey := strings.TrimSpace(c.Query("signKey"))

	err := LibraOreoAuth.RemoveSign(signKey, userId)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func signDiffGlobal(c *gin.Context) {
	userId := strings.TrimSpace(c.Query("userId"))
	signKey := strings.TrimSpace(c.Query("signKey"))

	diffDr, err := LibraOreoAuth.UserSignDiffGlobal(signKey, userId)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(diffDr)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func appendSignUri(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	signUri := AuthSignUri{}
	err = json.Unmarshal(bytes, &signUri)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	urlMethodVal := make(map[string]int)
	for url, methods := range signUri.UrlMethods {
		methodVal := 0
		for _, method := range methods {
			methodVal += methodString2Num(method)
		}

		if methodVal > 0 {
			url = strings.ToLower(strings.TrimSpace(url))
			urlMethodVal[url] = methodVal
		}
	}

	err = LibraOreoAuth.AppendUserSign(signUri.SignKey, signUri.UserIds, urlMethodVal)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func removeSignUri(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	signUri := AuthSignUri{}
	err = json.Unmarshal(bytes, &signUri)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	urlMethodVal := make(map[string]int)
	for url, methods := range signUri.UrlMethods {
		methodVal := 0
		for _, method := range methods {
			methodVal += methodString2Num(method)
		}

		if methodVal > 0 {
			url = strings.ToLower(strings.TrimSpace(url))
			urlMethodVal[url] = methodVal
		}
	}

	err = LibraOreoAuth.RemoveUserSign(signUri.SignKey, signUri.UserIds, urlMethodVal)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}
