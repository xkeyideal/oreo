package oreoauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/xkeyideal/oreo/route"

	"github.com/gin-gonic/gin"
)

func AddRoutes(routes []route.RouteData) error {
	return LibraOreoAuth.AddRoute(routes)
}

func printRoutes(c *gin.Context) {
	LibraOreoAuth.PrintRoutes()
	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func routeLists(c *gin.Context) {
	rs, err := LibraOreoAuth.GetRouteList()

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(rs)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func addRoutes(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	routes := []route.RouteData{}
	err = json.Unmarshal(bytes, &routes)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.AddRoute(routes)

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusCreated, 0, "OK", "", c)
}

func updateRouteDesc(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	r := AuthUrlMethods{}
	err = json.Unmarshal(bytes, &r)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.UpdateRouteDesc(r.Url, r.Desc)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	for _, method := range r.Methods {
		err = LibraOreoAuth.UpdateRouteMethodDesc(r.Url, method.Method, method.Desc)
		if err != nil {
			setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
			return
		}
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func delRoute(c *gin.Context) {
	url := strings.TrimSpace(c.Query("url"))

	err := LibraOreoAuth.DeleteRoute(url)
	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func enableDataAuth(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	r := AuthUrlMethod{}
	err = json.Unmarshal(bytes, &r)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.EnableRouteDataAuth(r.Url, r.Method)

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func disableDataAuth(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	r := AuthUrlMethod{}
	err = json.Unmarshal(bytes, &r)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.DisableRouteDataAuth(r.Url, r.Method)

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func delRouteMethod(c *gin.Context) {
	url := c.Query("url")
	method := c.Query("method")

	err := LibraOreoAuth.DeleteRouteByMethod(url, method)

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func updateRouteMethodDesc(c *gin.Context) {
	bytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		setStrResp(http.StatusBadRequest, HTTP_BODY_ERR, err.Error(), "", c)
		return
	}

	r := AuthUrlMethod{}
	err = json.Unmarshal(bytes, &r)
	if err != nil {
		setStrResp(http.StatusBadRequest, JSON_UNMARSHAL, err.Error(), "", c)
		return
	}

	err = LibraOreoAuth.UpdateRouteMethodDesc(r.Url, r.Method, r.Desc)

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	setStrResp(http.StatusOK, 0, "OK", "", c)
}

func dataAuthMethod(c *gin.Context) {
	dr, err := LibraOreoAuth.GetDataAuthRoutes()

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(dr)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}

func queryRouteInfo(c *gin.Context) {
	url := c.Query("url")

	ris, err := LibraOreoAuth.GetRouteByUrlRegex(url)

	if err != nil {
		setStrResp(http.StatusBadRequest, OREO_AUTH_ERR, err.Error(), "", c)
		return
	}

	res, _ := json.Marshal(ris)
	setStrResp(http.StatusOK, 0, "OK", string(res), c)
}
