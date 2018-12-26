package oreoauth

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/xkeyideal/oreo"
	"github.com/xkeyideal/oreo/authoperate"
)

var LibraOreoAuth *oreo.Oreo

type UrlMethod struct {
	Uri     string   `json:"uri"`
	Exist   bool     `json:"exist"`
	Desc    string   `json:"desc"`
	Methods []string `json:"methods"`
}

type ProjectRoute struct {
	EntryRoutes   []authoperate.RouteListView `json:"entryRoutes"`
	IllegalRoutes []authoperate.RouteListView `json:"illegalRoutes"`
	ExportRoutes  []UrlMethod                 `json:"exportRoutes"`
}

func DiffOreoProjectRoutes(projectRoutes map[string][]string) (ProjectRoute, error) {
	oreoRoutes, err := LibraOreoAuth.GetRouteList()
	if err != nil {
		return ProjectRoute{}, err
	}

	entryRoutes := []authoperate.RouteListView{}
	illegalRoutes := []authoperate.RouteListView{}
	uriSet := make(map[string]string)
	methodSet := make(map[string]struct{})
	for _, oreoRoute := range oreoRoutes {
		if projectMethods, ok := projectRoutes[oreoRoute.Uri]; ok {

			uriSet[oreoRoute.Uri] = oreoRoute.Desc
			entryMethods := []authoperate.RouteMethod{}
			illegalMethods := []authoperate.RouteMethod{}

			for _, oreoMethod := range oreoRoute.Methods {
				exist := false
				for _, projectMethod := range projectMethods {
					if oreoMethod.Method == projectMethod {
						entryMethods = append(entryMethods, oreoMethod)
						methodSet[fmt.Sprintf("%s%s", oreoRoute.Uri, oreoMethod.Method)] = struct{}{}
						exist = true
						break
					}
				}
				if !exist {
					illegalMethods = append(illegalMethods, oreoMethod)
				}
			}

			if len(entryMethods) > 0 {
				entryRoutes = append(entryRoutes, authoperate.RouteListView{
					Uri:     oreoRoute.Uri,
					Desc:    oreoRoute.Desc,
					Methods: entryMethods,
				})
			}
			if len(illegalMethods) > 0 {
				illegalRoutes = append(illegalRoutes, authoperate.RouteListView{
					Uri:     oreoRoute.Uri,
					Desc:    oreoRoute.Desc,
					Methods: illegalMethods,
				})
			}
		} else {
			illegalRoutes = append(illegalRoutes, oreoRoute)
		}
	}

	exportRoutes := []UrlMethod{}
	for uri, methods := range projectRoutes {
		if uriDesc, ok := uriSet[uri]; !ok {
			exportRoutes = append(exportRoutes, UrlMethod{
				Uri:     uri,
				Exist:   false,
				Methods: methods,
			})
		} else {
			exportMethods := []string{}
			has := false
			for _, method := range methods {
				if _, ok := methodSet[fmt.Sprintf("%s%s", uri, method)]; !ok {
					exportMethods = append(exportMethods, method)
					has = true
				}
			}
			if has {
				exportRoutes = append(exportRoutes, UrlMethod{
					Uri:     uri,
					Exist:   true,
					Desc:    uriDesc,
					Methods: exportMethods,
				})
			}
		}
	}

	sort.Slice(entryRoutes, func(i, j int) bool { return entryRoutes[i].Uri < entryRoutes[j].Uri })
	sort.Slice(exportRoutes, func(i, j int) bool { return exportRoutes[i].Uri < exportRoutes[j].Uri })
	sort.Slice(illegalRoutes, func(i, j int) bool { return illegalRoutes[i].Uri < illegalRoutes[j].Uri })

	projectRoute := ProjectRoute{
		EntryRoutes:   entryRoutes,
		IllegalRoutes: illegalRoutes,
		ExportRoutes:  exportRoutes,
	}

	return projectRoute, nil
}

func Start(groupName string, singleTon bool, cacheInterval time.Duration, mgoUrl, database string) {
	var err error
	LibraOreoAuth, err = oreo.NewOreo(groupName, singleTon, cacheInterval, mgoUrl, database, 30, 30*time.Second)
	if err != nil {
		fmt.Println("Init Oreo Auth Err: ", err.Error())
		os.Exit(1)
	}
}

func Stop() {
	LibraOreoAuth.Stop()
}
