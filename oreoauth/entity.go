package oreoauth

type AuthUrlMethod struct {
	Url    string `json:"url"`
	Method string `json:"method"`
	Desc   string `json:"desc"`
}

type AuthMethod struct {
	Method string `json:"method"`
	Desc   string `json:"desc"`
}

type AuthUrlMethods struct {
	Url     string       `json:"url"`
	Desc    string       `json:"desc"`
	Methods []AuthMethod `json:"methods"`
}

type AuthRole struct {
	RoleName   string              `json:"roleName"`
	RoleDesc   string              `json:"roleDesc"`
	RoleType   int                 `json:"roleType"` //角色类型，1表示超管
	IsDefault  bool                `json:"isDefault"`
	UrlMethods map[string][]string `json:"urlMethods"`
}

type AuthRoleUser struct {
	RoleName  string   `json:"roleName"`
	RoleUsers []string `json:"roleUsers"`
}

type AuthRoleInfo struct {
	RoleName string `json:"roleName"`
	RoleDesc string `json:"roleDesc"`
	RoleType int    `json:"roleType"`
}

type AuthUser struct {
	UserId string `json:"userId"`
	Name   string `json:"name"`
}

type AuthUserSign struct {
	UserId   string `json:"userId"`
	SignKey  string `json:"signKey"`
	SignDesc string `json:"signDesc"`
}

type AuthSign struct {
	UserId     string              `json:"userId"`
	SignKey    string              `json:"signKey"`
	UrlMethods map[string][]string `json:"urlMethods"`
}

type AuthSignCopy struct {
	SignKey     string   `json:"signKey"`
	SignDesc    string   `json:"signDesc"`
	SrcUserId   string   `json:"srcUserId"`
	DestUserIds []string `json:"destUserIds"`
}

type AuthSignUri struct {
	SignKey    string              `json:"signKey"`
	UserIds    []string            `json:"userIds"`
	UrlMethods map[string][]string `json:"urlMethods"`
}
