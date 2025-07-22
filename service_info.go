package nhppluginssdk

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type FullResponse struct {
	Code int        `json:"code"`
	Msg  string     `json:"msg"`
	Data ReResponse `json:"data"`
}

// Define return structure
type ReResponse struct {
	FullResponseData
	Resources   []ResourceData `json:"resources"`
	ExtInfo     map[string]any `json:"ext_info"`
	ServiceInfo ServiceInfo    `json:"service_info,omitempty"`
}

type FullResponseData struct {
	ID           int       `json:"ID"`
	CreatedAt    time.Time `json:"CreatedAt"`
	UpdatedAt    time.Time `json:"UpdatedAt"`
	SiteName     string    `json:"site_name"`
	SiteURL      string    `json:"site_url"`
	SiteIcon     string    `json:"site_icon"`
	Description  string    `json:"description"`
	Category     string    `json:"category"`
	Status       string    `json:"status"`
	IsCommend    bool      `json:"is_commend"`
	JwtSecret    string    `json:"jwt_secret"`
	Opentime     int       `json:"opentime"`
	SkipAuth     bool      `json:"skip_auth"`
	AppID        string    `json:"app_id"`
	TokenExpire  int64     `json:"token_expire"`
	CreatedBy    int       `json:"CreatedBy"`
	UpdatedBy    int       `json:"UpdatedBy"`
	DeletedBy    int       `json:"DeletedBy"`
	CookieDomain string    `json:"cookie_domain"`
}

type ResourceData struct {
	AcID     string `json:"ac_id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Maskhost bool   `json:"maskhost"`
	Protocol string `json:"protocol"`
}

type ServiceInfo struct {
	AppId  string `json:"app_id"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"` // 注意是小写 "scheme"
}

type JWTClaims struct {
	EncryptedData string `json:"access_key"` // 加密后的数据
	jwt.RegisteredClaims
}
