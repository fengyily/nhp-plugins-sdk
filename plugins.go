package nhppluginssdk

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	nhplog "github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"
	nhppluginssdk "github.com/fengyily/nhp-plugins-sdk"
	"github.com/gin-gonic/gin"

	toml "github.com/pelletier/go-toml/v2"
)

var (
	// Example Plugin Settings
	log           *nhplog.Logger
	pluginDirPath string
	hostname      string
	localIp       string
	localMac      string
)

var (
	name    = "nhp-plugins-sdk"
	version = "0.1.1"

	baseConfigWatch io.Closer
	resConfigWatch  io.Closer

	baseConf         *Config
	resourceMapMutex sync.Mutex
	resourceMap      common.ResourceGroupMap
)

var (
	errLoadConfig = fmt.Errorf("config load error")
)

func Version() string {
	return fmt.Sprintf("%s v%s", name, version)
}

func Init(in *plugins.PluginParamsIn) error {
	if in.PluginDirPath != nil {
		pluginDirPath = *in.PluginDirPath
	}
	if in.Log != nil {
		log = in.Log
	}
	if in.Hostname != nil {
		hostname = *in.Hostname
	}
	if in.LocalIp != nil {
		localIp = *in.LocalIp
	}
	if in.LocalMac != nil {
		localMac = *in.LocalMac
	}

	// load config
	fileNameBase := (filepath.Join(pluginDirPath, "etc", "config.toml"))
	if err := updateConfig(fileNameBase); err != nil {
		// ignore error
		_ = err
	}

	baseConfigWatch = utils.WatchFile(fileNameBase, func() {
		log.Info("base config: %s has been updated", fileNameBase)
		updateConfig(fileNameBase)
	})

	fileNameRes := filepath.Join(pluginDirPath, "etc", "resource.toml")
	if err := updateResource(fileNameRes); err != nil {
		// ignore error
		_ = err
	}
	resConfigWatch = utils.WatchFile(fileNameRes, func() {
		log.Info("resource config: %s has been updated", fileNameRes)
		updateResource(fileNameRes)
	})
	rand.Seed(time.Now().UnixNano())
	return nil
}

func updateConfig(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read base config: %v", err)
	}

	var conf Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal base config: %v", err)
	}

	baseConf = &conf
	return err
}

func updateResource(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read resource config: %v", err)
	}

	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	resourceMap = make(common.ResourceGroupMap)
	if err := toml.Unmarshal(content, &resourceMap); err != nil {
		log.Error("failed to unmarshal resource config: %v", err)
	}

	// res is pointer so we can update its fields
	for resId, res := range resourceMap {
		res.AuthServiceId = name
		res.ResourceId = resId
	}

	return err
}

func Close() error {
	if baseConfigWatch != nil {
		baseConfigWatch.Close()
	}
	if resConfigWatch != nil {
		resConfigWatch.Close()
	}
	return nil
}

func RefreshToken(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("refreshToken: helper is null")
	}

	oldNHPToken := getCookie("nhp_token", ctx)

	if len(oldNHPToken) == 0 {
		log.Error("old token is empty")
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = "old token is empty"
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, fmt.Errorf("old token is empty")
	}
	refreshToken := getCookie("nhp_refresh_token", ctx)
	if len(refreshToken) == 0 {
		log.Error("refresh token is empty")

		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = "refresh token is empty"
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, fmt.Errorf("refresh token is empty")
	}
	jwt := &JWTToken{
		JwtKey: []byte(res.ExInfo["JWTSecret"].(string)),
	}
	nhpToken, err := jwt.ExchangeNHPToken(oldNHPToken, refreshToken, res)
	if err != nil {
		log.Error("failed to generate token: %v", err)
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, err
	}

	// interact with udp server for door operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)
	if ackMsg == nil || err != nil {
		log.Error("knock failed. ackMsg is nil")
		ackMsg = &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		if err != nil {
			ackMsg.ErrMsg = err.Error()
		} else {
			ackMsg.ErrMsg = "ackMsg is nil"
		}
	} else {
		if len(ackMsg.ResourceHost) > 0 {
			log.Info("knock succeeded.%+v", res.Resources)
			log.Info("token: %s", nhpToken)

			ctx.SetCookie("nhp_token", nhpToken, int(int(res.ExInfo["TokenExpire"].(int64))), "/", res.CookieDomain, true, false)
			ctx.SetCookie("nhp_refresh_token", refreshToken, int(int(res.ExInfo["TokenExpire"].(int64))), "/", res.CookieDomain, true, false)
			ctx.SetSameSite(http.SameSiteNoneMode)
			ackMsg.ErrMsg = ""
			// assign the redirect url to the ackMsg
			if len(res.RedirectUrl) == 0 {
				log.Error("RedirectUrl is not provided.")
			} else {
				ackMsg.RedirectUrl = res.RedirectUrl
			}
		} else {
			ctx.SetCookie("nhp_token", nhpToken, 0, "/", res.CookieDomain, true, false)
			ctx.SetCookie("nhp_refresh_token", refreshToken, 0, "/", res.CookieDomain, true, false)
			ctx.SetSameSite(http.SameSiteNoneMode)
			log.Error("knock failed. ackMsg is nil")
			ackMsg = &common.ServerKnockAckMsg{}
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = "ackMsg is nil"
		}
	}
	ctx.JSON(http.StatusOK, map[string]string{
		"access_token":  nhpToken,
		"refresh_token": refreshToken,
	})
	return ackMsg, nil
}

func CorsMiddleware(c *gin.Context) {

	// Must be the SPECIFIC origin (not *) when credentials are true
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Credentials", "true")

	c.Header("Access-Control-Allow-Methods", "POST, GET, PUT, PATCH, OPTIONS, DELETE")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
	c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Type, Authorization")
	c.Header("Access-Control-Max-Age", "86400") // 24 hours

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}

	c.Next()
}

func GetCookie(name string, c *gin.Context) string {
	return getCookie(name, c)
}

func getCookie(name string, c *gin.Context) string {
	// 获取所有 Cookie
	cookies := c.Request.Cookies()

	// 创建一个 map 来存储非空 Cookie
	cookieMap := make(map[string]*http.Cookie)

	for _, cookie := range cookies {
		// 如果 Cookie 值不为空，则存入 map（后出现的会覆盖先出现的）
		if cookie.Value != "" {
			cookieMap[cookie.Name] = cookie
		}
	}
	if ck, ok := cookieMap[name]; ok {
		return ck.Value
	} else {
		return ""
	}
}

func Loadbalancing[T any](m map[string]T) T {
	var zero T // 类型的零值

	rand.Seed(time.Now().UnixNano())
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	if len(keys) == 0 {
		return zero
	}

	return m[keys[rand.Intn(len(keys))]]
}

func findResourceFromUrl(resId string) (*ReResponse, string, error) {
	var err error
	AuthUrl := baseConf.AuthUrl
	if len(AuthUrl) == 0 {
		log.Error("AuthUrl is not provided.")
		return nil, "401", fmt.Errorf("AuthUrl is not provided")
	}
	if !strings.HasPrefix(AuthUrl, "http") {
		log.Error("AuthUrl is not a valid URL: %s", AuthUrl)
		return nil, "403", fmt.Errorf("AuthUrl is not a valid URL: %s", AuthUrl)
	}
	// Prepare the request to the authentication URL
	authUrl, err := url.Parse(AuthUrl)
	if err != nil {
		log.Error("failed to parse AuthUrl: %v", err)
		return nil, "404", fmt.Errorf("failed to parse AuthUrl: %v", err)
	}
	reqUrl := authUrl.String()
	if !strings.HasSuffix(reqUrl, "/") {
		reqUrl += "/"
	}
	reqUrl += "ps/FindSiteByApplicationId"
	reqUrl += "?app_id=" + resId
	log.Info("auth request URL: %s", reqUrl)
	httpReq, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		log.Error("failed to create HTTP request: %v", err)
		return nil, "405", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	httpReq.Header.Set("User-Agent", "OpenNHP/"+Version())
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Requested-With", "XMLHttpRequest")
	// Send the HTTP request
	client := &http.Client{}
	authResp, err := client.Do(httpReq)
	if err != nil {
		log.Error("Error sending request: %v", err)
		return nil, "406", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	defer authResp.Body.Close()

	// Read response body
	body, err := io.ReadAll(authResp.Body)
	if err != nil {
		log.Error("Error reading response body: %v", err)
		return nil, "407", fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// Check HTTP status code
	if authResp.StatusCode != http.StatusOK {
		log.Error("API request failed with status code %d: %s", authResp.StatusCode, string(body))
		return nil, "408", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	// Parse JSON response
	var apiResponse FullResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		log.Error("Error unmarshaling response: %v", err)
		return nil, "409", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	if apiResponse.Code != 0 {
		log.Error("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
		return nil, fmt.Sprintf("50%d", apiResponse.Code), fmt.Errorf("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
	}
	//  Construct return structure
	reResponse := &ReResponse{
		FullResponseData: apiResponse.Data.FullResponseData,
		ServiceInfo:      apiResponse.Data.ServiceInfo,
		Resources:        apiResponse.Data.Resources,
		ExtInfo:          apiResponse.Data.ExtInfo,
	}
	return reResponse, "", nil
}

func mapResourceRsp(resRsp *ReResponse) (common.ResourceGroupMap, error) {
	if resRsp == nil {
		return nil, fmt.Errorf("input ReResponse is nil")
	}

	resourceGroupMap := make(common.ResourceGroupMap)

	if len(resRsp.Resources) == 0 {
		return resourceGroupMap, nil
	}

	resourceGroupId := resRsp.AppID

	resourceGroup := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId:     name,
			ResourceId:        resourceGroupId,
			OpenTime:          uint32(resRsp.Opentime),
			AuthProviderToken: resRsp.JwtSecret,
			Resources:         make(map[string]*common.ResourceInfo),
		},
		// Initialize extended fields
		AppKey:             resRsp.ExtInfo.LoginAppKey,
		AppSecret:          resRsp.ExtInfo.LoginAppSecret,
		AccessKey:          "",
		SecretKey:          "",
		ExInfo:             make(map[string]any),
		RedirectUrl:        resRsp.SiteURL,
		RedirectWithParams: false,
		SkipAuth:           resRsp.SkipAuth,
		CookieDomain:       resRsp.CookieDomain,
	}

	resourceGroup.ExInfo["ClientId"] = resRsp.ExtInfo.ClientId
	resourceGroup.ExInfo["LoginAppKey"] = resRsp.ExtInfo.LoginAppKey
	resourceGroup.ExInfo["LoginAppSecret"] = resRsp.ExtInfo.LoginAppSecret
	resourceGroup.ExInfo["RedirectWithParams"] = resRsp.ExtInfo.RedirectWithParams
	resourceGroup.ExInfo["JWTSecret"] = resRsp.JwtSecret
	resourceGroup.ExInfo["Title"] = resRsp.SiteName
	resourceGroup.ExInfo["TokenExpire"] = resRsp.TokenExpire

	// resourceGroup.ExInfo["AuthUrl"] = resRsp.SiteURL

	if resRsp.ExtInfo.RedirectWithParams == "true" {
		resourceGroup.RedirectWithParams = true
	}

	for _, res := range resRsp.Resources {
		resourceKey := res.AcID

		resourceInfo := &common.ResourceInfo{
			ACId:       res.AcID,
			Hostname:   res.Hostname,
			PortSuffix: false,
			MaskHost:   res.Maskhost,
		}

		if res.IP != "" && res.Port > 0 {
			resourceInfo.Addr = &common.NetAddress{
				Ip:       res.IP,
				Port:     res.Port,
				Protocol: res.Protocol,
			}
		}

		resourceGroup.Resources[resourceKey] = resourceInfo
	}
	resourceGroupMap[resourceGroupId] = resourceGroup

	return resourceGroupMap, nil
}

func FindResourceApi(resId string) (*common.ResourceData, error) {
	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	response, statusCode, err := findResourceFromUrl(resId)
	if err != nil {
		log.Error("FindResourceApi failed: %v", err)
	}

	log.Info("FindResourceApi statusCode=%s response: %v", statusCode, response)
	resourceMap, err := mapResourceRsp(response)
	if err != nil {
		err = fmt.Errorf("mapResourceRsp failed: %v", err)
		return nil, err
	}

	res, found := resourceMap[resId]
	if found {
		nhppluginssdk.Log().Info("FindResourceApi res: %v", res)
		return res, nil
	}
	err = fmt.Errorf("FindResourceApi failed: not found resource with id %s", resId)
	return nil, err
}
