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
	name    = "passcode"
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

func AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	action := ctx.Query("action")
	if strings.EqualFold(action, "refresh") || strings.EqualFold(action, "nhp-refresh") {
		AuthWithHttpRefresh(ctx, action, req, helper)
		return
	}
	resId := ctx.Query("resid")

	res, err := FindResourceApi(ctx, resId)
	if err != nil {
		log.Error("call FindResourceApi failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.String(http.StatusOK, "{\"errMsg\": \"resource error: %v\"}", err)
		return
	}
	// ctx.SetCookie("res_id", resId, 86400, "/", res.CookieDomain, true, false)
	ctx.SetSameSite(http.SameSiteNoneMode)
	CorsMiddleware(ctx)

	switch {
	case strings.EqualFold(action, "valid"):
		startTime := time.Now()
		format := ctx.Query("format")
		errCode := ""
		ackMsg, errCode, err = authRegular(ctx, req, res, helper)
		if time.Since(startTime).Seconds() > 3 {
			log.Info("authRegular took timeout %s", time.Since(startTime))
		} else {
			log.Info("authRegular took %s", time.Since(startTime))
		}
		if err != nil {
			if format == "json" {
				ctx.JSON(http.StatusOK, RefreshResponse{
					RedirectUrl: "/plugins/passcode?resid=" + resId + "&action=error&id=" + errCode,
					ErrCode:     errCode,
					ErrMsg:      err.Error(),
				})
			} else {
				ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+errCode)
			}
		}
	case strings.EqualFold(action, "knock"):
		ackMsg, err = knockByToken(ctx, req, res, helper)
	case strings.EqualFold(action, "login"):
		ackMsg, err = authAndShowLogin(ctx, req, res, helper)
	case strings.EqualFold(action, "error"):
		ackMsg, err = authAndShowRefreshError(ctx)
	default:
		ackMsg = nil
		err = fmt.Errorf("action invalid")
	}
	return
}

func AuthWithHttpRefresh(ctx *gin.Context, action string, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	nHPToken := getCookie("nhp_token", ctx)
	payload, err := ParseJWTToken(nHPToken)
	if err != nil {
		log.Error("cannot parse JWT: %v", err)
	}
	resId := payload.ResourceID
	log.Info("resId from nhp_token: %s", resId)
	res, err := FindResourceApi(ctx, resId)
	if err != nil {
		log.Error("call FindResourceApi failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.String(http.StatusOK, "{\"errMsg\": \"resource error: %v\"}", err)
		return
	}
	jwt := &JWTToken{
		jwtKey: []byte(res.ExInfo["JWTSecret"].(string)),
	}

	isOk, err := jwt.Validate(nHPToken, TokenTypeNHPToken)
	if err != nil {
		return nil, err
	}
	if !isOk {
		log.Error("nhp token is invalid")
		return nil, fmt.Errorf("nhp token is invalid")
	}

	CorsMiddleware(ctx)
	if strings.EqualFold(action, "refresh") {
		startTime := time.Now()
		ackMsg, err = RefreshToken(ctx, req, res, helper)
		if time.Since(startTime).Seconds() > 3 {
			log.Info("refreshToken took timeout %s", time.Since(startTime))
		} else {
			log.Info("refreshToken took %s", time.Since(startTime))
		}
	} else if strings.EqualFold(action, "nhp-refresh") {
		ackMsg, err = authAndShowRefresh(ctx, req, res, helper)
	} else {
		ackMsg = nil
		err = fmt.Errorf("unknown action: %s", action)
		log.Error("unknown action error: %v", err)
		ctx.String(http.StatusBadRequest, "{\"errMsg\": \"unknown action: %s\"}", action)
	}

	return
}

func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	ackMsg = req.Ack
	if helper == nil {
		return ackMsg, fmt.Errorf("AuthWithNHP: helper is null")
	}

	var found bool
	var res *common.ResourceData
	resourceMapMutex.Lock()
	res, found = resourceMap[req.Msg.ResourceId]
	resourceMapMutex.Unlock()

	if !found || len(res.Resources) == 0 {
		err = common.ErrResourceNotFound
		ackMsg.ErrCode = common.ErrResourceNotFound.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// there is no backend auth in this plugin, fail the request if SkipAuth is false
	if !res.SkipAuth {
		err = common.ErrBackendAuthRequired
		ackMsg.ErrCode = common.ErrBackendAuthRequired.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// skip backend auth and continue with AC operations
	log.Info("agent user [%s]: skip auth", req.Msg.UserId)
	ackMsg.OpenTime = res.OpenTime
	ackMsg.ResourceHost = res.Hosts()

	// PART III: request ac operation for each resource and block for response
	ackMsg, err = helper.AuthWithNhpCallbackFunc(req, res)

	return ackMsg, err
}

func authAndShowLogin(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("authAndShowLogin: helper is null")
	}

	if res.ExInfo == nil {
		log.Error("extra login info not available")
		ctx.String(http.StatusOK, "{\"errMsg\": \"extra login info not available\"}")
		return nil, fmt.Errorf("extra login info not available")
	}

	ctx.HTML(http.StatusOK, "passcode/passcode_login.html", gin.H{
		"title":       res.ExInfo["Title"].(string),
		"nhpServer":   hostname,
		"aspId":       req.AuthServiceId,
		"resId":       res.ResourceId,
		"exInfo":      res.ExInfo,
		"redirectUrl": res.RedirectUrl,
	})

	return nil, nil
}

func authAndShowRefreshError(ctx *gin.Context) (*common.ServerKnockAckMsg, error) {
	ctx.HTML(http.StatusOK, "passcode/error.html", gin.H{})
	return nil, nil
}

func authAndShowRefresh(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("authAndShowLogin: helper is null")
	}

	if res.ExInfo == nil {
		log.Error("extra login info not available")
		ctx.String(http.StatusOK, "{\"errMsg\": \"extra login info not available\"}")
		return nil, fmt.Errorf("extra login info not available")
	}

	ctx.HTML(http.StatusOK, "passcode/nhp_refresh.html", gin.H{
		"title":       res.ExInfo["Title"].(string),
		"nhpServer":   hostname,
		"aspId":       req.AuthServiceId,
		"resId":       res.ResourceId,
		"exInfo":      res.ExInfo,
		"redirectUrl": res.RedirectUrl,
	})

	return nil, nil
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
		jwtKey: []byte(res.ExInfo["JWTSecret"].(string)),
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

func knockByToken(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
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
		jwtKey: []byte(res.ExInfo["JWTSecret"].(string)),
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

			if len(res.RedirectUrl) == 0 {
				log.Error("RedirectUrl is not provided.")
			} else {
				redirectURL, err := url.Parse(res.RedirectUrl)
				if err != nil {
					log.Error("failed to parse redirect url: %v", err)
					return ackMsg, nil
				} else {
					defaultRes := loadbalancing(ackMsg.ResourceHost)
					if len(defaultRes) > 0 {
						redirectURL.Host = defaultRes
					} else {
						log.Error("no resource host available for redirect")
						return ackMsg, nil
					}
					log.Info("All host [%+v] , load balancing redirectURL: %s", ackMsg.ResourceHost, redirectURL.String())
				}
				ctx.Redirect(http.StatusFound, redirectURL.String())
				return ackMsg, nil
			}

			return ackMsg, nil
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

func authRegular(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "400", fmt.Errorf(" authRegular helper is null")
	}

	var err error
	passcode := ctx.Query("passcode")
	AuthUrl := baseConf.AuthUrl
	if len(AuthUrl) == 0 {
		log.Error("AuthUrl is not provided.")
		return nil, "401", fmt.Errorf("AuthUrl is not provided")
	}
	if len(passcode) == 0 {
		log.Error("passcode is not provided.")
		return nil, "402", fmt.Errorf("passcode is not provided")
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
	reqUrl += "PC/auth"
	reqUrl += "?resid=" + res.ResourceId
	reqUrl += "&code=" + passcode
	log.Info("auth request URL: %s", reqUrl)
	httpReq, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		log.Error("failed to create HTTP request: %v", err)
		return nil, "405", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	httpReq.Header.Set("User-Agent", "OpenNHP/"+Version())
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	// Add any additional headers if needed
	httpReq.Header.Set("X-Requested-With", "XMLHttpRequest")

	// 发送请求
	client := &http.Client{}
	authResp, err := client.Do(httpReq)
	if err != nil {
		log.Error("Error sending request: %v", err)
		return nil, "406", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	defer authResp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(authResp.Body)
	if err != nil {
		log.Error("Error reading response body: %v", err)
		return nil, "407", fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// 检查 HTTP 状态码
	if authResp.StatusCode != http.StatusOK {
		log.Error("API request failed with status code %d: %s", authResp.StatusCode, string(body))
		return nil, "408", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	type Response struct {
		Code int         `json:"code"`
		Data interface{} `json:"data"`
		Msg  string      `json:"msg"`
	}
	// 解析 JSON 响应
	var apiResponse Response
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		log.Error("Error unmarshaling response: %v", err)
		return nil, "409", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	if apiResponse.Code != 0 {
		log.Error("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
		return nil, fmt.Sprintf("50%d", apiResponse.Code), fmt.Errorf("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
	}

	resp := &RefreshResponse{}
	// interact with udp server for door operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)
	if ackMsg == nil || len(ackMsg.ResourceHost) == 0 {
		log.Error("knock failed. ackMsg is nil")
		ackMsg = &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		if err != nil {
			ackMsg.ErrMsg = err.Error()
		} else {
			ackMsg.ErrMsg = "ackMsg is nil"
		}
	} else {
		log.Info("knock succeeded.%+v", res.Resources)

		jwt := &JWTToken{
			jwtKey: []byte(res.ExInfo["JWTSecret"].(string)),
		}
		nhpToken, refreshToken, err := jwt.GenerateAll(res.AuthServiceId, res)
		if err != nil {
			log.Error("failed to generate token: %v", err)
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = err.Error()
			ctx.JSON(http.StatusOK, ackMsg)
			return ackMsg, "410", err
		}
		log.Info("token: %s", nhpToken)

		ackMsg.ErrMsg = ""
		// assign the redirect url to the ackMsg
		if len(res.RedirectUrl) == 0 {
			log.Error("RedirectUrl is not provided.")
		} else {
			redirectURL, err := url.Parse(res.RedirectUrl)
			if err != nil {
				log.Error("failed to parse redirect url: %v", err)
				return ackMsg, "411", nil
			} else {
				defaultRes := loadbalancing(ackMsg.ResourceHost)
				if len(defaultRes) > 0 {
					redirectURL.Host = defaultRes
				} else {
					log.Error("no resource host available for redirect")
					return ackMsg, "412", nil
				}
				log.Info("All host [%+v] , load balancing redirectURL: %s", ackMsg.ResourceHost, redirectURL.String())
			}
			resp.RedirectUrl = redirectURL.String()
		}
		resp.CookieDomain = res.CookieDomain
		resp.ResourceHost = ackMsg.ResourceHost
		resp.NHPRefreshToken = refreshToken
		resp.NHPToken = nhpToken

		log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
		ctx.JSON(http.StatusOK, resp)
		log.Info("Done %+v", resp)
		return ackMsg, "", nil
	}

	ctx.JSON(http.StatusOK, resp)
	return ackMsg, "", nil
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

func loadbalancing[T any](m map[string]T) T {
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
	resp := &ReResponse{
		ID:           apiResponse.Data.ID,
		CreatedAt:    apiResponse.Data.CreatedAt,
		UpdatedAt:    apiResponse.Data.UpdatedAt,
		SiteName:     apiResponse.Data.SiteName,
		SiteURL:      apiResponse.Data.SiteURL,
		SiteIcon:     apiResponse.Data.SiteIcon,
		Description:  apiResponse.Data.Description,
		Category:     apiResponse.Data.Category,
		Status:       apiResponse.Data.Status,
		IsCommend:    apiResponse.Data.IsCommend,
		JwtSecret:    apiResponse.Data.JwtSecret,
		Opentime:     apiResponse.Data.Opentime,
		SkipAuth:     apiResponse.Data.SkipAuth,
		AppID:        apiResponse.Data.AppID,
		TokenExpire:  apiResponse.Data.TokenExpire,
		CreatedBy:    apiResponse.Data.CreatedBy,
		UpdatedBy:    apiResponse.Data.UpdatedBy,
		DeletedBy:    apiResponse.Data.DeletedBy,
		CookieDomain: apiResponse.Data.CookieDomain,
	}

	// Copy ExtInfo fields
	resp.ExtInfo.ClientId = apiResponse.Data.ExtInfo.ClientId
	resp.ExtInfo.LoginAppKey = apiResponse.Data.ExtInfo.LoginAppKey
	resp.ExtInfo.LoginAppSecret = apiResponse.Data.ExtInfo.LoginAppSecret
	resp.ExtInfo.RedirectWithParams = apiResponse.Data.ExtInfo.RedirectWithParams

	// Convert Resources
	for _, res := range apiResponse.Data.Resources {
		resourceData := ResourceData{
			AcID:     res.AcID,
			Hostname: res.Hostname,
			IP:       res.IP,
			Port:     res.Port,
			Maskhost: res.Maskhost,
			Protocol: res.Protocol,
		}
		resp.Resources = append(resp.Resources, resourceData)
	}

	return resp, "", nil
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

func FindResourceApi(ctx *gin.Context, resId string) (*common.ResourceData, error) {
	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	response, statusCode, err := findResourceFromUrl(resId)

	format := ctx.Query("format")
	if err != nil {
		if format == "json" {
			ctx.JSON(http.StatusOK, RefreshResponse{
				RedirectUrl: "/plugins/passcode?resid=" + resId + "&action=error&id=" + statusCode,
				ErrCode:     statusCode,
				ErrMsg:      err.Error(),
			})
		} else {
			ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+statusCode)
		}
	}

	resourceMap, err := mapResourceRsp(response)
	if err != nil {
		err = fmt.Errorf("mapResourceRsp failed: %v", err)
		return nil, err
	}

	res, found := resourceMap[resId]
	if found {
		return res, nil
	}
	err = fmt.Errorf("FindResourceApi failed")
	return nil, err
}

type FullResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		ID          int       `json:"ID"`
		CreatedAt   time.Time `json:"CreatedAt"`
		UpdatedAt   time.Time `json:"UpdatedAt"`
		SiteName    string    `json:"site_name"`
		SiteURL     string    `json:"site_url"`
		SiteIcon    string    `json:"site_icon"`
		Description string    `json:"description"`
		Category    string    `json:"category"`
		Status      string    `json:"status"`
		IsCommend   bool      `json:"is_commend"`
		JwtSecret   string    `json:"jwt_secret"`
		Resources   []struct {
			AcID     string `json:"ac_id"`
			Hostname string `json:"hostname"`
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Maskhost bool   `json:"maskhost"`
			Protocol string `json:"protocol"`
		} `json:"resources"`
		ExtInfo struct {
			ClientId           string `json:"ClientId"`
			LoginAppKey        string `json:"LoginAppKey"`
			LoginAppSecret     string `json:"LoginAppSecret"`
			RedirectWithParams string `json:"RedirectWithParams"`
		} `json:"ext_info"`
		Opentime     int    `json:"opentime"`
		SkipAuth     bool   `json:"skip_auth"`
		AppID        string `json:"app_id"`
		TokenExpire  int64  `json:"token_expire"`
		CreatedBy    int    `json:"CreatedBy"`
		UpdatedBy    int    `json:"UpdatedBy"`
		DeletedBy    int    `json:"DeletedBy"`
		CookieDomain string `json:"cookie_domain"`
	} `json:"data"`
}

// Define return structure
type ReResponse struct {
	ID          int            `json:"ID"`
	CreatedAt   time.Time      `json:"CreatedAt"`
	UpdatedAt   time.Time      `json:"UpdatedAt"`
	SiteName    string         `json:"site_name"`
	SiteURL     string         `json:"site_url"`
	SiteIcon    string         `json:"site_icon"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Status      string         `json:"status"`
	IsCommend   bool           `json:"is_commend"`
	JwtSecret   string         `json:"jwt_secret"`
	Opentime    int            `json:"opentime"`
	SkipAuth    bool           `json:"skip_auth"`
	AppID       string         `json:"app_id"`
	TokenExpire int64          `json:"token_expire"`
	CreatedBy   int            `json:"CreatedBy"`
	UpdatedBy   int            `json:"UpdatedBy"`
	DeletedBy   int            `json:"DeletedBy"`
	Resources   []ResourceData `json:"resources"`
	ExtInfo     struct {
		ClientId           string `json:"ClientId"`
		LoginAppKey        string `json:"LoginAppKey"`
		LoginAppSecret     string `json:"LoginAppSecret"`
		RedirectWithParams string `json:"RedirectWithParams"`
	} `json:"ext_info"`
	CookieDomain string `json:"cookie_domain"`
}

type ResourceData struct {
	AcID     string `json:"ac_id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Maskhost bool   `json:"maskhost"`
	Protocol string `json:"protocol"`
}
