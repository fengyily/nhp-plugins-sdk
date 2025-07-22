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
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	nhplog "github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/fengyily/nhp-plugins-sdk/resource"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
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
	baseConf        *resource.Config
)

var (
	errLoadConfig  = fmt.Errorf("config load error")
	resourceHander resource.ResourceHandler
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

	var conf resource.Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal base config: %v", err)
	}

	baseConf = &conf

	switch baseConf.ResourceMode {
	case "file":
		resourceHander = resource.NewResource(resource.ResourceTypeFile)
		log.Info("Resource mode set to file")
	case "api":
		resourceHander = resource.NewResource(resource.ResourceTypeAPI)
		log.Info("Resource mode set to API")
	default:
		resourceHander = resource.NewResource(resource.ResourceTypeAPI)
		log.Info("Resource mode set to default API")
	}
	return err
}

func Close() error {
	if baseConfigWatch != nil {
		baseConfigWatch.Close()
	}

	return nil
}

func FindResource(resId string) (*common.ResourceData, error) {
	if resourceHander == nil {
		log.Error("resource handler is not initialized")
		return nil, fmt.Errorf("resource handler is not initialized")
	}

	return resourceHander.FindResourceByID(resId)
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

func GetRedirectUrlByResource(ackMsg *common.ServerKnockAckMsg, res *common.ResourceData) (*common.ServerKnockAckMsg, string, error) {
	if len(res.RedirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
		return ackMsg, "", nil
	} else {
		redirectURL, err := url.Parse(res.RedirectUrl)
		if err != nil {
			log.Error("failed to parse redirect url: %v", err)
			return ackMsg, "", err
		} else {
			defaultRes := Loadbalancing(ackMsg.ResourceHost)
			if len(defaultRes) > 0 {
				redirectURL.Host = defaultRes
			} else {
				log.Error("no resource host available for redirect")
				return ackMsg, "", err
			}
			log.Info("All host [%+v] , load balancing redirectURL: %s", ackMsg.ResourceHost, redirectURL.String())
		}
		serviceInfo := resource.ServiceInfo{
			AppId:  res.ResourceId,
			IP:     nhpsdkutils.GetStringFromMap(res.ExInfo, "Ip"),
			Port:   nhpsdkutils.GetIntFromMap(res.ExInfo, "Port"),
			Scheme: nhpsdkutils.GetStringFromMap(res.ExInfo, "Scheme"),
		}

		// 1. 序列化ServiceInfo为JSON
		infoJSON, err := json.Marshal(serviceInfo)
		if err != nil {
			log.Error("failed to marshal service info: %v", err)
			// return ackMsg, nil
		}
		// 2. AES-GCM加密
		encryptedInfo, err := EncryptWithGCM(infoJSON)
		if err != nil {
			log.Error("failed to encrypt service info: %v", err)
			return ackMsg, "", err
		}
		// 3. 生成JWT
		tokenString, err := CreateAccessJWT(encryptedInfo)
		if err != nil {
			log.Error("failed to generate JWT: %v", err)
			return ackMsg, "", err
		}
		query := redirectURL.Query()
		query.Set("access_token", string(tokenString))
		redirectURL.RawQuery = query.Encode()
		log.Info("ServiceInfo JSON------------------------------: %s", string(tokenString))
		return ackMsg, redirectURL.String(), nil
	}
}
