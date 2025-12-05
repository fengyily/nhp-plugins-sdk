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
	"runtime/debug"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	nhplog "github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/fengyily/nhp-plugins-sdk/models"
	"github.com/fengyily/nhp-plugins-sdk/resource"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"

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
)

type HanderUpdateFunc func(handler resource.ResourceHandler) error

var (
	errLoadConfig = fmt.Errorf("config load error")
)

func Version() string {
	return fmt.Sprintf("%s v%s", name, version)
}

func Init(in *plugins.PluginParamsIn, hander HanderUpdateFunc) (err error) {
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
	if err := updateConfig(fileNameBase, in, hander); err != nil {
		// ignore error
		_ = err
	}

	baseConfigWatch = utils.WatchFile(fileNameBase, func() {
		log.Info("base config: %s has been updated", fileNameBase)
		updateConfig(fileNameBase, in, hander)
	})

	rand.Seed(time.Now().UnixNano())
	return nil
}

func updateConfig(file string, in *plugins.PluginParamsIn, hander HanderUpdateFunc) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("🔥 PANIC in updateConfig: %v", r)
			debug.PrintStack()
			err = fmt.Errorf("panic in updateConfig: %v", r)
		}
	}()

	// 1. 检查文件是否存在
	if _, err := os.Stat(file); os.IsNotExist(err) {
		log.Error("Config file does not exist: %s", file)
		return fmt.Errorf("config file not found: %s", file)
	}

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read base config: %v", err)
		return fmt.Errorf("read config failed: %w", err)
	}

	var conf resource.Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal base config: %v", err)
	}
	var resourceHander resource.ResourceHandler
	switch conf.ResourceMode {
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
	if hander != nil {
		resourceHander.Init(*in, conf)
		if err := hander(resourceHander); err != nil {
			log.Error("Failed to update resource handler: %v", err)
			return fmt.Errorf("failed to update resource handler: %w", err)
		}
	}

	return err
}

func Close() error {
	if baseConfigWatch != nil {
		baseConfigWatch.Close()
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

	c.SetSameSite(http.SameSiteNoneMode)
	origin := c.GetHeader("Origin")
	if len(origin) == 0 {
		host := c.Request.Host
		origin = "https://" + host
	}
	c.Header("Access-Control-Allow-Origin", origin)
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

// GetUserFromAuthHeader 从 Authorization header 中解析用户信息
// 支持 Bearer token 格式，尝试从 JWT 中提取用户名
// 如果无法解析或 header 为空，返回 "anonymous"
func GetUserFromAuthHeader(authHeader string) string {
	if len(authHeader) == 0 {
		return "anonymous"
	}

	// 移除 "Bearer " 前缀
	tokenString := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenString = authHeader[7:]
	}

	// 尝试解析 JWT 获取用户信息（不验证签名，只解析 payload）
	user, err := parseUserFromJWT(tokenString)
	if err != nil {
		log.Warning("failed to parse auth token for user: %v", err)
		return "anonymous"
	}

	if len(user) > 0 {
		return user
	}

	return "anonymous"
}

// parseUserFromJWT 从 JWT 中解析用户信息，使用通用的 claims 结构
func parseUserFromJWT(tokenString string) (string, error) {
	// 使用 MapClaims 来解析任意结构的 JWT
	claims := jwt.MapClaims{}
	parser := new(jwt.Parser)
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return "", fmt.Errorf("failed to parse token unverified: %v", err)
	}

	// 按优先级返回用户标识，检查各种常见的字段名
	fieldPriority := []string{"sub", "user_id", "userId", "username", "name", "email", "preferred_username"}
	for _, field := range fieldPriority {
		if val, ok := claims[field]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal, nil
			}
		}
	}

	return "", nil
}

func GetRedirectUrlByResource(ackMsg *common.ServerKnockAckMsg, res *common.ResourceData, conf resource.Config, action string, user string) (*common.ServerKnockAckMsg, string, error) {
	if len(res.RedirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
		return ackMsg, "", nil
	} else {
		redirectURL, err := url.Parse(res.RedirectUrl)
		if err != nil {
			log.Error("failed to parse redirect url: %v", err)
			return ackMsg, "", err
		} else {

			defaultRes := nhpsdkutils.Loadbalancing(ackMsg.ResourceHost)
			if len(defaultRes) > 0 {
				redirectURL.Host = defaultRes
			} else {
				log.Error("no resource host available for redirect")
				return ackMsg, "", err
			}
			log.Info("All host [%+v] , load balancing redirectURL: %s", ackMsg.ResourceHost, redirectURL.String())
		}

		mainIP := nhpsdkutils.GetStringFromMap(res.ExInfo, "Ip")
		mainPort := nhpsdkutils.GetIntFromMap(res.ExInfo, "Port")
		mainScheme := nhpsdkutils.GetStringFromMap(res.ExInfo, "Scheme")
		mainMapPort := nhpsdkutils.GetIntFromMap(res.ExInfo, "MapPort")
		mainConport := nhpsdkutils.GetIntFromMap(res.ExInfo, "ConPort")
		subRaw := res.ExInfo["Sub"]
		var subServices []models.Resource

		if subArray, ok := subRaw.([]models.Resource); ok {
			log.Warning("subArray is of type []models.Resource{} with length %d", len(subArray))
			for _, item := range subArray {
				subSvc := models.Resource{
					IP:            item.IP,
					Port:          item.Port,
					Scheme:        item.Scheme,
					MapPort:       item.MapPort,
					ConnectorPort: item.ConnectorPort,
				}
				subServices = append(subServices, subSvc)

			}
		} else {
			log.Warning("sub is not an array or missing, skipping sub services")
		}

		// 如果 user 为空，设置为 anonymous
		if len(user) == 0 {
			user = "anonymous"
		}

		serviceInfo := models.ServiceInfo{
			AppId:  res.ResourceId,
			Action: action,
			User:   user,
			Resource: models.Resource{
				IP:            mainIP,
				Port:          mainPort,
				Scheme:        mainScheme,
				MapPort:       mainMapPort,
				ConnectorPort: mainConport,
			},
			Sub: subServices,
		}

		// 1. 序列化ServiceInfo为JSON
		infoJSON, err := json.Marshal(serviceInfo)
		if err != nil {
			log.Error("failed to marshal service info: %v", err)
			// return ackMsg, nil
		}
		// 2. AES-GCM加密
		encryptedInfo, err := nhpsdkutils.EncryptWithGCM(infoJSON, conf.AesKey)
		if err != nil {
			log.Error("failed to encrypt service info: %v", err)
			return ackMsg, "", err
		}
		// 3. 生成JWT
		tokenString, err := nhpsdkutils.CreateAccessJWT(encryptedInfo, conf.AesKey)
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
