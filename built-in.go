package nhppluginssdk

import (
	"strings"

	nhplog "github.com/OpenNHP/opennhp/nhp/log"
)

func GetAuthUrl() string {
	if baseConf == nil {
		log.Error("baseConf is nil")
		return ""
	}
	authUrl := baseConf.AuthUrl
	if len(authUrl) == 0 {
		log.Error("AuthUrl is not provided.")
		return ""
	}
	if !strings.HasPrefix(authUrl, "http") {
		log.Error("AuthUrl is not a valid URL: %s", authUrl)
		return ""
	}
	return authUrl
}

func GetHostname() string {
	return hostname
}

func GetLocalIP() string {
	return localIp
}

func GetLocalMac() string {
	return localMac
}

func Log() *nhplog.Logger {
	return log
}
