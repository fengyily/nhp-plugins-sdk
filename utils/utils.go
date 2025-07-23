package utils

import (
	"math/rand"
	"strconv"
	"time"

	"github.com/fengyily/nhp-plugins-sdk/models"
	"github.com/golang-jwt/jwt/v4"
)

func GetStringFromMap(m map[string]any, key string) string {
	if value, ok := m[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}

func GetIntFromMap(m map[string]any, key string) int {
	if value, ok := m[key]; ok {
		if intValue, ok := value.(int); ok {
			return intValue
		} else if intValue, ok := value.(int64); ok {
			return int(intValue)
		} else if intValue, ok := value.(float64); ok {
			return int(intValue)
		} else if floatValue, ok := value.(float32); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(int32); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(int16); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(int8); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(uint); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(uint64); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(uint32); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(uint16); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(uint8); ok {
			return int(floatValue)
		} else if floatValue, ok := value.(bool); ok {
			if floatValue {
				return 1 // Convert true to 1
			}
			return 0 // Convert false to 0
		} else if strValue, ok := value.(string); ok {
			if intValue, err := strconv.Atoi(strValue); err == nil {
				return intValue
			}
		}
	}
	return 0
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

func CreateAccessJWT(encryptedData string, signingKey string) (string, error) {
	claims := models.JWTClaims{
		EncryptedData: encryptedData, // 存储AES-GCM加密后的数据
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(120) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "opennhp", // 发行者标识
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(signingKey))
}
