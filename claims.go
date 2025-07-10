package nhppluginssdk

import (
	"fmt"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type TokenType string

const (
	TokenTypeNHPToken        TokenType = "nhp_token"
	TokenTypeNHPRefreshToken TokenType = "nhp_refresh_token"
)

type PasscodeClaims struct {
	SessionID  string    `json:"session_id"`
	ResourceID string    `json:"resource_id"`
	TokenType  TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

type RefreshResponse struct {
	RedirectUrl     string            `json:"redirectUrl,omitempty"`
	ResourceHost    map[string]string `json:"resourceHost,omitempty"`
	NHPToken        string            `json:"nhpToken,omitempty"`
	NHPRefreshToken string            `json:"nhpRefreshToken,omitempty"`
	ErrCode         string            `json:"errCode"`
	ErrMsg          string            `json:"errMsg,omitempty"`
	CookieDomain    string            `json:"cookieDomain"`
}

type JWTToken struct {
	jwtKey []byte
}

func (jwttoken *JWTToken) GenerateAll(ac string, res *common.ResourceData) (string, string, error) {
	// 设置token过期时间
	openTime := time.Now().Add(time.Duration(res.OpenTime) * time.Second)
	expirationTime := time.Now().Add(time.Duration(res.ExInfo["TokenExpire"].(int64)) * time.Second)

	// 创建Claims
	claims := &PasscodeClaims{
		SessionID:  uuid.New().String(),
		ResourceID: res.ResourceId,
		TokenType:  TokenTypeNHPToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(openTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "opennhp",
		},
	}

	// 使用HS256算法创建token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 生成完整的已签名token
	tokenString, err := token.SignedString(jwttoken.jwtKey)
	if err != nil {
		return "", "", err
	}

	// 生成refresh token
	refreshClaims := &RefreshTokenJWT{
		SessionID: claims.SessionID,
		TokenType: TokenTypeNHPRefreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "opennhp",
		},
	}
	// 使用HS256算法创建refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	// 生成完整的已签名refresh token
	refreshTokenString, err := refreshToken.SignedString(jwttoken.jwtKey)
	if err != nil {
		return "", "", err
	}
	// 返回token和refresh token
	return tokenString, refreshTokenString, nil

}

func (jwttoken *JWTToken) ExchangeNHPToken(nhpToken string, nhpRefreshToken string, res *common.ResourceData) (string, error) {
	openTime := time.Now().Add(time.Duration(res.OpenTime) * time.Second)
	isOk, err := jwttoken.Validate(nhpRefreshToken, TokenTypeNHPRefreshToken)
	if err != nil {
		return "", err
	}
	if !isOk {
		return "", fmt.Errorf("refresh token is invalid")
	}

	// 创建Claims
	claims := &PasscodeClaims{
		SessionID:  uuid.New().String(),
		ResourceID: res.ResourceId,
		TokenType:  TokenTypeNHPToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(openTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "opennhp",
		},
	}

	// 使用HS256算法创建token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 生成完整的已签名token
	tokenString, err := token.SignedString(jwttoken.jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (jwttoken *JWTToken) Validate(tokenString string, tokenType TokenType) (bool, error) {
	// 解析token
	token, err := jwt.ParseWithClaims(tokenString, &PasscodeClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法是否正确
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwttoken.jwtKey, nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(*PasscodeClaims); ok && token.Valid {
		if claims.TokenType != tokenType {
			return false, fmt.Errorf("invalid token type[%s]", claims.TokenType)
		}
		return true, nil
	}

	return false, fmt.Errorf("invalid token")
}

func ParseJWTToken(tokenString string) (*PasscodeClaims, error) {
	type MyCustomClaims struct {
		ResId string `json:"resource_id"`
		jwt.StandardClaims
	}

	claims := &MyCustomClaims{}
	parser := new(jwt.Parser)
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		err = fmt.Errorf("failed to parse token unverified: %v", err)
		return nil, err
	}

	resourceID := claims.ResId
	return &PasscodeClaims{
		ResourceID: resourceID,
	}, nil
}
