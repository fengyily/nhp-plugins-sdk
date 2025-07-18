package nhppluginssdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func EncryptWithGCM(plaintext []byte) (string, error) {
	block, err := aes.NewCipher([]byte(baseConf.AesKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func DecryptGCM(ciphertext string) ([]byte, error) {
	// 解码Base64字符串
	decoded, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	// 创建AES加密块
	block, err := aes.NewCipher([]byte(baseConf.AesKey))
	if err != nil {
		return nil, err
	}

	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 检查密文长度
	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return nil, errors.New("密文太短")
	}

	// 分离Nonce和实际密文
	nonce := decoded[:nonceSize]
	ciphertextBytes := decoded[nonceSize:]

	// 解密数据
	return gcm.Open(nil, nonce, ciphertextBytes, nil)
}
