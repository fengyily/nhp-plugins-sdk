package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type RequestOptions struct {
	Method      string            // "GET" or "POST"
	BaseURL     string            // 基础URL
	Endpoint    string            // 端点路径
	QueryParams map[string]string // URL查询参数
	Headers     map[string]string // 请求头
	Body        interface{}       // POST请求的body内容
}

type Response struct {
	StatusCode int         // HTTP状态码
	Body       []byte      // 响应体
	Data       interface{} // 解析后的数据(如果适用)
}

// SendRequest 发送HTTP请求的通用方法
func SendRequest(options RequestOptions) (*Response, error) {
	// 验证基础URL
	if len(options.BaseURL) == 0 {
		return nil, fmt.Errorf("base URL is not provided")
	}
	if !strings.HasPrefix(options.BaseURL, "http") {
		return nil, fmt.Errorf("base URL is not a valid URL: %s", options.BaseURL)
	}

	// 解析基础URL
	baseUrl, err := url.Parse(options.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	// 构建完整URL
	reqUrl := baseUrl.String()
	if !strings.HasSuffix(reqUrl, "/") {
		reqUrl += "/"
	}
	reqUrl += options.Endpoint

	// 添加查询参数
	if len(options.QueryParams) > 0 {
		query := url.Values{}
		for k, v := range options.QueryParams {
			query.Add(k, v)
		}
		reqUrl += "?" + query.Encode()
	}

	// 准备请求体
	var body io.Reader
	if options.Method == "POST" && options.Body != nil {
		jsonBody, err := json.Marshal(options.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		body = bytes.NewBuffer(jsonBody)
	}

	// 创建请求
	req, err := http.NewRequest(options.Method, reqUrl, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// 设置默认请求头
	req.Header.Set("User-Agent", "OpenNHP-Plugins-SDK")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	// 添加自定义请求头
	for k, v := range options.Headers {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       respBody,
	}, nil
}

// ParseJSONResponse 解析JSON响应到指定结构体
func ParseJSONResponse(resp *Response, target interface{}) error {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}
	if len(resp.Body) == 0 {
		return fmt.Errorf("response body is empty")
	}
	return json.Unmarshal(resp.Body, target)
}
