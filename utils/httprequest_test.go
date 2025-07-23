package utils

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/fengyily/nhp-plugins-sdk/models"
)

func TestHttpRequest(t *testing.T) {
	options := RequestOptions{
		Method:   "GET",
		BaseURL:  "http://localhost:8888",
		Endpoint: "ps/FindSiteByApplicationId",
		QueryParams: map[string]string{
			"app_id": "aaaaa",
		},
	}

	resp, err := SendRequest(options)
	if err != nil {
		log.Error("Request failed: %v", err)
		return
	}

	// 处理响应...
	if err != nil {
		log.Error("Request failed: %v", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Error("API request failed with status code %d: %s", resp.StatusCode, string(resp.Body))
		return
	}

	var result models.FullResponse
	if err := ParseJSONResponse(resp, &result); err != nil {
		log.Error("Error parsing response: %v", err)
		return
	}

	s, _ := json.Marshal(result)
	log.Info("%s", s)
}
