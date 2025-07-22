package resource

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/fengyily/nhp-plugins-sdk/utils"
)

type APIResourceHandler struct{}

func (a *APIResourceHandler) Init(in *plugins.PluginParamsIn, conf *Config) error {
	baseConf = conf
	// Initialization logic for API resource handler
	return nil // Placeholder return
}

func (a *APIResourceHandler) FindResourceByID(resId string) (*common.ResourceData, error) {
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
		log.Info("FindResourceApi res: %v", res)
		return res, nil
	}
	err = fmt.Errorf("FindResourceApi failed: not found resource with id %s", resId)
	return nil, err
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
	httpReq.Header.Set("User-Agent", "OpenNHP-Plugins-SDK")
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
		AppKey:             utils.GetStringFromMap(resRsp.ExtInfo, "LoginAppKey"),
		AppSecret:          utils.GetStringFromMap(resRsp.ExtInfo, "LoginAppSecret"),
		AccessKey:          "",
		SecretKey:          "",
		ExInfo:             make(map[string]any),
		RedirectUrl:        resRsp.SiteURL,
		RedirectWithParams: false,
		SkipAuth:           resRsp.SkipAuth,
		CookieDomain:       resRsp.CookieDomain,
	}

	resourceGroup.ExInfo = resRsp.ExtInfo

	resourceGroup.ExInfo["JWTSecret"] = resRsp.JwtSecret
	resourceGroup.ExInfo["Title"] = resRsp.SiteName
	resourceGroup.ExInfo["TokenExpire"] = resRsp.TokenExpire
	resourceGroup.ExInfo["Ip"] = resRsp.ServiceInfo.IP
	resourceGroup.ExInfo["Port"] = resRsp.ServiceInfo.Port
	resourceGroup.ExInfo["Scheme"] = resRsp.ServiceInfo.Scheme

	if utils.GetStringFromMap(resRsp.ExtInfo, "RedirectWithParams") == "true" {
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

func (a *APIResourceHandler) Close() error {

	return nil
}
