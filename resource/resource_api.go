package resource

import (
	"fmt"
	"net/http"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/fengyily/nhp-plugins-sdk/models"
	"github.com/fengyily/nhp-plugins-sdk/utils"
)

type APIResourceHandler struct {
	baseConf Config
}

func (a *APIResourceHandler) Init(in plugins.PluginParamsIn, conf Config) error {
	a.baseConf = conf
	// Initialization logic for API resource handler
	return nil // Placeholder return
}

func (a *APIResourceHandler) Update(conf Config) error {
	a.baseConf = conf
	// Update logic for API resource handler
	return nil // Placeholder return
}

func (a *APIResourceHandler) FindResourceByID(resId string) (*common.ResourceData, error) {
	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	response, statusCode, err := a.findResourceFromUrl(resId)
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

func (a *APIResourceHandler) findResourceFromUrl(resId string) (*models.ReResponse, string, error) {
	var err error
	AuthUrl := a.baseConf.AuthUrl
	if len(AuthUrl) == 0 {
		log.Error("AuthUrl is not provided.")
		return nil, "401", fmt.Errorf("AuthUrl is not provided")
	}

	resp, err := utils.SendRequest(utils.RequestOptions{
		Method:   "GET",
		BaseURL:  AuthUrl,
		Endpoint: "ps/FindSiteByApplicationId",
		QueryParams: map[string]string{
			"app_id": resId,
		},
	})
	if err != nil {
		log.Error("Request failed: %v", err)
		return nil, "402", fmt.Errorf("request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Error("API request failed with status code %d: %s", resp.StatusCode, string(resp.Body))
		return nil, "403", fmt.Errorf("api request failed with status code %d: %s", resp.StatusCode, string(resp.Body))
	}

	var apiResponse models.FullResponse
	if err := utils.ParseJSONResponse(resp, &apiResponse); err != nil {
		log.Error("Error parsing response: %v", err)
		return nil, "403", fmt.Errorf("error parsing response: %v", err)
	}
	if apiResponse.Code != 0 {
		log.Error("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
		return nil, fmt.Sprintf("50%d", apiResponse.Code), fmt.Errorf("api request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
	}

	return &apiResponse.Data, "", nil
}

func mapResourceRsp(resRsp *models.ReResponse) (common.ResourceGroupMap, error) {
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

func (a *APIResourceHandler) GetConfig() Config {
	return a.baseConf
}
