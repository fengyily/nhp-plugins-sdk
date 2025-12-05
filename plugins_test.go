package nhppluginssdk

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/fengyily/nhp-plugins-sdk/models"
)

func TestStructToMap(t *testing.T) {
	sub := map[string]any{
		"Sub": []models.Resource{
			{
				IP:            "aaa",
				Port:          8080,
				Scheme:        "http",
				MapPort:       80,
				ConnectorPort: 9090,
			},
		},
	}
	res := common.ResourceData{
		ExInfo: sub,
	}
	subRaw := res.ExInfo["Sub"]
	var subServices []models.Resource

	if subArray, ok := subRaw.([]models.Resource); ok {
		log.Warning("subArray is of type []interface{} with length %d", len(subArray))
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
}
