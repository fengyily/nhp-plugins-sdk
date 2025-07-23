package resource

import (
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type ResourceType int

const (
	ResourceTypeFile ResourceType = iota
	ResourceTypeAPI
)

type ResourceHandler interface {
	Init(in plugins.PluginParamsIn, baseConf Config) error
	Update(baseConf Config) error
	FindResourceByID(id string) (*common.ResourceData, error)
	Close() error
	GetConfig() Config
}

func NewResource(resourceType ResourceType) ResourceHandler {
	switch resourceType {
	case ResourceTypeFile:
		return &FileResourceHandler{}
	case ResourceTypeAPI:
		return &APIResourceHandler{}
	default:
		return &APIResourceHandler{}
	}
}
