package resource

import (
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

var baseConf *Config

type ResourceType int

const (
	ResourceTypeFile ResourceType = iota
	ResourceTypeAPI
)

type ResourceHandler interface {
	Init(in *plugins.PluginParamsIn, baseConf *Config) error
	FindResourceByID(id string) (*common.ResourceData, error)
	Close() error
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
