package resource

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

var (
	name             = "auth_plugins_file_resource_handler"
	resConfigWatch   io.Closer
	resourceMapMutex sync.Mutex
	resourceMap      common.ResourceGroupMap
	errLoadConfig    = fmt.Errorf("config load error")
)

type FileResourceHandler struct{}

func (f *FileResourceHandler) Init(in *plugins.PluginParamsIn, conf *Config) error {
	baseConf = conf
	fileNameRes := filepath.Join(*in.PluginDirPath, "etc", "resource.toml")
	if err := updateResource(fileNameRes); err != nil {
		// ignore error
		_ = err
	}
	resConfigWatch = utils.WatchFile(fileNameRes, func() {
		log.Info("resource config: %s has been updated", fileNameRes)
		updateResource(fileNameRes)
	})
	return nil
}

func (a *FileResourceHandler) Update(conf *Config) error {
	baseConf = conf
	// Update logic for API resource handler
	return nil // Placeholder return
}

func (f *FileResourceHandler) FindResourceByID(resId string) (*common.ResourceData, error) {
	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	res, found := resourceMap[resId]
	if found {
		return res, nil
	}
	return nil, common.ErrResourceNotFound
}

func updateResource(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read resource config: %v", err)
	}

	resourceMapMutex.Lock()
	defer resourceMapMutex.Unlock()

	resourceMap = make(common.ResourceGroupMap)
	if err := toml.Unmarshal(content, &resourceMap); err != nil {
		log.Error("failed to unmarshal resource config: %v", err)
	}

	// res is pointer so we can update its fields
	for resId, res := range resourceMap {
		res.AuthServiceId = name
		res.ResourceId = resId
	}

	return err
}

func (f *FileResourceHandler) Close() error {
	if resConfigWatch != nil {
		resConfigWatch.Close()
	}
	return nil
}
