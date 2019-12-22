package main

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

func getDataStore(dConfig *dataStoreConfig, zms *map[string]*zoneManager) dataStore {
	switch dConfig.Mode {
	case "yaml":
		return newYamlDataStore(dConfig.Path, zms)
	}
	return nil
}

type dataStore interface {
	setZone(zoneName string, data *zoneStoreData) error
	getZone(zoneName string) (*zoneStoreData, error)
	save() error
	load() error
}

type storeData struct {
	Zones map[string]zoneStoreData `yaml:"zones"`
}

type zoneStoreData struct {
	Serial uint32   `yaml:"serial"`
	Origin string   `yaml:"origin"`
	Tree   *dnsTree `yaml:"tree"`
}

func newYamlDataStore(path string, zms *map[string]*zoneManager) dataStore {
	yd := &yamlDataStore{
		path: path,
	}
	err := yd.load()
	if err != nil {
		zoneData := map[string]zoneStoreData{}
		for _, zm := range *zms {
			zoneData[zm.ZoneConfig.Suffix] = zoneStoreData{}
		}
		yd.data = &storeData{
			Zones: zoneData,
		}
	}
	return yd
}

type yamlDataStore struct {
	path string
	data *storeData
}

func (yd *yamlDataStore) setZone(zoneName string, data *zoneStoreData) error {
	_, ok := yd.data.Zones[zoneName]
	if ok {
		yd.data.Zones[zoneName] = *data
		return yd.save()
	}
	return fmt.Errorf("not found")
}
func (yd *yamlDataStore) getZone(zoneName string) (*zoneStoreData, error) {
	zoneData, ok := yd.data.Zones[zoneName]
	if ok {
		return &zoneData, nil
	}
	return nil, fmt.Errorf("not found")
}

func (yd *yamlDataStore) save() error {
	y, err := yaml.Marshal(yd.data)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(yd.path, y, 0644); err != nil {
		return err
	}
	return nil
}

func (yd *yamlDataStore) load() error {
	data := &storeData{}
	buf, err := ioutil.ReadFile(yd.path)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(buf, data); err != nil {
		return err
	}
	yd.data = data
	return nil
}
