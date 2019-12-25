package main

// Config for Application
type Config struct {
	Server      serverConfig       `yaml:"server"`
	Webhook     webhookConfig      `yaml:"webhook"`
	DataStore   dataStoreConfig    `yaml:"dataStore"`
	ZoneDefault zoneDefaultConfig  `yaml:"zoneDefault"`
	Zones       []zoneConfig       `yaml:"zones"`
	TsigSecrets []tsigSecretConfig `yaml:"tsigSecrets"`
	Netbox      netboxConfig       `yaml:"netbox"`
	Slack       slackConfig        `yaml:"slack"`
}

type dataStoreConfig struct {
	Mode string `yaml:"mode"`
	Path string `yaml:"path"`
}

type webhookConfig struct {
	Listen    string   `yaml:"listen"`
	Timeout   string   `yaml:"timeout"`
	AllowFrom []string `yaml:"allowFrom"`
}

type serverConfig struct {
	CPUProfile  *string  `yaml:"cpuProfile"`
	CPU         *int     `yaml:"cpu"`
	SoReuseport *uint32  `yaml:"soReuseport"`
	Listen      []string `yaml:"listen"`
}

type zoneConfig struct {
	Suffix        string                   `yaml:"suffix"`
	Origin        *string                  `yaml:"origin"`
	SOA           soaConfig                `yaml:"soa"`
	TTL           *uint32                  `yaml:"ttl"`
	NS            *[]string                `yaml:"ns"`
	Records       *[]addtionalRecordConfig `yaml:"records"`
	AllowTransfer *[]string                `yaml:"allowTransfer"`
}

type addtionalRecordConfig struct {
	Name  string  `yaml:"name"`
	CNAME *string `yaml:"cname"`
	TXT   *string `yaml:"txt"`
}

type tsigSecretConfig struct {
	Name   string `yaml:"name"`
	Secret string `yaml:"secret"`
}

type zoneDefaultConfig struct {
	SOA           soaConfig `yaml:"soa"`
	TTL           *uint32   `yaml:"ttl"`
	NS            *[]string `yaml:"ns"`
	AllowTransfer *[]string `yaml:"allowTransfer"`
}

type soaConfig struct {
	NS      *string `yaml:"ns"`
	MBox    *string `yaml:"mBox"`
	Refresh *uint32 `yaml:"refresh"`
	Retry   *uint32 `yaml:"retry"`
	Expire  *uint32 `yaml:"expire"`
	MinTTL  *uint32 `yaml:"minTTL"`
}

type netboxConfig struct {
	Host       string  `yaml:"host"`
	ServerName *string `yaml:"serverName"`
	UseTLS     bool    `yaml:"useTLS"`
	VerifyTLS  bool    `yaml:"verifyTLS"`
	Token      string  `yaml:"token"`
	Mode       string  `yaml:"mode"`
	Interval   string  `yaml:"interval"`
}

type soa struct {
	NS      string `yaml:"ns"`
	MBox    string `yaml:"mBox"`
	Refresh uint32 `yaml:"refresh"`
	Retry   uint32 `yaml:"retry"`
	Expire  uint32 `yaml:"expire"`
	MinTTL  uint32 `yaml:"minTTL"`
}

type slackConfig struct {
	WebhookURL string `yaml:"webhookURL"`
	Channel    string `yaml:"channel"`
	Name       string `yaml:"name"`
	IconURL    string `yaml:"iconURL"`
	IcomEmoji  string `yaml:"iconEmoji"`
}
