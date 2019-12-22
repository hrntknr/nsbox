package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
)

type ipAddressResp struct {
	Next    *string `json:"next"`
	Results []struct {
		Address     string `json:"address"`
		Description string `json:"description"`
		DNS         string `json:"dns_name"`
	} `json:"results"`
}

func newDNSTree() *dnsTree {
	return &dnsTree{
		Records: map[string][]dnsRecord{},
	}
}

type dnsTree struct {
	Records map[string][]dnsRecord `yaml:"records"`
}

func (tree *dnsTree) search(prefix string) *[]dnsRecord {
	result := tree.Records[prefix]
	return &result
}

func (tree *dnsTree) addRecords(name string, r dnsRecord) {
	_, ok := tree.Records[name]
	if !ok {
		tree.Records[name] = []dnsRecord{}
	}
	tree.Records[name] = append(tree.Records[name], r)
}

type dnsRecord struct {
	DNSType uint16 `yaml:"dnsType,omitempty"`
	A       net.IP `yaml:"a,omitempty"`
	AAAA    net.IP `yaml:"aaaa,omitempty"`
	CNAME   string `yaml:"cname,omitempty"`
	TXT     string `yaml:"txt,omitempty"`
}

var limit = 1000

func startNetboxSync(config *Config, zms *map[string]*zoneManager) error {
	interval, err := time.ParseDuration(config.Netbox.Interval)
	if err != nil {
		return err
	}
	go func() {
		for _, zm := range *zms {
			zm.initSerial()
		}
		ds := getDataStore(&config.DataStore, zms)
		if ds != nil {
			for suffix, zm := range *zms {
				zd, err := ds.getZone(zm.ZoneConfig.Suffix)
				if err == nil {
					zm.Tree = *zd.Tree
					zm.setSerial(zd.Serial)
				}
				(*zms)[suffix] = zm
			}
		}
		go syncNetbox(config, zms, ds)
		if config.Webhook.Listen != "" {
			go func() {
				ch, err := startListen(&config.Webhook)
				if err != nil {
					log.Print(err)
					return
				}
				for {
					<-ch
					go syncNetbox(config, zms, ds)
				}
			}()
		}
		go func() {
			for range time.Tick(interval) {
				go syncNetbox(config, zms, ds)
			}
		}()
		select {}
	}()
	return nil
}

func syncNetbox(config *Config, zms *map[string]*zoneManager, ds dataStore) {
	newTree := map[string]*dnsTree{}
	for _, zm := range *zms {
		_, ok := newTree[zm.ZoneConfig.Suffix]
		if !ok {
			newTree[zm.ZoneConfig.Suffix] = newDNSTree()
		}
		for name, record := range zm.ZoneConfig.Records {
			for _, r := range record {
				newTree[zm.ZoneConfig.Suffix].addRecords(name, r)
			}
		}
	}
	for i := 0; ; i++ {
		client := getClient(config)
		resp, err := client.R().SetQueryParams(map[string]string{
			"limit":  fmt.Sprint(limit),
			"offset": fmt.Sprint(limit * i),
		}).Get("/api/ipam/ip-addresses")
		if err != nil {
			log.Println(err)
		}
		ipAddressResp := ipAddressResp{}
		if err := json.Unmarshal(resp.Body(), &ipAddressResp); err != nil {
			log.Print(err)
			break
		}
		if resp.StatusCode() != 200 {
			log.Print(string(resp.Body()))
			log.Print(fmt.Errorf("invalid status code: %d", resp.StatusCode()))
			break
		}
		for _, result := range ipAddressResp.Results {
			var domain string
			switch config.Netbox.Mode {
			case "description":
				domain = dns.Fqdn(result.Description)
			case "dns":
				domain = dns.Fqdn(result.DNS)
			default:
				log.Print(fmt.Errorf("invalid mode"))
			}
			for _, zm := range *zms {
				if zm.includesBySuffix(domain) {
					_, ok := newTree[zm.ZoneConfig.Suffix]
					if !ok {
						continue
					}
					prefix, err := zm.getPrefixBySuffix(domain)
					if err != nil {
						continue
					}
					ip := net.ParseIP(strings.Split(result.Address, "/")[0])
					if ip.To4() != nil {
						newTree[zm.ZoneConfig.Suffix].addRecords(prefix, dnsRecord{
							DNSType: dns.TypeA,
							A:       ip,
						})
					} else {
						newTree[zm.ZoneConfig.Suffix].addRecords(prefix, dnsRecord{
							DNSType: dns.TypeAAAA,
							AAAA:    ip,
						})
					}
				}
			}
		}
		if ipAddressResp.Next == nil {
			log.Println("sync complete.")
			sortAllZone(&newTree)
			for zoneName, tree := range newTree {
				zm, ok := (*zms)[zoneName]
				if !ok {
					zm.Tree = *tree
					if ds != nil {
						if err := ds.setZone(zoneName, &zoneStoreData{
							Serial: zm.getSerial(),
							Tree:   tree,
						}); err != nil {
							log.Println(err)
						}
					}
					log.Printf("update zone: %s\n", zoneName)
					continue
				}
				if !compareZone(tree, &zm.Tree) {
					diff := ""
					if &zm.Tree != nil {
						diff = cmp.Diff(&zm.Tree.Records, tree.Records)
						fmt.Print(diff)
					}
					zm.updateSerial()
					zm.Tree = *tree
					if ds != nil {
						if err := ds.setZone(zoneName, &zoneStoreData{
							Serial: zm.getSerial(),
							Tree:   tree,
						}); err != nil {
							log.Println(err)
						}
					}
					err := notifySlack(&config.Slack, zoneName, zm.getSerial(), diff)
					if err != nil {
						fmt.Println(err)
					}
					log.Printf("update zone: %s serial: %d\n", zoneName, zm.getSerial())
				}
			}
			break
		}
		log.Println(*ipAddressResp.Next)
	}
}

func compareZone(zone1 *dnsTree, zone2 *dnsTree) bool {
	if zone1 == nil || zone2 == nil {
		return false
	}
	if len(zone1.Records) != len(zone2.Records) {
		return false
	}
	for name, records1 := range zone1.Records {
		records2, ok := zone2.Records[name]
		if !ok {
			return false
		}
		if len(records1) != len(records2) {
			return false
		}
		for i, record1 := range records1 {
			if record1.DNSType != records2[i].DNSType {
				return false
			}
			if record1.DNSType == dns.TypeA {
				if bytes.Compare(record1.A, records2[i].A) != 0 {
					return false
				}
			}
			if record1.DNSType == dns.TypeAAAA {
				if bytes.Compare(record1.AAAA, records2[i].AAAA) != 0 {
					return false
				}
			}
			if record1.DNSType == dns.TypeCNAME {
				if record1.CNAME != records2[i].CNAME {
					return false
				}
			}
			if record1.DNSType == dns.TypeTXT {
				if record1.TXT != records2[i].TXT {
					return false
				}
			}
		}
	}
	return true
}

func sortAllZone(zones *map[string]*dnsTree) {
	for _, zone := range *zones {
		for _, records := range zone.Records {
			sort.Slice(records, func(i, j int) bool {
				if records[i].DNSType == records[j].DNSType {
					switch records[i].DNSType {
					case dns.TypeA:
						return bytes.Compare(records[i].A, records[j].A) < 0
					case dns.TypeAAAA:
						return bytes.Compare(records[i].AAAA, records[j].AAAA) < 0
					case dns.TypeTXT:
						return records[i].TXT < records[j].TXT
					case dns.TypeCNAME:
						// invalid
						return true
					}
				}
				return records[i].DNSType < records[j].DNSType
			})
		}
	}
}

func getClient(config *Config) *resty.Client {
	client := resty.New()
	var serverName string
	if config.Netbox.ServerName != nil {
		serverName = *config.Netbox.ServerName
	} else {
		serverName = config.Netbox.Host
	}
	if config.Netbox.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !config.Netbox.VerifyTLS,
			ServerName:         serverName,
		}
		client.SetHostURL("https://" + serverName)
		client.SetTransport(&http.Transport{
			DialContext:     newDialer(config.Netbox.Host),
			TLSClientConfig: tlsConfig,
		})
	} else {
		client.SetTransport(&http.Transport{
			DialContext: newDialer(config.Netbox.Host),
		})
		client.SetHostURL("http://" + serverName)
	}
	client.SetHeader("Authorization", fmt.Sprintf("Token %s", config.Netbox.Token))
	return client
}

func newDialer(host string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}
		addr = host + addr[strings.LastIndex(addr, ":"):]
		return dialer.DialContext(ctx, network, addr)
	}
}
