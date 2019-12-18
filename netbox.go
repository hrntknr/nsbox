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
	"github.com/miekg/dns"
)

type IPAddressResp struct {
	Next    *string `json:"next"`
	Results []struct {
		Address     string `json:"address"`
		Description string `json:"description"`
		DNS         string `json:"dns_name"`
	} `json:"results"`
}

type DNSTree struct {
	Records map[string][]DNSRecord `yaml:"records"`
}

func (tree *DNSTree) search(fqdn string, origin string) *[]DNSRecord {
	tree, ok := resolveDomain[origin]
	if !ok {
		return nil
	}
	prefix, err := getPrefix(fqdn, origin)
	if err != nil {
		return nil
	}
	result := resolveDomain[origin].Records[prefix]
	return &result
}

type DNSRecord struct {
	DNSType uint16 `yaml:"dnsType,omitempty"`
	A       net.IP `yaml:"a,omitempty"`
	AAAA    net.IP `yaml:"aaaa,omitempty"`
	CNAME   string `yaml:"cname,omitempty"`
	TXT     string `yaml:"txt,omitempty"`
}

var resolveDomain map[string]*DNSTree = map[string]*DNSTree{}

var limit = 1000

func startNetboxSync(config *Config, zones *[]Zone) error {
	interval, err := time.ParseDuration(config.Netbox.Interval)
	if err != nil {
		return err
	}
	go func() {
		initSerial(zones)
		ds := getDataStore(&config.DataStore, zones)
		if ds != nil {
			for _, z := range *zones {
				zd, err := ds.getZone(z.Suffix)
				if err == nil {
					setSerial(z.Suffix, zd.Serial)
					resolveDomain[z.Suffix] = zd.Tree
				}
			}
		}
		syncNetbox(config, zones, ds)
		for range time.Tick(interval) {
			syncNetbox(config, zones, ds)
		}
	}()
	return nil
}

func injectConfigRecord(tree map[string]*DNSTree, zones *[]Zone) {
	for _, zone := range *zones {
		_, ok := tree[zone.Origin]
		if !ok {
			tree[zone.Origin] = &DNSTree{
				Records: map[string][]DNSRecord{},
			}
		}
		for name, record := range zone.Records {
			for _, r := range record {
				tree[zone.Origin].Records[name] = append(tree[zone.Origin].Records[name], r)
			}
		}
	}
}

func syncNetbox(config *Config, zones *[]Zone, ds dataStore) {
	newResolveDomain := map[string]*DNSTree{}
	injectConfigRecord(newResolveDomain, zones)
	for i := 0; ; i++ {
		client := getClient(config)
		resp, err := client.R().SetQueryParams(map[string]string{
			"limit":  fmt.Sprint(limit),
			"offset": fmt.Sprint(limit * i),
		}).Get("/api/ipam/ip-addresses")
		if err != nil {
			log.Println(err)
		}
		ipAddressResp := IPAddressResp{}
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
			filterdOrigins := []string{}
			for _, zone := range *zones {
				if strings.HasSuffix(domain, zone.Origin) {
					filterdOrigins = append(filterdOrigins, zone.Origin)
				}
			}
			if len(filterdOrigins) == 0 {
				continue
			}
			origin := filterdOrigins[0]
			_, ok := newResolveDomain[origin]
			if !ok {
				continue
			}
			prefix, err := getPrefix(domain, origin)
			if err != nil {
				continue
			}
			_, ok = newResolveDomain[origin].Records[prefix]
			if !ok {
				newResolveDomain[origin].Records[prefix] = []DNSRecord{}
			}
			ip := net.ParseIP(strings.Split(result.Address, "/")[0])
			if ip.To4() != nil {
				newResolveDomain[origin].Records[prefix] = append(newResolveDomain[origin].Records[prefix], DNSRecord{
					DNSType: dns.TypeA,
					A:       ip,
				})
			} else {
				newResolveDomain[origin].Records[prefix] = append(newResolveDomain[origin].Records[prefix], DNSRecord{
					DNSType: dns.TypeAAAA,
					AAAA:    ip,
				})
			}
		}
		if ipAddressResp.Next == nil {
			log.Println("sync complete.")
			sortAllZone(&newResolveDomain)
			updateFlag := false
			for zoneName, zone1 := range newResolveDomain {
				zone2, ok := resolveDomain[zoneName]
				if !ok {
					updateFlag = true
					log.Printf("update zone: %s\n", zoneName)
					if ds != nil {
						if err := ds.setZone(zoneName, &zoneStoreData{
							Serial: getSerial(zoneName),
							Tree:   zone1,
						}); err != nil {
							log.Println(err)
						}
					}
					continue
				}
				if !compareZone(zone1, zone2) {
					updateFlag = true
					log.Printf("update zone: %s\n", zoneName)
					updateSerial(zoneName)
					if ds != nil {
						if err := ds.setZone(zoneName, &zoneStoreData{
							Serial: getSerial(zoneName),
							Tree:   zone1,
						}); err != nil {
							log.Println(err)
						}
					}
				}
			}
			if updateFlag {
				resolveDomain = newResolveDomain
			}
			break
		}
		log.Println(*ipAddressResp.Next)
	}
}

func compareZone(zone1 *DNSTree, zone2 *DNSTree) bool {
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

func sortAllZone(zones *map[string]*DNSTree) {
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

func getPrefix(fqdn string, origin string) (prefix string, err error) {
	if !strings.HasSuffix(fqdn, "."+origin) {
		return "", fmt.Errorf("invalid origin")
	}
	return fqdn[:len(fqdn)-len(origin)-1], nil
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
