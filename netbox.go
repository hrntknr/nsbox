package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
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
	Records map[string][]DNSRecord
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
	DNSType uint16
	A       net.IP
	AAAA    net.IP
	CNAME   string
}

var resolveDomain map[string]*DNSTree = map[string]*DNSTree{}

var limit = 1000

func startNetboxSync(config *Config, zones *[]Zone) error {
	interval, err := time.ParseDuration(config.Netbox.Interval)
	if err != nil {
		return err
	}
	go func() {
		syncNetbox(config, zones)
		for range time.Tick(interval) {
			syncNetbox(config, zones)
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

func syncNetbox(config *Config, zones *[]Zone) {
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
			resolveDomain = newResolveDomain
			fmt.Println("sync complete.")
			break
		}
		fmt.Println(*ipAddressResp.Next)
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
