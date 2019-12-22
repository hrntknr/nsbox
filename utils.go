package main

import (
	"fmt"
	"math/rand"

	"github.com/miekg/dns"
)

func zoneMerge(zoneConfig *zoneConfig, zoneDefaultConfig *zoneDefaultConfig) (*zone, error) {
	var fqdn string = dns.Fqdn(zoneConfig.Suffix)
	var origin string
	var soaNS, mBox string
	var ttl, refresh, retry, expire, minTTL uint32
	var ns []string = []string{}
	if zoneConfig.Origin != nil {
		origin = dns.Fqdn(*zoneConfig.Origin)
	} else {
		origin = dns.Fqdn(zoneConfig.Suffix)
	}
	if zoneConfig.TTL != nil {
		ttl = *zoneConfig.TTL
	} else if zoneDefaultConfig.TTL != nil {
		ttl = *zoneDefaultConfig.TTL
	} else {
		return nil, fmt.Errorf("ttl not found")
	}
	if zoneConfig.NS != nil {
		for _, server := range *zoneConfig.NS {
			ns = append(ns, dns.Fqdn(server))
		}
	} else if zoneDefaultConfig.NS != nil {
		for _, server := range *zoneDefaultConfig.NS {
			ns = append(ns, dns.Fqdn(server))
		}
	} else {
		return nil, fmt.Errorf("ns not found")
	}
	if zoneConfig.SOA.NS != nil {
		soaNS = *zoneConfig.SOA.NS
	} else if zoneDefaultConfig.SOA.NS != nil {
		soaNS = *zoneDefaultConfig.SOA.NS
	} else {
		return nil, fmt.Errorf("soa.ns not found")
	}
	if zoneConfig.SOA.MBox != nil {
		mBox = *zoneConfig.SOA.MBox
	} else if zoneDefaultConfig.SOA.MBox != nil {
		mBox = *zoneDefaultConfig.SOA.MBox
	} else {
		return nil, fmt.Errorf("soa.mBox not found")
	}
	if zoneConfig.SOA.Refresh != nil {
		refresh = *zoneConfig.SOA.Refresh
	} else if zoneDefaultConfig.SOA.Refresh != nil {
		refresh = *zoneDefaultConfig.SOA.Refresh
	} else {
		return nil, fmt.Errorf("soa.refresh not found")
	}
	if zoneConfig.SOA.Retry != nil {
		retry = *zoneConfig.SOA.Retry
	} else if zoneDefaultConfig.SOA.Retry != nil {
		retry = *zoneDefaultConfig.SOA.Retry
	} else {
		return nil, fmt.Errorf("soa.retry not found")
	}
	if zoneConfig.SOA.Expire != nil {
		expire = *zoneConfig.SOA.Expire
	} else if zoneDefaultConfig.SOA.Expire != nil {
		expire = *zoneDefaultConfig.SOA.Expire
	} else {
		return nil, fmt.Errorf("soa.expire not found")
	}
	if zoneConfig.SOA.MinTTL != nil {
		minTTL = *zoneConfig.SOA.MinTTL
	} else if zoneDefaultConfig.SOA.MinTTL != nil {
		minTTL = *zoneDefaultConfig.SOA.MinTTL
	} else {
		return nil, fmt.Errorf("soa.minTTL not found")
	}
	records := map[string][]dnsRecord{}
	if zoneConfig.Records != nil {
		for _, zc := range *zoneConfig.Records {
			if zc.CNAME != nil {
				_, ok := records[zc.Name]
				if !ok {
					records[zc.Name] = []dnsRecord{}
				}
				records[zc.Name] = append(records[zc.Name], dnsRecord{
					DNSType: dns.TypeCNAME,
					CNAME:   toFQDN(*zc.CNAME, fqdn),
				})
			}
			if zc.TXT != nil {
				_, ok := records[zc.Name]
				if !ok {
					records[zc.Name] = []dnsRecord{}
				}
				records[zc.Name] = append(records[zc.Name], dnsRecord{
					DNSType: dns.TypeTXT,
					TXT:     *zc.TXT,
				})
			}
		}
	}
	return &zone{
		SOA: soa{
			NS:      dns.Fqdn(soaNS),
			MBox:    dns.Fqdn(mBox),
			Refresh: refresh,
			Retry:   retry,
			Expire:  expire,
			MinTTL:  minTTL,
		},
		Records: records,
		Suffix:  fqdn,
		Origin:  origin,
		TTL:     ttl,
		NS:      ns,
	}, nil
}

func toFQDN(name string, zone string) string {
	if dns.IsFqdn(name) {
		return name
	}
	return fmt.Sprintf("%s.%s", name, zone)
}

func sortRR(rr []dns.RR, rnd bool) {
	if rnd {
		i := 0
		for j := 0; j < len(rr); j++ {
			switch rr[j].(type) {
			case *dns.AAAA:
				rr[i], rr[j] = rr[j], rr[i]
				i++
			}
		}
		for j := 0; j < len(rr); j++ {
			switch rr[j].(type) {
			case *dns.A:
				rr[i], rr[j] = rr[j], rr[i]
				i++
			}
		}
		n := len(rr) - i
		for j := n - 1; j >= 0; j-- {
			k := rand.Intn(j + 1)
			rr[j], rr[k] = rr[k], rr[j]
		}
	} else {

	}
}
