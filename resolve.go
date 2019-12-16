package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	Server      ServerConfig       `yaml:"server"`
	ZoneDefault ZoneDefaultConfig  `yaml:"zoneDefault"`
	Zones       []ZoneConfig       `yaml:"zones"`
	TsigSecrets []TsigSecretConfig `yaml:"tsigSecrets"`
	Netbox      NetboxConfig       `yaml:"netbox"`
}

type ServerConfig struct {
	CPUProfile  *string  `yaml:"cpuProfile"`
	CPU         *int     `yaml:"cpu"`
	SoReuseport *uint32  `yaml:"soReuseport"`
	Listen      []string `yaml:"listen"`
}

type ZoneConfig struct {
	Suffix string    `yaml:"suffix"`
	Origin *string   `yaml:"origin"`
	SOA    SOAConfig `yaml:"soa"`
	TTL    *uint32   `yaml:"ttl"`
	NS     *[]string `yaml:"ns"`
}

type TsigSecretConfig struct {
	Name   string `yaml:"name"`
	Secret string `yaml:"secret"`
}

type ZoneDefaultConfig struct {
	SOA SOAConfig `yaml:"soa"`
	TTL *uint32   `yaml:"ttl"`
	NS  *[]string `yaml:"ns"`
}

type SOAConfig struct {
	NS      *string `yaml:"ns"`
	MBox    *string `yaml:"mBox"`
	Refresh *uint32 `yaml:"refresh"`
	Retry   *uint32 `yaml:"retry"`
	Expire  *uint32 `yaml:"expire"`
	MinTTL  *uint32 `yaml:"minTTL"`
}

type NetboxConfig struct {
	Host       string  `yaml:"host"`
	ServerName *string `yaml:"serverName"`
	UseTLS     bool    `yaml:"useTLS"`
	VerifyTLS  bool    `yaml:"verifyTLS"`
	Token      string  `yaml:"token"`
	Mode       string  `yaml:"mode"`
	Interval   string  `yaml:"interval"`
}

type Zone struct {
	Suffix string   `yaml:"suffix"`
	Origin *string  `yaml:"origin"`
	SOA    SOA      `yaml:"soa"`
	TTL    uint32   `yaml:"ttl"`
	NS     []string `yaml:"ns"`
}

type SOA struct {
	NS      string `yaml:"ns"`
	MBox    string `yaml:"mBox"`
	Refresh uint32 `yaml:"refresh"`
	Retry   uint32 `yaml:"retry"`
	Expire  uint32 `yaml:"expire"`
	MinTTL  uint32 `yaml:"minTTL"`
}

func handleZone(zone *Zone) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Response = true

		if r.IsTsig() != nil {
			name := r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name
			if w.TsigStatus() == nil {
				m.SetTsig(name, dns.HmacMD5, 300, time.Now().Unix())
			} else {
				// TODO: 正しい応答法がワカラン
				// m.SetTsig(name, dns.HmacMD5, 300, time.Now().Unix())
				// BADKEYなど
				w.WriteMsg(m)
				return
			}
		}

		m.Authoritative = true
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeSOA:
				soa, err := getSOA(q.Name, zone)
				if err != nil {
					m.Ns = append(m.Ns, getSOAonError(zone))
					w.WriteMsg(m)
					return
				}
				m.Answer = append(m.Answer, soa)
			case dns.TypeA:
				results := resolve(zone, []string{q.Name}, true, false)
				if len(results) == 0 {
					m.Ns = append(m.Ns, getSOAonError(zone))
					w.WriteMsg(m)
					return
				}
				for _, result := range results {
					m.Answer = append(m.Answer, result)
				}
			case dns.TypeAAAA:
				results := resolve(zone, []string{q.Name}, false, true)
				if len(results) == 0 {
					m.Ns = append(m.Ns, getSOAonError(zone))
					w.WriteMsg(m)
					return
				}
				for _, result := range results {
					m.Answer = append(m.Ns, result)
				}
			}
		}
		nss := getNS(zone.Suffix, zone)
		for _, ns := range nss {
			m.Ns = append(m.Ns, ns)
		}
		extras := resolve(zone, zone.NS, true, true)
		for _, extra := range extras {
			m.Extra = append(m.Extra, extra)
		}
		w.WriteMsg(m)
	}
}

func zoneMerge(zoneConfig *ZoneConfig, zoneDefaultConfig *ZoneDefaultConfig) (*Zone, error) {
	var origin *string
	var soaNS, mBox string
	var ttl, refresh, retry, expire, minTTL uint32
	var ns []string = []string{}
	if zoneConfig.Origin != nil {
		fqdn := dns.Fqdn(*zoneConfig.Origin)
		origin = &fqdn
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
	return &Zone{
		SOA: SOA{
			NS:      dns.Fqdn(soaNS),
			MBox:    dns.Fqdn(mBox),
			Refresh: refresh,
			Retry:   retry,
			Expire:  expire,
			MinTTL:  minTTL,
		},
		Suffix: dns.Fqdn(zoneConfig.Suffix),
		Origin: origin,
		TTL:    ttl,
		NS:     ns,
	}, nil
}

func getSOAonError(zone *Zone) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone.Suffix, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 0},
		Ns:      zone.SOA.NS,
		Mbox:    zone.SOA.MBox,
		Serial:  2019121501,
		Refresh: zone.SOA.Refresh,
		Retry:   zone.SOA.Retry,
		Expire:  zone.SOA.Expire,
		Minttl:  zone.SOA.MinTTL,
	}
}

func getSOA(qName string, zone *Zone) (*dns.SOA, error) {
	if qName != zone.Suffix {
		return nil, fmt.Errorf("Not found")
	}
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: qName, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: zone.TTL},
		Ns:      zone.SOA.NS,
		Mbox:    zone.SOA.MBox,
		Serial:  2019121501,
		Refresh: zone.SOA.Refresh,
		Retry:   zone.SOA.Retry,
		Expire:  zone.SOA.Expire,
		Minttl:  zone.SOA.MinTTL,
	}, nil
}

func getNS(qName string, zone *Zone) []dns.RR {
	nss := []dns.RR{}
	for _, ns := range zone.NS {
		nss = append(nss, &dns.NS{
			Hdr: dns.RR_Header{Name: qName, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: zone.TTL},
			Ns:  dns.Fqdn(ns),
		})
	}
	sortRR(nss)
	return nss
}

func resolve(zone *Zone, fqdns []string, ipv4 bool, ipv6 bool) []dns.RR {
	rr := []dns.RR{}
	for _, fqdn := range fqdns {
		domain, ok := resolveDomain[zone.Suffix]
		if !ok {
			continue
		}
		records := domain.search(fqdn, zone.Suffix)
		if records == nil {
			continue
		}
		for _, record := range *records {
			if ipv4 && record.DNSType == dns.TypeA {
				rr = append(rr, &dns.A{
					Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: zone.TTL},
					A:   record.A,
				})
			}
			if ipv6 && record.DNSType == dns.TypeAAAA {
				rr = append(rr, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: zone.TTL},
					AAAA: record.AAAA,
				})
			}
		}
	}
	sortRR(rr)
	return rr
}

func sortRR(rr []dns.RR) {
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
}
