package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type zone struct {
	Suffix  string                 `yaml:"suffix"`
	Origin  string                 `yaml:"origin"`
	SOA     soa                    `yaml:"soa"`
	TTL     uint32                 `yaml:"ttl"`
	NS      []string               `yaml:"ns"`
	Records map[string][]dnsRecord `yaml:"records"`
}

func newZoneManager(zone *zone) *zoneManager {
	return &zoneManager{
		ZoneConfig: *zone,
		Serial:     serial{},
		Tree:       dnsTree{},
	}
}

type zoneManager struct {
	ZoneConfig zone
	Serial     serial
	Tree       dnsTree
}

func (zm *zoneManager) handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	m.SetEdns0(4096, true)

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
		results, cnameAllLen := zm.resolve(q.Name, []uint16{dns.TypeCNAME})
		if len(results) != 0 {
			m.Answer = append(m.Ns, results[0])
			if q.Qtype != dns.TypeCNAME {
				cname := *results[0].(*dns.CNAME)
				glues, allLen := zm.resolve(cname.Target, []uint16{q.Qtype})
				if allLen != 0 {
					for _, glue := range glues {
						m.Answer = append(m.Answer, glue)
					}
				}
			}
			w.WriteMsg(m)
			return
		}
		switch q.Qtype {
		case dns.TypeSOA:
			soa, err := zm.getSOA(q.Name)
			if err != nil {
				m.Ns = append(m.Ns, zm.getSOAonError())
				w.WriteMsg(m)
				return
			}
			m.Answer = append(m.Answer, soa)
		case dns.TypeA:
			results, allLen := zm.resolve(q.Name, []uint16{dns.TypeA})
			if len(results) == 0 {
				if allLen == 0 {
					m.SetRcode(r, dns.RcodeNameError)
				} else {
					m.SetRcode(r, dns.RcodeSuccess)
				}
				m.Ns = append(m.Ns, zm.getSOAonError())
				w.WriteMsg(m)
				return
			}
			for _, result := range results {
				m.Answer = append(m.Answer, result)
			}
		case dns.TypeAAAA:
			results, allLen := zm.resolve(q.Name, []uint16{dns.TypeAAAA})
			if len(results) == 0 {
				if allLen == 0 {
					m.SetRcode(r, dns.RcodeNameError)
				} else {
					m.SetRcode(r, dns.RcodeSuccess)
				}
				m.Ns = append(m.Ns, zm.getSOAonError())
				w.WriteMsg(m)
				return
			}
			for _, result := range results {
				m.Answer = append(m.Answer, result)
			}
		case dns.TypeTXT:
			results, allLen := zm.resolve(q.Name, []uint16{dns.TypeTXT})
			if len(results) == 0 {
				if allLen == 0 {
					m.SetRcode(r, dns.RcodeNameError)
				} else {
					m.SetRcode(r, dns.RcodeSuccess)
				}
				m.Ns = append(m.Ns, zm.getSOAonError())
				w.WriteMsg(m)
				return
			}
			for _, result := range results {
				m.Answer = append(m.Answer, result)
			}
		case dns.TypeCNAME:
			if cnameAllLen == 0 {
				m.SetRcode(r, dns.RcodeNameError)
			} else {
				m.SetRcode(r, dns.RcodeSuccess)
			}
			m.Ns = append(m.Ns, zm.getSOAonError())
			w.WriteMsg(m)
			return
		}
	}
	w.WriteMsg(m)
}

func (zm *zoneManager) resolve(fqdn string, dnsTypes []uint16) ([]dns.RR, int) {
	rr := []dns.RR{}
	prefix, err := zm.getPrefixByOrigin(fqdn)
	if err != nil {
		return nil, 0
	}
	records := zm.Tree.search(prefix)
	if records == nil {
		return nil, 0
	}
	for _, record := range *records {
		for _, t := range dnsTypes {
			if t == dns.TypeA && record.DNSType == dns.TypeA {
				rr = append(rr, &dns.A{
					Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
					A:   record.A,
				})
			}
			if t == dns.TypeAAAA && record.DNSType == dns.TypeAAAA {
				rr = append(rr, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
					AAAA: record.AAAA,
				})
			}
			if t == dns.TypeTXT && record.DNSType == dns.TypeTXT {
				rr = append(rr, &dns.TXT{
					Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
					Txt: []string{record.TXT},
				})
			}
			if t == dns.TypeCNAME && record.DNSType == dns.TypeCNAME {
				rr = append(rr, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
					Target: record.CNAME,
				})
			}
		}
	}
	sortRR(rr)
	return rr, len(*records)
}

func (zm *zoneManager) getSOAonError() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zm.ZoneConfig.Origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
		Ns:      zm.ZoneConfig.SOA.NS,
		Mbox:    zm.ZoneConfig.SOA.MBox,
		Serial:  zm.getSerial(),
		Refresh: zm.ZoneConfig.SOA.Refresh,
		Retry:   zm.ZoneConfig.SOA.Retry,
		Expire:  zm.ZoneConfig.SOA.Expire,
		Minttl:  zm.ZoneConfig.SOA.MinTTL,
	}
}

func (zm *zoneManager) getSOA(qName string) (*dns.SOA, error) {
	if qName != zm.ZoneConfig.Suffix {
		return nil, fmt.Errorf("Not found")
	}
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: qName, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
		Ns:      zm.ZoneConfig.SOA.NS,
		Mbox:    zm.ZoneConfig.SOA.MBox,
		Serial:  zm.getSerial(),
		Refresh: zm.ZoneConfig.SOA.Refresh,
		Retry:   zm.ZoneConfig.SOA.Retry,
		Expire:  zm.ZoneConfig.SOA.Expire,
		Minttl:  zm.ZoneConfig.SOA.MinTTL,
	}, nil
}

func (zm *zoneManager) initSerial() {
	now := time.Now()
	zm.Serial = serial{
		YYYY: now.Year(),
		MM:   int(now.Month()),
		DD:   now.Day(),
		N:    1,
	}
}
func (zm *zoneManager) setSerial(serial uint32) {
	zm.Serial = *unmarshalSerial(serial)
}

func (zm *zoneManager) getSerial() uint32 {
	return marshalSerial(&zm.Serial)
}

func (zm *zoneManager) updateSerial() {
	now := time.Now()
	n := 1
	if zm.Serial.YYYY == now.Year() &&
		zm.Serial.MM == int(now.Month()) &&
		zm.Serial.DD == now.Day() {
		n = zm.Serial.N + 1
	}
	zm.Serial = serial{
		YYYY: now.Year(),
		MM:   int(now.Month()),
		DD:   now.Day(),
		N:    n,
	}
}

func (zm *zoneManager) includesBySuffix(fqdn string) bool {
	if strings.HasSuffix(fqdn, zm.ZoneConfig.Suffix) || fqdn == zm.ZoneConfig.Suffix {
		return true
	}
	return false
}

func (zm *zoneManager) getPrefixBySuffix(fqdn string) (string, error) {
	if fqdn == zm.ZoneConfig.Suffix {
		return "", nil
	}
	if !strings.HasSuffix(fqdn, "."+zm.ZoneConfig.Suffix) {
		return "", fmt.Errorf("invalid suffix")
	}
	return fqdn[:len(fqdn)-len(zm.ZoneConfig.Suffix)-1], nil
}

func (zm *zoneManager) getPrefixByOrigin(fqdn string) (string, error) {
	if fqdn == zm.ZoneConfig.Origin {
		return "", nil
	}
	if !strings.HasSuffix(fqdn, "."+zm.ZoneConfig.Origin) {
		return "", fmt.Errorf("invalid origin")
	}
	return fqdn[:len(fqdn)-len(zm.ZoneConfig.Origin)-1], nil
}
