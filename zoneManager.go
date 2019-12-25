package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type zone struct {
	Suffix        string                 `yaml:"suffix"`
	Origin        string                 `yaml:"origin"`
	SOA           soa                    `yaml:"soa"`
	TTL           uint32                 `yaml:"ttl"`
	NS            []string               `yaml:"ns"`
	Records       map[string][]dnsRecord `yaml:"records"`
	AllowTransfer []string               `yaml:"allowTransfer"`
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
		results, cnameAllLen := zm.resolve(q.Name, []uint16{dns.TypeCNAME}, false)
		if len(results) != 0 {
			m.Answer = append(m.Ns, results[0])
			if q.Qtype != dns.TypeCNAME {
				cname := *results[0].(*dns.CNAME)
				glues, allLen := zm.resolve(cname.Target, []uint16{q.Qtype}, false)
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
		case dns.TypeNS:
			nss, err := zm.getNS(q.Name)
			if err != nil {
				m.Ns = append(m.Ns, zm.getSOAonError())
				w.WriteMsg(m)
				return
			}
			for _, ns := range nss {
				m.Answer = append(m.Answer, ns)
				sortRR(m.Answer, true)
			}
		case dns.TypeA:
			results, allLen := zm.resolve(q.Name, []uint16{dns.TypeA}, false)
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
			results, allLen := zm.resolve(q.Name, []uint16{dns.TypeAAAA}, false)
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
			results, allLen := zm.resolve(q.Name, []uint16{dns.TypeTXT}, false)
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
		case dns.TypeAXFR:
			allowTransfer := []*net.IPNet{}
			for _, allowStr := range zm.ZoneConfig.AllowTransfer {
				_, subnet, err := net.ParseCIDR(allowStr)
				if err != nil {
					w.WriteMsg(m)
					return
				}
				allowTransfer = append(allowTransfer, subnet)
			}

			ip, err := parseIP(w.RemoteAddr().String())
			if err != nil {
				w.WriteMsg(m)
				return
			}
			allowFlag := false
			for _, allow := range allowTransfer {
				if allow.Contains(ip) {
					allowFlag = true
					break
				}
			}
			if !allowFlag {
				w.WriteMsg(m)
				return
			}
			if zm.ZoneConfig.Origin != q.Name {
				w.WriteMsg(m)
				return
			}
			ch := make(chan *dns.Envelope)
			tr := new(dns.Transfer)
			var wg sync.WaitGroup
			go func() {
				wg.Add(1)
				tr.Out(w, r, ch)
				wg.Done()
			}()
			soa, err := zm.getSOA(zm.ZoneConfig.Origin)
			if err != nil {
				w.WriteMsg(m)
				return
			}
			ns, err := zm.getNS(zm.ZoneConfig.Origin)
			if err != nil {
				w.WriteMsg(m)
				return
			}
			allRR, _ := zm.resolve(zm.ZoneConfig.Origin, []uint16{dns.TypeCNAME, dns.TypeA, dns.TypeAAAA}, true)
			rr := []dns.RR{soa}
			for _, _rr := range ns {
				rr = append(rr, _rr)
			}
			for _, _rr := range allRR {
				rr = append(rr, _rr)
			}
			rr = append(rr, soa)
			ch <- &dns.Envelope{RR: rr}
			close(ch)
			wg.Wait()
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

func (zm *zoneManager) resolve(fqdn string, dnsTypes []uint16, any bool) ([]dns.RR, int) {
	rr := []dns.RR{}
	records := map[string][]dnsRecord{}
	if any {
		for prefix, record := range zm.Tree.Records {
			name := fmt.Sprintf("%s.%s", prefix, fqdn)
			if prefix == "" {
				name = fqdn
			}
			records[name] = record
		}
	} else {
		prefix, err := zm.getPrefixByOrigin(fqdn)
		if err != nil {
			return nil, 0
		}
		records[fqdn] = zm.Tree.Records[prefix]
		if records == nil {
			return nil, 0
		}
	}
	keys := make([]string, len(records))
	i := 0
	for k := range records {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, name := range keys {
		for _, record := range records[name] {
			for _, t := range dnsTypes {
				if t == dns.TypeA && record.DNSType == dns.TypeA {
					rr = append(rr, &dns.A{
						Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
						A:   record.A,
					})
				}
				if t == dns.TypeAAAA && record.DNSType == dns.TypeAAAA {
					rr = append(rr, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
						AAAA: record.AAAA,
					})
				}
				if t == dns.TypeTXT && record.DNSType == dns.TypeTXT {
					rr = append(rr, &dns.TXT{
						Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
						Txt: []string{record.TXT},
					})
				}
				if t == dns.TypeCNAME && record.DNSType == dns.TypeCNAME {
					rr = append(rr, &dns.CNAME{
						Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
						Target: record.CNAME,
					})
				}
			}
		}
	}
	sortRR(rr, !any)
	return rr, len(records)
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
	if qName != zm.ZoneConfig.Origin {
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

func (zm *zoneManager) getNS(qName string) ([]*dns.NS, error) {
	if qName != zm.ZoneConfig.Origin {
		return nil, fmt.Errorf("Not found")
	}
	result := []*dns.NS{}
	for _, ns := range zm.ZoneConfig.NS {
		result = append(result, &dns.NS{
			Hdr: dns.RR_Header{Name: qName, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: zm.ZoneConfig.TTL},
			Ns:  ns,
		})
	}
	return result, nil
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
