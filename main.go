package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

var (
	configPath = flag.String("c", "./config.yml", "path of configuration file")
	config     = &Config{
		Netbox: NetboxConfig{
			UseTLS:    false,
			VerifyTLS: true,
			Mode:      "description",
			Interval:  "1m",
		},
	}
)

func serve(net string, listen string, secret *map[string]string, soreuseport bool) {
	server := &dns.Server{Addr: listen, Net: net, TsigSecret: *secret, ReusePort: soreuseport}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	buf, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := yaml.Unmarshal(buf, config); err != nil {
		log.Fatal(err)
	}

	if config.Server.CPUProfile != nil {
		f, err := os.Create(*config.Server.CPUProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if config.Server.CPU != nil {
		runtime.GOMAXPROCS(*config.Server.CPU)
	}

	zones := []Zone{}
	for _, zoneConfig := range config.Zones {
		zone, err := zoneMerge(&zoneConfig, &config.ZoneDefault)
		if err != nil {
			log.Fatal(err)
		}
		dns.HandleFunc(zone.Origin, handleZone(zone))
		zones = append(zones, *zone)
	}

	if err := startNetboxSync(config, &zones); err != nil {
		log.Fatal(err)
	}

	secret := map[string]string{}
	for _, ts := range config.TsigSecrets {
		secret[dns.Fqdn(ts.Name)] = ts.Secret
	}
	if config.Server.SoReuseport != nil {
		for i := uint32(0); i < *config.Server.SoReuseport; i++ {
			for _, listen := range config.Server.Listen {
				go serve("tcp", listen, &secret, true)
				go serve("udp", listen, &secret, true)
			}
		}
	} else {
		for _, listen := range config.Server.Listen {
			go serve("tcp", listen, &secret, false)
			go serve("udp", listen, &secret, false)
		}
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
