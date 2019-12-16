package main

import (
	"flag"
	"fmt"
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
		Server: ServerConfig{
			Port: 53,
		},
		Netbox: NetboxConfig{
			UseTLS:    false,
			VerifyTLS: true,
			Mode:      "description",
			Interval:  "1m",
		},
	}
)

func serve(net string, port int, secret *map[string]string, soreuseport bool) {
	server := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: net, TsigSecret: *secret, ReusePort: soreuseport}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
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

	origins := []string{}
	for _, zoneConfig := range config.Zones {
		zone, err := zoneMerge(&zoneConfig, &config.ZoneDefault)
		if err != nil {
			log.Fatal(err)
		}
		var origin string
		if zone.Origin == nil {
			origin = zone.Suffix
		} else {
			origin = *zone.Origin
		}
		dns.HandleFunc(origin, handleZone(zone))
		origins = append(origins, origin)
	}

	if err := startNetboxSync(config, origins); err != nil {
		log.Fatal(err)
	}

	secret := map[string]string{}
	for _, ts := range config.TsigSecrets {
		secret[dns.Fqdn(ts.Name)] = ts.Secret
	}
	if config.Server.SoReuseport != nil {
		for i := uint32(0); i < *config.Server.SoReuseport; i++ {
			go serve("tcp", config.Server.Port, &secret, true)
			go serve("udp", config.Server.Port, &secret, true)
		}
	} else {
		go serve("tcp", config.Server.Port, &secret, false)
		go serve("udp", config.Server.Port, &secret, false)
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
