package main

import (
	"log"
	"net"
	"net/http"
	"time"
)

var retry time.Duration = 10 * time.Second

func getHandler(ch chan struct{}, ts string, allowFrom []*net.IPNet) (func(w http.ResponseWriter, r *http.Request), error) {
	timeout, err := time.ParseDuration(ts)
	if err != nil {
		return nil, err
	}
	var access time.Time
	return func(w http.ResponseWriter, r *http.Request) {
		ip, err := parseIP(r.RemoteAddr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte{})
			return
		}
		allowFlag := false
		for _, allow := range allowFrom {
			if allow.Contains(ip) {
				allowFlag = true
				break
			}
		}
		if !allowFlag {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte{})
			return
		}
		log.Println("webhook received")
		access = time.Now()
		w.Write([]byte{})
		go func() {
			t := time.NewTimer(timeout)
			<-t.C
			if access.Add(timeout).Before(time.Now()) {
				log.Println("webhook timeout")
				ch <- struct{}{}
			}
		}()
	}, nil
}

func startListen(wc *webhookConfig) (chan struct{}, error) {
	ch := make(chan struct{})
	mux := http.NewServeMux()
	if wc.Timeout == "" {
		wc.Timeout = "30s"
	}
	networks := []*net.IPNet{}
	for _, allowStr := range wc.AllowFrom {
		_, subnet, err := net.ParseCIDR(allowStr)
		if err != nil {
			log.Println(err)
		}
		networks = append(networks, subnet)
	}
	handler, err := getHandler(ch, wc.Timeout, networks)
	if err != nil {
		return nil, err
	}
	mux.Handle("/", http.HandlerFunc(handler))
	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Addr:         wc.Listen,
		Handler:      mux,
	}
	go func() {
		for {
			err := srv.ListenAndServe()
			log.Println(err)
			time.Sleep(retry)
		}
	}()
	return ch, nil
}
