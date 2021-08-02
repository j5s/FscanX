package lib

import (
	"FscanX/config"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
	dialTimout       = 5 * time.Second
	keepAlive        = 15 * time.Second
)

func Inithttp(webinfo config.WebInfo) {
	//PocInfo.Proxy = "http://127.0.0.1:8080"
	err := InitHttpClient(webinfo.SetProxy, time.Duration(webinfo.TimeOut)*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

func InitHttpClient(DownProxy string, Timeout time.Duration) error {
	dialer := &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     0,
		MaxIdleConns:        0,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}
	if DownProxy != "" {
		if DownProxy == "1" {
			DownProxy = "http://127.0.0.1:8080"
		} else if !strings.Contains(DownProxy, "://") {
			DownProxy = "http://127.0.0.1:" + DownProxy
		}
		u, err := url.Parse(DownProxy)
		if err != nil {
			return err
		}
		tr.Proxy = http.ProxyURL(u)
	}

	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}