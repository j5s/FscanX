package webscan

import (
	"FscanX/config"
	"FscanX/webscan/lib"
	"embed"
	"fmt"
	"net/http"
	"strings"
)

//go:embed pocs
var Pocs embed.FS

func WebScanPOC(info *httpdata) {
	var pocinfo = config.WebConfig
	buf := strings.Split(info.Host, "/")
	pocinfo.Target = strings.Join(buf[:3], "/")
	if pocinfo.PocName != "" {
		Execute(pocinfo,info.Thread)
		return
	}
	for _, infostr := range info.Infostr {
		pocinfo.PocName = lib.CheckInfoPoc(infostr)
		Execute(pocinfo,info.Thread)
	}
}

func Execute(PocInfo config.WebInfo,thread int) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webtitle %v %v", PocInfo.Target, err)
		_ = errlog
		return
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	if PocInfo.SetCookie != "" {
		req.Header.Set("Cookie", PocInfo.SetCookie)
	}
	lib.CheckMultiPoc(req, Pocs,thread, PocInfo.PocName)
}