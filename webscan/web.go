package webscan

import (
	"FscanX/config"
	"FscanX/webscan/lib"
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/saintfish/chardet"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type httpdata struct {
	Host string
	Ports int
	Infostr []string
	Thread int
}

type CheckDatas struct {
	Body    []byte
	Headers string
}

func WebScan(result *config.PortResult,fragile bool,thread int){
	for _,value := range result.Port{
		_ = webtitle(&httpdata{Host: result.IP,Ports: value,Thread: thread},fragile)
	}
}

var (
	Charsets = []string{"utf-8", "gbk", "gb2312"}
)

func webtitle(httpd *httpdata,fragile bool) error{
	var CheckData []CheckDatas
	switch httpd.Ports {
	case 80:
		httpd.Host = fmt.Sprintf("http://%s", httpd.Host)
	case 443:
		httpd.Host = fmt.Sprintf("https://%s", httpd.Host)
	default:
		httpd.Host = fmt.Sprintf("http://%s:%v", httpd.Host, httpd.Ports)
	}
	err,result ,CheckData := geturl(httpd,1,CheckData)
	if err != nil && ! strings.Contains(err.Error(),"EOF"){
		return err
	}
	if strings.Contains(result,"://"){
		redirecturl, err := url.Parse(result)
		if err == nil {
			httpd.Host = redirecturl.String()
			err,result,CheckData = geturl(httpd,3,CheckData)
			if err != nil {
				return err
			}
		}
	}
	if result == "https" {
		httpd.Host = strings.Replace(httpd.Host , "http://", "https://", 1)
		err, result, CheckData = geturl(httpd, 1, CheckData)
		if strings.Contains(result, "://") {
			//有跳转
			redirecturl, err := url.Parse(result)
			if err == nil {
				httpd.Host  = redirecturl.String()
				err, result, CheckData = geturl(httpd, 3, CheckData)
				if err != nil {
					return err
				}
			}
		} else {
			if err != nil {
				return err
			}
		}
	}

	err, _, CheckData = geturl(httpd, 2, CheckData)
	if err != nil {
		return err
	}
	 // 进行脆弱扫描
	if fragile == true {
		httpd.Infostr = InfoCheck(httpd.Host, CheckData)
		WebScanPOC(httpd)
	}
	return err

}

func geturl(info *httpdata, flag int, CheckData []CheckDatas) (error, string, []CheckDatas) {
	Url := info.Host
	if flag == 2 {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}

	res, err := http.NewRequest("GET", Url, nil)
	if err == nil {
		res.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		res.Header.Set("Accept", "*/*")
		res.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		if config.WebConfig.SetCookie != "" {
			res.Header.Set("Cookie", "rememberMe=1;"+config.WebConfig.SetCookie)
		} else {
			res.Header.Set("Cookie", "rememberMe=1")
		}
		res.Header.Set("Connection", "close")

		var client *http.Client
		if flag == 1 {
			client = lib.ClientNoRedirect
		} else {
			client = lib.Client
		}
		resp, err := client.Do(res)
		if err == nil {
			defer resp.Body.Close()
			var title string
			var text []byte
			body, err := getRespBody(resp)
			if err != nil {
				return err, "", CheckData
			}
			if flag != 2 {
				re := regexp.MustCompile("(?ims)<title>(.*)</title>")
				find := re.FindSubmatch(body)
				if len(find) > 1 {
					text = find[1]
					GetEncoding := func() string { // 判断Content-Type
						r1, err := regexp.Compile(`(?im)charset=\s*?([\w-]+)`)
						if err != nil {
							return ""
						}
						headerCharset := r1.FindString(resp.Header.Get("Content-Type"))
						if headerCharset != "" {
							for _, v := range Charsets { // headers 编码优先，所以放在前面
								if strings.Contains(strings.ToLower(headerCharset), v) == true {
									return v
								}
							}
						}

						r2, err := regexp.Compile(`(?im)<meta.*?charset=['"]?([\w-]+)["']?.*?>`)
						if err != nil {
							return ""
						}
						htmlCharset := r2.FindString(string(body))
						if htmlCharset != "" {
							for _, v := range Charsets {
								if strings.Contains(strings.ToLower(htmlCharset), v) == true {
									return v
								}
							}
						}
						return ""
					}
					encode := GetEncoding()
					_, encode1, _ := charset.DetermineEncoding(body, "")
					var encode2 string
					detector := chardet.NewTextDetector()
					detectorstr, _ := detector.DetectBest(body)
					if detectorstr != nil {
						encode2 = detectorstr.Charset
					}
					if encode == "gbk" || encode == "gb2312" || encode1 == "gbk" || strings.Contains(strings.ToLower(encode2), "gb") {
						titleGBK, err := Decodegbk(text)
						if err == nil {
							title = string(titleGBK)
						}
					} else {
						title = string(text)
					}
				} else {
					title = "None"
				}
				title = strings.Trim(title, "\r\n \t")
				title = strings.Replace(title, "\n", "", -1)
				title = strings.Replace(title, "\r", "", -1)
				title = strings.Replace(title, "&nbsp;", " ", -1)
				if len(title) > 100 {
					title = title[:100]
				}
				if title == "" {
					title = "None"
				}
				result := fmt.Sprintf("[*] %s code:%-3v title:%v", Url, resp.StatusCode, title)
				fmt.Println(result)
			}
			CheckData = append(CheckData, CheckDatas{body, fmt.Sprintf("%s", resp.Header)})
			redirURL, err1 := resp.Location()
			if err1 == nil {
				return nil, redirURL.String(), CheckData
			}
			if resp.StatusCode == 400 && info.Host[:5] != "https" {
				return err, "https", CheckData
			}
			return err, "", CheckData
		}
		return err, "https", CheckData
	}
	return err, "", CheckData
}


func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := ioutil.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer oResp.Body.Close()
		body = raw
	}
	return body, nil
}

func Decodegbk(s []byte) ([]byte, error) { // GBK解码
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}