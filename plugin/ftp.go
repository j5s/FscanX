package plugin

import (
	"FscanX/config"
	"fmt"
	"github.com/jlaffaye/ftp"
	"strings"
	"time"
)

func FtpScan(info *config.HostData)(tmperr error){
	var starttime = time.Now().Unix()
	// 遍历字典用户名
	for _,user := range config.Userdict["ftp"]{
		// 遍历密码字典
		for _ ,pass := range config.Passwords {
			pass = strings.Replace(pass,"{user}",user,-1)
			flag, err := mssqlConn(info,user,pass)
			if flag == true && err == nil {
				return nil
			}else{
				errlog := fmt.Sprintf("[-] ftp %v:%v %v %v %v", info.HostName, info.Ports, user, pass, err)
				_ = errlog
				tmperr = err
			}
			if time.Now().Unix() - starttime > (int64(len(config.Userdict["ftp"])*len(config.Passwords)) * info.TimeOut){
				return err
			}
		}
	}
	return tmperr
}

func FtpConn(info *config.HostData, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.HostName, info.Ports, user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(info.TimeOut)*time.Second)
	if err == nil {
		err = conn.Login(Username, Password)
		if err == nil {
			flag = true
			result := fmt.Sprintf("[+] ftp://%v:%v:%v %v", Host, Port, Username, Password)
			dirs, err := conn.List("")
			//defer conn.Logout()
			if err == nil {
				if len(dirs) > 0 {
					for i := 0; i < len(dirs); i++ {
						if len(dirs[i].Name) > 50 {
							result += "\n   [->]" + dirs[i].Name[:50]
						} else {
							result += "\n   [->]" + dirs[i].Name
						}
						if i == 5 {
							break
						}
					}
				}
			}
			fmt.Println(result)
		}
	}
	return flag, err
}