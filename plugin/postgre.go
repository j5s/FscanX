package plugin

import (
	"FscanX/config"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func PostgreScan(info *config.HostData) (tmperr error)  {
	var starttime = time.Now().Unix()
	// 遍历字典用户名
	for _,user := range config.Userdict["postgresql"]{
		// 遍历密码字典
		for _ ,pass := range config.Passwords {
			pass = strings.Replace(pass,"{user}",user,-1)
			flag, err := postgresConn(info,user,pass)
			if flag == true && err == nil {
				return nil
			}else{
				errlog := fmt.Sprintf("[-] postgres %v:%v %v %v %v", info.HostName, info.Ports, user, pass, err)
				_ = errlog
				tmperr = err
			}
			if time.Now().Unix() - starttime > (int64(len(config.Userdict["postgresql"])*len(config.Passwords)) * info.TimeOut){
				return err
			}
		}
	}
	return tmperr
}
func postgresConn(info *config.HostData, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.HostName, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", Username, Password, Host, Port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.TimeOut) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] %v:%v [postgres]:%v %v", Host, Port, Username, Password)
			fmt.Println(result)
			flag = true
		}
	}
	return flag, err
}