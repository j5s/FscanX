package plugin

import (
	"FscanX/config"
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"strings"
	"time"
)

func MssqlScan(info *config.HostData) (tmperr error)  {
	var starttime = time.Now().Unix()
	// 遍历字典用户名
	for _,user := range config.Userdict["mssql"]{
		 // 遍历密码字典
		for _ ,pass := range config.Passwords {
			pass = strings.Replace(pass,"{user}",user,-1)
			flag, err := mssqlConn(info,user,pass)
			if flag == true && err == nil {
				return nil
			}else{
				errlog := fmt.Sprintf("[-] mssql %v:%v %v %v %v", info.HostName, info.Ports, user, pass, err)
				_ = errlog
				tmperr = err
			}
			if time.Now().Unix() - starttime > (int64(len(config.Userdict["mssql"])*len(config.Passwords)) * info.TimeOut){
				return err
			}
		}
	}
	return tmperr
}

func mssqlConn(info *config.HostData, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.HostName, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", Host, Username, Password, Port, time.Duration(info.TimeOut)*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.TimeOut) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(info.TimeOut) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] %v:%v [mssql]:%v %v", Host, Port, Username, Password)
			fmt.Println(result)
			flag = true
		}
	}
	return flag, err
}