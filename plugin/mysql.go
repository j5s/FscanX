package plugin

import (
	"FscanX/config"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"strings"
	"time"
)

func MysqlScan(info *config.HostData) (tmperr error)  {
	var starttime = time.Now().Unix()
	// 遍历字典用户名
	for _,user := range config.Userdict["mysql"]{
		// 遍历密码字典
		for _ ,pass := range config.Passwords {
			pass = strings.Replace(pass,"{user}",user,-1)
			flag, err := mysqlConn(info,user,pass)
			if flag == true && err == nil {
				return nil
			}else{
				errlog := fmt.Sprintf("[-] mysql %v:%v %v %v %v", info.HostName, info.Ports, user, pass, err)
				_ = errlog
				tmperr = err
			}
			if time.Now().Unix() - starttime > (int64(len(config.Userdict["mysql"])*len(config.Passwords)) * info.TimeOut){
				return err
			}
		}
	}
	return tmperr
}

func mysqlConn(info *config.HostData, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.HostName, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, time.Duration(info.TimeOut)*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.TimeOut) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(info.TimeOut) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] %v:%v [mysql]:%v %v", Host, Port, Username, Password)
			fmt.Println(result)
			flag = true
		}
	}
	return flag, err
}