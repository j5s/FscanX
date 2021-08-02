package plugin

import (
	"FscanX/config"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func SshScan(info *config.HostData)(tmperr error) {
	var starttime = time.Now().Unix()
	// 遍历字典用户名
	for _,user := range config.Userdict["ssh"]{
		// 遍历密码字典
		for _ ,pass := range config.Passwords {
			pass = strings.Replace(pass,"{user}",user,-1)
			flag, err := sshConn(info,user,pass)
			if flag == true && err == nil {
				return nil
			}else{
				errlog := fmt.Sprintf("[-] ssh %v:%v %v %v %v", info.HostName, info.Ports, user, pass, err)
				_ = errlog
				tmperr = err
			}
			if time.Now().Unix() - starttime > (int64(len(config.Userdict["ssh"])*len(config.Passwords)) * info.TimeOut){
				return err
			}
		}
	}
	return tmperr
}
func sshConn(info *config.HostData, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.HostName, info.Ports, user, pass
	Auth := []ssh.AuthMethod{}
	if info.SshKey != "" {
		pemBytes, err := ioutil.ReadFile(info.SshKey)
		if err != nil {
			return false, errors.New("read key failed " + err.Error())
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, errors.New("parse key failed " + err.Error())
		}
		Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: time.Duration(info.TimeOut) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			flag = true
			var result string
			if info.Command != "" {
				combo, _ := session.CombinedOutput(info.Command)
				result = fmt.Sprintf("[+] %v:%v [SSH] %v %v \n %v", Host, Port, Username, Password, string(combo))
				if info.SshKey != "" {
					result = fmt.Sprintf("[+] %v:%v [SSH] sshkey correct \n %v", Host, Port, string(combo))
				}
				fmt.Println(result)
			} else {
				result = fmt.Sprintf("[+] %v:%v [SSH] %v %v", Host, Port, Username, Password)
				if info.SshKey != "" {
					result = fmt.Sprintf("[+] %v:%v [SSH] sshkey correct", Host, Port)
				}
				fmt.Println(result)
			}
		}
	}
	return flag, err
}