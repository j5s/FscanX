package plugin

import (
	"bytes"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	Os string
	IsAlive []string
)
func init(){
	Os = runtime.GOOS
}

func PingScan(thread int64,hostlist []string,noping bool)[]string{
	var wg sync.WaitGroup

	var hostchan = make(chan string)
   	// 创建信道持续向其中写入ip
	go func() {
		for _, ip := range hostlist{
			hostchan <- ip
		}
		defer close(hostchan)
	}()
	// 采用并发的方式来读取ip，之后进行icmp的扫描
	for i:=0;i<int(thread);i++{
		wg.Add(1)
		go func(hostchan chan string) {
			defer wg.Done()
			for ip := range hostchan{
				if noping == true{
					if icmps(ip) == true {
						IsAlive = append(IsAlive,ip)
					}
				}else{
					if execping(ip) == true {
						IsAlive = append(IsAlive,ip)
					}
				}
			}
		}(hostchan)
	}
	wg.Wait()
	//fmt.Println(IsAlive)
	return IsAlive
}

// 执行ping 命令来判断主机是否存活

func execping(host string) bool{
	var cmd *exec.Cmd
	switch Os {
	case "windows":
		cmd = exec.Command("cmd","/c","ping -n 1 -w 1 "+host+" && echo true || echo false")
		break
	case "linux":
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+host+" >/dev/null && echo true || echo false")
		break
	case "darwin":
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+host+" >/dev/null && echo true || echo false")
		break
	default:
		cmd = nil
	}
	var outinfo = bytes.Buffer{}
	if cmd != nil {
		cmd.Stdout = &outinfo
		var err = cmd.Start()
		if err != nil {
			return false
		}
	if err = cmd.Wait(); err != nil {
		return false
	}else{
		if strings.Contains(outinfo.String(),"true"){
			return true
		}else{
			return false
		}
	}
	}else{
		return false
	}
}

// 利用icmp协议来判断主机是否存货

func icmps(host string) (bool) {
	conn, err := net.DialTimeout("ip4:icmp",host,3*time.Second)
	if err != nil {
		return false
	}
	defer func() {
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(3*time.Second)); err != nil {
		return false
	}
	msg := packet(host)
	if _, err := conn.Write(msg);err != nil {
		return false
	}
	var receive = make([]byte,60)
	if _, err := conn.Read(receive);err != nil {
		return false
	}
	return true
}

func packet(host string)[]byte{
	var msg = make([]byte,40)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4],msg[5] = host[0],host[1]
	msg[6],msg[7] = byte(1 >> 8),byte(1 & 255)
	msg[2] = byte(checksum(msg[0:40]) >> 8)
	msg[3] = byte(checksum(msg[0:40]) & 255)
	return msg
}

func checksum(msg []byte)uint16 {
	var sum = 0
	var length = len(msg)
	for i:=0;i<length - 1 ;i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length % 2 == 1{
		sum += int(msg[length - 1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}