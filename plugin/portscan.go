package plugin

import (
	"FscanX/config"
	"fmt"
	"net"
	"sync"
	"time"
)

var mutex sync.Mutex

// 对存活主机的IP列表进行并发处理

func PortScan(thread int64,ports []int,iplist []string)[]config.PortResult{
	var result []config.PortResult
	if len(ports) != 0 && len(iplist) != 0 {
		var hostchan = make(chan string)
		var wg sync.WaitGroup
		go func() {
			for _, ip := range iplist{
				hostchan <- ip
			}
			defer close(hostchan)
		}()
		for i:=0;i<int(thread);i++{
			wg.Add(1)
			go func(hostschan chan string) {
				defer wg.Done()
				for ip := range hostschan{
					var portlist = toscanports(thread,ports,ip) // 对每一个IP都进行端口扫描
					result = append(result,config.PortResult{ip,portlist})
				}
			}(hostchan)

		}
		wg.Wait()
	}
	return result
}
// 对端口进行并发处理

func toscanports(thread int64,ports []int,ip string)[]int{
	var temp []int
	if len(ports) != 0 {
		var portchan = make(chan int)
		var wg sync.WaitGroup
		go func() {
			for _, port := range ports{
				portchan <- port
			}
			defer close(portchan)
		}()
		for i:=0;i<int(thread);i++{
			wg.Add(1)
			go func(portschan chan int) {
				for port := range portchan{
					if portconnect(ip,port) == true {
						temp = append(temp,port)
					}
				}
				wg.Done() // 这里写wg.Done()的原因是因为每次单个IP都需要遍历完成全部端口才能结束
			}(portchan)
		}
		wg.Wait()
	}
	return temp
}


func portconnect(ip string,port int) bool {
	host,scan := ip,port
	conn, err := net.DialTimeout("tcp4",fmt.Sprintf("%s:%v",host,scan),time.Duration(2)*time.Second)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}