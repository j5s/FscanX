package core

import (
	"FscanX/config"
	"FscanX/plugin"
	"FscanX/webscan"
	"FscanX/webscan/lib"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

func Scanner(flag config.EnterFlag) {
	if flag.ScanHost == ""{
		fmt.Println("FscanX.exe [global options] command [command options] [arguments...] HOST ")
		return
	}
	start := time.Now()
	if flag.ScanType != ""{
		fmt.Println("当前操作系统:",runtime.GOOS)
		fmt.Println("进程信息:", os.Args[0],os.Getpid())
		fmt.Println("")
	}
	switch flag.ScanType {
	case "hostscan":
		hostscanner(flag)
	case "ms17010":
		ms17010scanner(flag)
	case "smbghost":
		smbghostscanner(flag)
	case "portscan":
		portscanner(flag)
	case "oxidscan":
		oxidscanner(flag)
	case "webscan":
		webscanner(flag)
	}
	elapsed := time.Since(start)
	if elapsed != 0{
		fmt.Println("[total time]", elapsed)
	}

}

func webscanner(flag config.EnterFlag){
	fmt.Println("Load webscan")
	fmt.Println("[config] ==> | thread",flag.Thread,"| noping",flag.NoPing,"|")
	fmt.Println("")
	lib.Inithttp(config.WebConfig)
	ips, _ :=  ResolveIPS(flag.ScanHost)
	var result []config.PortResult
	//fmt.Println(ips)
	var aliveip =  plugin.PingScan(flag.Thread,ips,flag.NoPing)
	var resolveports []int
	if flag.Ports != "" {
		resolveports = resolvePorts(flag.Ports)
	}else{
		resolveports = config.WebPorts
	}
	result = plugin.PortScan(flag.Thread,resolveports,aliveip)
	var wg sync.WaitGroup
	result = plugin.PortScan(flag.Thread,resolveports,aliveip)
	var taskchan = make(chan config.PortResult)
	go func() {
		for _,value := range result {
			taskchan <- value
		}
		defer close(taskchan)
	}()
	for i:=0;i<int(flag.Thread);i++{
		wg.Add(1)
		go func(chan config.PortResult) {
			for value := range taskchan{
				webscan.WebScan(&value,flag.Fragile,int(flag.Thread))
			}
			defer wg.Done()
		}(taskchan)
	}
	wg.Wait()
	printalivePC(aliveip)

}


func printalivePC(ips []string) {
	fmt.Println("---------------------------------------")
	fmt.Println("Alive PC:",len(ips))
	fmt.Println("Scan Finished!")
}
func hostscanner(flag config.EnterFlag){
	fmt.Println("Load hostscan")
	fmt.Println("[config] ==> | thread",flag.Thread,"| noping",flag.NoPing,"|")
	fmt.Println("")
	ips ,_ := ResolveIPS(flag.ScanHost)
	var aliveip = plugin.PingScan(flag.Thread,ips,flag.NoPing)
	for _,ip:= range aliveip{
		fmt.Println("[+]",ip)
	}
	printalivePC(aliveip)

}
func oxidscanner(flag config.EnterFlag){
	fmt.Println("Load oxidscan")
	fmt.Println("[config] ==> | thread",flag.Thread,"| noping",flag.NoPing,"|")
	fmt.Println("")
	// 首先对存活主机进行扫描，扫描完成后才能进行ms17070的扫描
	// 解析IP
	ips, _ :=  ResolveIPS(flag.ScanHost)
	//fmt.Println(ips)
	var aliveip =  plugin.PingScan(flag.Thread,ips,flag.NoPing)
	if len(aliveip) > 0 {
		var wg sync.WaitGroup
		var taskchan = make(chan string)
		go func() {
			for _, ip := range aliveip {
				taskchan <- ip
			}
			defer close(taskchan)
		}()
		for i := 0; i < int(flag.Thread); i++ {
			wg.Add(1)
			go func(taskchan chan string) {
				defer wg.Done()
				for ip := range taskchan {
					_ = FuncCall(PluginMap, "135", &config.HostData{HostName: ip, TimeOut: 5, Ports: 135})
				}
			}(taskchan)
		}
		wg.Wait()
	}
	printalivePC(aliveip)
}

func ms17010scanner(flag config.EnterFlag){
	fmt.Println("Load ms17010")
	fmt.Println("[config] ==> | thread",flag.Thread,"| noping",flag.NoPing,"|")
	fmt.Println("")
	// 首先对存活主机进行扫描，扫描完成后才能进行ms17070的扫描
	// 解析IP
	ips, _ :=  ResolveIPS(flag.ScanHost)
	//fmt.Println(ips)
	var aliveip =  plugin.PingScan(flag.Thread,ips,flag.NoPing)
	if len(aliveip) > 0 {
		var wg sync.WaitGroup
		var taskchan = make(chan string)
		go func() {
			for _,ip := range aliveip{
				taskchan <- ip
			}
			defer close(taskchan)
		}()
		for i:=0;i<int(flag.Thread);i++{
			wg.Add(1)
			go func(taskchan chan string) {
				defer wg.Done()
				for ip := range taskchan{
					var info  = config.HostData{HostName: ip,TimeOut: 5}
					err := plugin.MS17070(&info)
					if err != nil {
						fmt.Println("[*]",info.HostName)
					}
				}
			}(taskchan)
		}
		wg.Wait()
	}
	printalivePC(aliveip)
}


func smbghostscanner(flag config.EnterFlag){
	fmt.Println("Load smbghost [CVE-2020-0796]")
	fmt.Println("[config] ==> | thread",flag.Thread,"| noping",flag.NoPing,"|")
	fmt.Println("")
	ips, _ :=  ResolveIPS(flag.ScanHost)
	//fmt.Println(ips)
	var aliveip =  plugin.PingScan(flag.Thread,ips,flag.NoPing)
	if len(aliveip) > 0 {
		var wg sync.WaitGroup
		var taskchan = make(chan string)
		go func() {
			for _,ip := range aliveip{
				taskchan <- ip
			}
			defer close(taskchan)
		}()
		for i:=0;i<int(flag.Thread);i++{
			wg.Add(1)
			go func(taskchan chan string) {
				defer wg.Done()
				for ip := range taskchan{
					var info  = config.HostData{HostName: ip,TimeOut: 5}
					err := plugin.SMBGHOST(&info)
					if err != nil {
						fmt.Println("[*]",info.HostName)
					}
				}
			}(taskchan)
		}
		wg.Wait()
	}
	printalivePC(aliveip)
}

func portscanner(flag config.EnterFlag) {
	fmt.Println("Load portscan")
	fmt.Println("[config] ==> | Fragile",flag.Fragile,"| thread",flag.Thread,"| noping",flag.NoPing,"| netbios",flag.Netbios,"|")
	// 第一步对存活主机进行探测，获取存活主机的列表
	fmt.Println("")
	var result []config.PortResult
	ips, _ :=  ResolveIPS(flag.ScanHost)
	//fmt.Println(ips)
	var aliveip =  plugin.PingScan(flag.Thread,ips,flag.NoPing)
	var resolveports []int
	// 这里解析端口，如果输入的有端口就采用输入的端口进行扫描，否在采用默认端口扫描
	if flag.Ports != "" {
		resolveports = resolvePorts(flag.Ports)
	}else{
		resolveports = config.DefaultPorts
	}
	// 获取完存活主机，在进行判断，如果Fragile参数为true，则进行脆弱端口的扫描，否在就进行常规端口扫描
	if flag.Fragile == true{

		var wg sync.WaitGroup
		result = plugin.PortScan(flag.Thread,resolveports,aliveip)
		var taskchan = make(chan config.PortResult)
		go func() {
			for _,value := range result {
				taskchan <- value
			}
			defer close(taskchan)
		}()
		for i:=0;i<int(flag.Thread);i++{
			wg.Add(1)
			go func(chan config.PortResult) {
				for value := range taskchan{
					var temport []int
					for _,key := range value.Port{
						temport = append(temport, key)
						switch strconv.Itoa(key) {
						case "445":
							_ = FuncCall(PluginMap,"ms17010",&config.HostData{HostName: value.IP,TimeOut:5,Ports: 445,SshKey:""})
							_ = FuncCall(PluginMap,"smbghost",&config.HostData{HostName: value.IP,TimeOut:5,Ports: 445,SshKey:""})
							break
						case "3306":
							_ = FuncCall(PluginMap,"3306",&config.HostData{HostName: value.IP,TimeOut:5,Ports:3306,SshKey:""})
							break
						case "139":
							if flag.Netbios == true {
								_ = FuncCall(PluginMap,"139",&config.HostData{HostName: value.IP,TimeOut:5,Ports:139,SshKey:"",ScanType: "netbios"})
							}else{
								continue
							}
							break
						case "1433":
							_ = FuncCall(PluginMap,"1433",&config.HostData{HostName: value.IP,TimeOut:5,Ports:1433,SshKey:""})
							break
						case "5432":
							_ = FuncCall(PluginMap,"5432",&config.HostData{HostName: value.IP,TimeOut:5,Ports:5432,SshKey:""})
							break
						case "21":
							_ = FuncCall(PluginMap,"21",&config.HostData{HostName: value.IP,TimeOut:5,Ports:21,SshKey:""})
							break
						case "22":
							_ = FuncCall(PluginMap,"22",&config.HostData{HostName: value.IP,TimeOut:5,Ports:22,SshKey:flag.Sshkey,Command:""})
							break
						case "27017":
							_ = FuncCall(PluginMap,"27017",&config.HostData{HostName: value.IP,TimeOut:5,Ports:27017,SshKey:""})
							break
						case "6379":
							_ = FuncCall(PluginMap,"6379",&config.HostData{HostName: value.IP,TimeOut: 5,Ports: 6379,SshKey: ""})
						default:
							continue
						}
					}
					fmt.Println("[*]",value.IP,temport)
				}
				wg.Done()
			}(taskchan)
		}
		wg.Wait()
	}else{
		result = plugin.PortScan(flag.Thread,resolveports,aliveip)
		for _,key := range result {
			for _,value := range key.Port{
				if value == 139 && flag.Netbios == true{
					_ = FuncCall(PluginMap,"139",&config.HostData{HostName: key.IP,TimeOut:5,Ports:139,SshKey:"",ScanType: "netbios"})
				}
				if value == 22 && flag.Sshkey != ""{
					_ = FuncCall(PluginMap,"22",&config.HostData{HostName: key.IP,TimeOut:5,Ports:22,SshKey:flag.Sshkey,Command:"whoami"})
				}
				if value == 6379 && (config.RedisFile !="" || config.RedisShell!=""){
					_ = FuncCall(PluginMap,"6379",&config.HostData{HostName: key.IP,TimeOut: 5,Ports: 6379,SshKey: ""})
				}
			}
			fmt.Println("[*]",key.IP,key.Port)
		}
	}
	printalivePC(aliveip)
}
