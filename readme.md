# FscanX 
其实FscanX的灵感来源于fscan和LodanGo这两个开源项目，首先不得不说fscan和LadonGo两个都是非常优秀的内网扫描器。并且其独自的特色也让其在内网扫描器领域独占鳌头。其中LadonGo的插件式让其在扫描时更加专注，而fscan的傻瓜式则让其对内网的信息搜集更加高效。
但是对于一个懒蛋的我，我选择两者都要（毕竟小孩子才做选择），所以我将其Fscan进行了完全改造，在结合了LadonGo的单插件扫描的同时，保留了Fscan对于Web的漏洞和内网服务的脆弱检测，使其即像LadonGo的同时，也更加流氓。

<br>目前实现的功能如下  （Example）:
<br>1.CVE-2020-0796 smbghost 插件扫描，支持整个C段式扫描
```shell
    FscanX.exe smbghost --thread 60 --noping 192.168.1.1/24
```
![img.png](image/img4.png)
<br>2. MS-17010 Eternal blue 扫描
```shell
    FscanX.exe ms17010 192.168.1.1/24
```
<br>3. ICMP / ping 存活主机探测
```shell
    FscanX.exe hostscan --noping --thread 60 192.168.1.1/24
```
![img.png](image/img1.png)
<br>4. TCP 端口扫描（支持脆弱端口的漏洞检测）
```shell
    FscanX.exe portscan --thread 60 --fragile --noping 192.168.1.1/24
```
![img.png](image/img3.png)
<br>5. Web 服务检测
```shell 
    FscanX.exe webscan --thread 60 --fragile --noping 192.168.1.1/24
```
![img.png](image/img2.png)
<br>6.oxid 网卡信息发现
```shell
    FscanX.exe oxidscan 192.168.1.1/24
```
![img.png](image/img.png)
<br> 上述为一些使用例子，详细可使用-h或--help查看帮助
<br> 最后：
<br> 感谢：https://github.com/shadow1ng/fscan
<br> 感谢：https://github.com/k8gege/LadonGo
