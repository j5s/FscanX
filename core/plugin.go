package core

import "FscanX/plugin"

var PluginMap = map[string]interface{}{
	"ms17010":  plugin.MS17070,
	"smbghost": plugin.SMBGHOST,
	"1433":     plugin.MssqlScan,
	"3306":     plugin.MysqlScan,
	"5432":     plugin.PostgreScan,
	"139":      plugin.NetBIOS,
	"21":       plugin.FtpScan,
	"22":       plugin.SshScan,
	"27017":    plugin.MongodbScan,
	"135":      plugin.Findnet,
	"6379":     plugin.RedisScan,
}