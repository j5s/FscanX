package core

import (
	"FscanX/config"
	"github.com/urfave/cli/v2"
	"os"
	"reflect"
	"regexp"
)

func GetFlags(){
	var enter config.EnterFlag
	var reg = regexp.MustCompile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}")
	var app = cli.App{
		Commands:[]*cli.Command{
			{
				Name:"webscan",
				Usage: "discovery and vulnerability scanning of the web server",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "thread",
						Value: 50,
						Usage: "set gorouite for fscanX",

					},
					&cli.BoolFlag{
						Name: "noping",
						Value: false,
						Usage: "whether to use ping command",
					},
					&cli.StringFlag{
						Name: "cookie",
						Usage: "set cookies to use when scanning",
					},
					&cli.StringFlag{
						Name: "proxy",
						Usage: "set http proxy to use when scanning",
					},
					&cli.StringFlag{
						Name: "port",
						Usage: "The list of ports to be scanned",
					},
					&cli.BoolFlag{
						Name: "fragile",
						Value: false,
						Usage: "Detection and blasting of vulnerable web",
					},
				},
				Action: func(c *cli.Context) error {
					enter.NoPing = reflect.ValueOf(c.Value("noping")).Bool()
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					if reg.MatchString(c.Args().Get(0)) == true{
						enter.ScanHost = c.Args().Get(0)
					}
					if reflect.ValueOf(c.Value("cookie")).String() != ""{
						config.WebConfig.SetCookie = reflect.ValueOf(c.Value("cookie")).String()
					}
					if reflect.ValueOf(c.Value("proxy")).String() != ""{
						config.WebConfig.SetProxy = reflect.ValueOf(c.Value("proxy")).String()
					}
					if reflect.ValueOf(c.Value("port")).String() != ""{
						enter.Ports = reflect.ValueOf(c.Value("port")).String()
					}
					enter.Fragile = reflect.ValueOf(c.Value("fragile")).Bool()
					enter.ScanType = "webscan"
					return nil
				},
			},
			{
				Name:"oxidscan",
				Usage: "Obtain the network card address on the windows remote host through oxid",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "thread",
						Value: 50,
						Usage: "set gorouite for fscanX",

					},
					&cli.BoolFlag{
						Name: "noping",
						Value: false,
						Usage: "whether to use ping command",
					},
				},
				Action: func(c *cli.Context) error {
					enter.NoPing = reflect.ValueOf(c.Value("noping")).Bool()
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					if reg.MatchString(c.Args().Get(0)) == true{
						enter.ScanHost = c.Args().Get(0)
					}
					enter.ScanType = "oxidscan"
					return nil
				},
			},
			{
				Name:"hostscan",
				Usage: "The scan finds the surviving host and outputs details",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "thread",
						Value: 50,
						Usage: "set gorouite for fscanX",

					},
					&cli.BoolFlag{
						Name: "noping",
						Value: false,
						Usage: "whether to use ping command",
					},
				},
				Action: func(c *cli.Context) error {
					enter.NoPing = reflect.ValueOf(c.Value("noping")).Bool()
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					if reg.MatchString(c.Args().Get(0)) == true{
						enter.ScanHost = c.Args().Get(0)
					}
					enter.ScanType = "hostscan"
					return nil
				},
			},
			{
				Name:"portscan",
				Usage: "Port scans are performed after the scan completes for the surviving host and details are output",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "thread",
						Value: 50,
						Usage: "set gorouite for fscanX",

					},
					&cli.BoolFlag{
						Name: "noping",
						Value: false,
						Usage: "Whether to use ping command",
					},
					&cli.StringFlag{
						Name: "port",
						Usage: "The list of ports to be scanned",
					},
					&cli.BoolFlag{
						Name: "fragile",
						Value: false,
						Usage: "Detection and blasting of vulnerable ports",
					},
					&cli.BoolFlag{
						Name: "netbios",
						Value: false,
						Usage: "Detects netbios and output details",
					},
					&cli.StringFlag{
						Name: "sk",
						Usage: "Use ssh key certification (as --sk id_rsa)",
					},
					&cli.StringFlag{
						Name: "rf",
						Usage: "redis file to write sshkey file (as --rf id_rsa.pub)",
					},
					&cli.StringFlag{
						Name: "rs",
						Usage: "redis shell to write cron file (as: --rs 192.168.1.1:6666)",
					},
				},
				Action: func(c *cli.Context) error {
					enter.NoPing = reflect.ValueOf(c.Value("noping")).Bool()
					enter.Fragile = reflect.ValueOf(c.Value("fragile")).Bool()
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					enter.Netbios = reflect.ValueOf(c.Value("netbios")).Bool()
					if reg.MatchString(c.Args().Get(0)) == true{
						enter.ScanHost = c.Args().Get(0)
					}
					enter.ScanType = "portscan"
					if reflect.ValueOf(c.Value("port")).String() != "" {
						enter.Ports = reflect.ValueOf(c.Value("port")).String()
					}
					if reflect.ValueOf(c.Value("sk")).String() != ""{
						enter.Sshkey = reflect.ValueOf(c.Value("sshkey")).String()
					}
					if reflect.ValueOf(c.Value("rf")).String() != ""{
						config.RedisFile = reflect.ValueOf(c.Value("rf")).String()
					}
					if reflect.ValueOf(c.Value("rs")).String() != ""{
						config.RedisFile = reflect.ValueOf(c.Value("rs")).String()
					}
					return nil
				},
			},
			{
				Name: "ms17010",
				Usage: "The target is first tested for survival before the eternal blue is tested",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "thread",
						Value: 50,
						Usage: "set gorouite for fscanX",
					},
					&cli.BoolFlag{
						Name: "noping",
						Value: false,
						Usage: "whether to use ping command",
					},
				},
				Action: func(c *cli.Context) error {
					enter.NoPing = reflect.ValueOf(c.Value("noping")).Bool()
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					if reg.MatchString(c.Args().Get(0)) == true{
						enter.ScanHost = c.Args().Get(0)
					}
					enter.ScanType = "ms17010"
					return nil
				},
			},
			{
				Name: "smbghost",
				Usage: "The target is first tested for survival before the CVE-2020-0796 is tested",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name: "thread",
						Value: 50,
						Usage: "set gorouite for fscanX",
					},
					&cli.BoolFlag{
						Name: "noping",
						Value: false,
						Usage: "whether to use ping command",
					},
				},
				Action: func(c *cli.Context) error {
					enter.NoPing = reflect.ValueOf(c.Value("noping")).Bool()
					enter.Thread = reflect.ValueOf(c.Value("thread")).Int()
					if reg.MatchString(c.Args().Get(0)) == true {
						enter.ScanHost = c.Args().Get(0)
					}
					enter.ScanType = "smbghost"
					return nil
				},
			},
		},
	}
	app.Usage = "A Large killer focused on intranet scanning"
	 _ = app.Run(os.Args)

	 Scanner(enter)
}
