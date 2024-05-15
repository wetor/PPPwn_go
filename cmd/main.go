package main

import (
	"flag"
	"fmt"

	"github.com/wetor/PPPwn_go/cmd/common"
	"github.com/wetor/PPPwn_go/internal/config"
	"github.com/wetor/PPPwn_go/internal/exploit"
	"github.com/wetor/PPPwn_go/internal/logger"
	"github.com/wetor/PPPwn_go/internal/utils"
)

func main() {
	var configFile, logFile string
	var fw, netInterface, stage1, stage2, targetMac string
	var list, ver bool

	flag.BoolVar(&list, "list", false, "list net interface")
	flag.BoolVar(&ver, "v", false, "show version")

	flag.StringVar(&configFile, "config", "config.yaml", "config yaml file")
	flag.StringVar(&fw, "fw", "", "PS4 firmware")
	flag.StringVar(&netInterface, "interface", "", "net interface name")
	flag.StringVar(&stage1, "stage1", "stage1/stage1.bin", "stage1.bin file path")
	flag.StringVar(&stage2, "stage2", "stage2/stage2.bin", "stage2.bin file path")
	flag.StringVar(&targetMac, "target_mac", "", "[optional] inject only this mac address")
	flag.StringVar(&logFile, "log", "", "[optional] output log file path")
	flag.Parse()

	fmt.Println("[+] PPPwn - PlayStation 4 PPPoE RCE by theflow")
	fmt.Println("[+] PPPwn_go - Go rewrite version by wetor")

	if ver {
		fmt.Printf("PPPwn_go %s", common.Version())
		return
	}

	if list {
		err := utils.ShowInterfaces()
		if err != nil {
			logger.Fatal(err)
		}
		return
	}

	if configFile != "" {
		err := config.LoadConfig(configFile)
		if err != nil {
			logger.Fatal(err)
		}
	} else {
		if netInterface == "" {
			logger.Fatalf("'--interface' required, use '-list' show all net interface name")
		}
		if fw == "" {
			logger.Fatalf("'--fw' required, supported firmwares %v", exploit.SupportedFirmware)
		}
		if !utils.IsExist(stage1) {
			logger.Fatalf("--stage1=%s file not exist", stage1)
		}
		if !utils.IsExist(stage2) {
			logger.Fatalf("--stage2=%s file not exist", stage2)
		}

		config.Conf = &config.Config{
			Debug: false,
			Server: &config.Server{
				Host: "0.0.0.0",
				Port: 8899,
			},
			Interface: netInterface,
			Injects: []*config.Inject{
				{
					TargetMAC:  targetMac,
					Firmware:   fw,
					Stage1File: stage1,
					Stage2File: stage2,
				},
			},
		}
	}

	out, notify := logger.NewNotify()
	logger.Init(&logger.Options{
		File:  logFile,
		Debug: false,
		Out:   out,
	})
	_ = notify

	inject := config.Conf.Injects[0]
	e := exploit.NewExploit(&exploit.Option{
		Interface: config.Conf.Interface,
		Inject:    inject,
	})
	e.Run()
}
