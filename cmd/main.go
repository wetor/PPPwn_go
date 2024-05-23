package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/wetor/PPPwn_go/cmd/common"
	"github.com/wetor/PPPwn_go/internal/config"
	"github.com/wetor/PPPwn_go/internal/exploit"
	"github.com/wetor/PPPwn_go/internal/logger"
	"github.com/wetor/PPPwn_go/internal/utils"
)

func main() {
	var configFile, logFile string
	var fw, netInterface, stage1, stage2, targetMac string
	var list, ver, debug, retry bool
	var recvTimeout, retryWait int

	flag.BoolVar(&list, "list", false, "list net interface")
	flag.BoolVar(&ver, "v", false, "show version")
	flag.BoolVar(&debug, "debug", false, "debug mod(more logs)")

	flag.StringVar(&configFile, "config", "", "config yaml file")
	flag.StringVar(&fw, "fw", "", "PS4 firmware")
	flag.StringVar(&netInterface, "interface", "", "net interface name")
	flag.StringVar(&stage1, "stage1", "stage1/stage1.bin", "stage1.bin file path")
	flag.StringVar(&stage2, "stage2", "stage2/stage2.bin", "stage2.bin file path")
	flag.StringVar(&targetMac, "target_mac", "", "[optional] inject only this mac address")
	flag.StringVar(&logFile, "log", "", "[optional] output log file path")
	flag.BoolVar(&retry, "retry", false, "[optional] retry after retry_wait seconds of failure")
	flag.IntVar(&retryWait, "retry_wait", 5, "[optional] retry after wait seconds of failure")
	flag.IntVar(&recvTimeout, "receive_timeout", 30, "[optional] main steps timeout second")
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
			Timeout:   recvTimeout,
			Debug:     debug,
			LogFile:   logFile,
			Retry:     retry,
			RetryWait: retryWait,
			Interface: netInterface,
			Injects: &config.Inject{
				TargetMAC:  targetMac,
				Firmware:   fw,
				Stage1File: stage1,
				Stage2File: stage2,
			},
		}
	}

	out, _ := logger.NewNotify()
	logger.Init(&logger.Options{
		File:  config.Conf.LogFile,
		Debug: config.Conf.Debug,
		Out:   out,
	})

	inject := config.Conf.Injects

	stage1Data, err := os.ReadFile(inject.Stage1File)
	if err != nil {
		logger.Fatal(err)
	}
	stage2Data, err := os.ReadFile(inject.Stage2File)
	if err != nil {
		logger.Fatal(err)
	}

	e := exploit.NewExploit(&exploit.Option{
		Timeout:    config.Conf.Timeout,
		Interface:  config.Conf.Interface,
		Stage1Data: stage1Data,
		Stage2Data: stage2Data,
		Inject:     inject,
	})

	utils.TimeBeginPeriod()
	defer utils.TimeEndPeriod()

	for {
		err = e.Run()
		if err != nil {
			if config.Conf.Retry {
				_ = e.End()
				fmt.Println()
				logger.Infof("[+] retry after %ds...", config.Conf.RetryWait)
				time.Sleep(time.Duration(config.Conf.RetryWait) * time.Second)
			} else {
				logger.Fatal(err)
				break
			}
		} else {
			break
		}
	}
}
