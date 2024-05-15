package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wetor/PPPwn_go/cmd/common"
	"github.com/wetor/PPPwn_go/internal/exploit"
	"github.com/wetor/PPPwn_go/internal/logger"
	"github.com/wetor/PPPwn_go/internal/utils"
)

func main() {
	var fw, netInterface, stage1, stage2 string
	var list, ver bool
	flag.BoolVar(&list, "list", false, "list net interface")
	flag.BoolVar(&ver, "v", false, "show version")
	flag.StringVar(&fw, "fw", "", "PS4 firmware")
	flag.StringVar(&netInterface, "interface", "", "net interface name")
	flag.StringVar(&stage1, "stage1", "stage1/stage1.bin", "stage1.bin")
	flag.StringVar(&stage2, "stage2", "stage2/stage2.bin", "stage2.bin")
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

	offs, ok := exploit.FirmwareOffsets[fw]
	if !ok {
		logger.Fatalf("fw '%s' not supported, supported firmwares %v", fw, exploit.SupportedFirmware)
	}

	if netInterface == "" {
		logger.Fatalf("'-interface' required. use '-list' show all net interface name")
	}

	out, notify := logger.NewNotify()
	logger.Init(&logger.Options{
		File:  "log/log.log",
		Debug: false,
		Out:   out,
	})

	go func() {
		for {
			select {
			case data := <-notify:
				fmt.Printf("Recive: %s", data)
			}
		}
	}()

	stage1Data, err := os.ReadFile(stage1)
	if err != nil {
		logger.Fatal(err)
	}
	stage2Data, err := os.ReadFile(stage2)
	if err != nil {
		logger.Fatal(err)
	}

	e := exploit.NewExploit(offs, netInterface, stage1Data, stage2Data)
	e.Run()
}
