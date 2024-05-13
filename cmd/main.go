package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/wetor/PPPwn_go/internal/exploit"
	"github.com/wetor/PPPwn_go/internal/utils"
)

func main() {
	var fw, netInterface, stage1, stage2 string
	var list bool
	flag.BoolVar(&list, "list", false, "list net interface")
	flag.StringVar(&fw, "fw", "", "PS4 firmware")
	flag.StringVar(&netInterface, "interface", "", "net interface name")
	flag.StringVar(&stage1, "stage1", "stage1/stage1.bin", "stage1.bin")
	flag.StringVar(&stage2, "stage2", "stage2/stage2.bin", "stage2.bin")
	flag.Parse()

	fmt.Println("[+] PPPwn - PlayStation 4 PPPoE RCE by theflow")
	fmt.Println("[+] PPPwn_go - Go rewrite version by wetor")

	if list {
		utils.ShowInterfaces()
		return
	}

	offs, ok := exploit.FirmwareOffsets[fw]
	if !ok {
		log.Fatalf("fw '%s' not supported, supported firmwares %v", fw, exploit.SupportedFirmware)
	}

	if netInterface == "" {
		log.Fatal("'-interface' required. use '-list' show all net interface name")
	}

	stage1Data, err := os.ReadFile(stage1)
	if err != nil {
		log.Fatal(err)
	}
	stage2Data, err := os.ReadFile(stage2)
	if err != nil {
		log.Fatal(err)
	}
	e := exploit.NewExploit(offs, netInterface, stage1Data, stage2Data)
	e.Run()
}
