package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	var fw, netInterface, stage1, stage2 string
	flag.StringVar(&fw, "fw", "950", "PS4 firmware")
	flag.StringVar(&netInterface, "interface", "", "network interface")
	flag.StringVar(&stage1, "stage1", "stage1/stage1.bin", "stage1.bin")
	flag.StringVar(&stage2, "stage2", "stage2/stage2.bin", "stage2.bin")
	flag.Parse()
	offs, ok := FirmwareOffsets[fw]
	if !ok {
		log.Fatal("fw not found")
	}

	stage1Data, err := os.ReadFile(stage1)
	if err != nil {
		log.Fatal(err)
	}
	stage2Data, err := os.ReadFile(stage2)
	if err != nil {
		log.Fatal(err)
	}
	e := NewExploit(offs, netInterface, stage1Data, stage2Data)
	e.Run()
}
