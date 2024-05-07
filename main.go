package main

import "flag"

func main() {
	var fw, netInterface, stage1, stage2 string
	flag.StringVar(&fw, "fw", "950", "PS4 firmware")
	flag.StringVar(&netInterface, "interface", "", "network interface")
	flag.StringVar(&stage1, "stage1", "stage1/stage1.bin", "stage1.bin")
	flag.StringVar(&stage2, "stage2", "stage2/stage2.bin", "stage2.bin")
	flag.Parse()

	_ = FirmwareOffsets[fw]

}
