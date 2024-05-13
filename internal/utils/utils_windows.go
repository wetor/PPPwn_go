//go:build windows

package utils

import "syscall"

func TimeBeginPeriod() {
	winmmDLL := syscall.NewLazyDLL("winmm.dll")
	procTimeBeginPeriod := winmmDLL.NewProc("timeBeginPeriod")
	procTimeBeginPeriod.Call(uintptr(1))
}

func TimeEndPeriod() {
	winmmDLL := syscall.NewLazyDLL("winmm.dll")
	procTimeEndPeriod := winmmDLL.NewProc("timeEndPeriod")
	procTimeEndPeriod.Call(uintptr(1))
}
