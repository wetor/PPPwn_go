package main

type PPP interface {
	L2socket(iface, filter string)
}
