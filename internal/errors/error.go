package errors

import "fmt"

var (
	LCPNegotiationError  = fmt.Errorf("LCPNegotiationError")
	IPCPNegotiationError = fmt.Errorf("IPCPNegotiationError")
	PPPNegotiationError  = fmt.Errorf("PPPNegotiationError")
)

var (
	KASLRLeakInvalidError        = fmt.Errorf("KASLRLeakInvalidError")
	ScanningCorruptedFailedError = fmt.Errorf("ScanningCorruptedFailedError")
	ReceiveTimeoutError          = fmt.Errorf("ReceiveTimeoutError")
)

func IsTimeout(err error) bool {
	return err == ReceiveTimeoutError
}
