package common

import "fmt"

var (
	version   = "dev"
	buildTime = "dev"
)

func Version() string {
	return fmt.Sprintf("%s-%s", version, buildTime)
}
