package web

import "github.com/wetor/PPPwn_go/internal/logger"

const (
	CommandLogPause     = "log_pause"
	CommandLogResume    = "log_resume"
	CommandLogTerminate = "log_terminate"
)

type Command struct {
	Action        string `json:"action"`
	actionFuncMap map[string]func() error
}

func (c *Command) Init() {
	c.Action = ""
	c.actionFuncMap = make(map[string]func() error)
}

func (c *Command) SetActionFunc(action string, f func() error) {
	c.actionFuncMap[action] = f
}

func (c *Command) Execute() error {
	switch c.Action {
	case CommandLogPause:
		logger.PauseLogNotify()
	case CommandLogResume:
		logger.EnableLogNotify()
	case CommandLogTerminate:
	}
	if f, ok := c.actionFuncMap[c.Action]; ok {
		err := f()
		if err != nil {
			return err
		}
	}
	return nil
}
