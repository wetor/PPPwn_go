package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Server struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Inject struct {
	TargetMAC  string `yaml:"target_mac"`
	Firmware   string `yaml:"firmware"`
	Stage1File string `yaml:"stage1_file"`
	Stage2File string `yaml:"stage2_file"`
}

type Config struct {
	Timeout   int     `yaml:"receive_timeout"`
	Debug     bool    `yaml:"debug"`
	LogFile   string  `yaml:"log_file"`
	Retry     bool    `yaml:"retry"`
	RetryWait int     `yaml:"retry_wait"`
	Interface string  `yaml:"interface"`
	Injects   *Inject `yaml:"injects"`
}

func (c *Config) Default() {
	if c.Timeout == 0 {
		c.Timeout = 30
	}
	if c.RetryWait == 0 {
		c.RetryWait = 5
	}
}

var Conf *Config

func LoadConfig(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	Conf = &Config{}
	err = yaml.Unmarshal(data, Conf)
	if err != nil {
		return err
	}
	Conf.Default()
	d, _ := yaml.Marshal(Conf)
	fmt.Printf("-- CONFIG ------------------------------------\n%s\n----------------------------------------------\n", string(d))
	return nil
}
