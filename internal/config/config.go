package config

import (
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
	Debug     bool      `yaml:"debug"`
	Server    *Server   `yaml:"server"`
	Interface string    `yaml:"interface"`
	Injects   []*Inject `yaml:"injects"`
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
	return nil
}
