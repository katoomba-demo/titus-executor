package main

import (
	"context"
	"github.com/Netflix/titus-executor/vk"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
)

func main() {
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := vk.NewVk()
	if err != nil {
		panic(err)
	}

	err = p.Start(ctx)
	if err != nil {
		panic(err)
	}
}
