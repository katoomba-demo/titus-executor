package main

import (
	"context"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/vk"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"gopkg.in/urfave/cli.v1"
	"os"
	"time"
)

func run(dockerCfg *docker.Config, cfg *config.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()


	cfg.UseNewNetworkDriver = true
	p, err := vk.NewVk(dockerCfg, cfg)
	if err != nil {
		return err
	}

	err = p.Start(ctx)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))

	app := cli.NewApp()
	app.Name = "titus-kubernoots"
	defer time.Sleep(1 * time.Second)
	cfg, cfgFlags := config.NewConfig()
	app.Flags = []cli.Flag{}
	app.Flags = append(app.Flags, cfgFlags...)

	dockerCfg, dockerCfgFlags := docker.NewConfig()
	app.Flags = append(app.Flags, dockerCfgFlags...)

	app.Action = func(c *cli.Context) error {
		return cli.NewExitError(run(dockerCfg, cfg), 1)
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}

}
