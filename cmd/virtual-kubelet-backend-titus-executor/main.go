package main

import (
	"context"

	"github.com/Netflix/titus-executor/tag"

	"github.com/pkg/errors"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/vk/backend"

	"time"

	"github.com/Netflix/titus-executor/uploader"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"gopkg.in/urfave/cli.v1"

	"os"
)

func main() {
	var podFileName string
	var statusPipe string

	var flags = []cli.Flag{
		cli.StringFlag{
			Name:        "pod",
			Destination: &podFileName,
			Usage:       "The location of the pod spec file (json-ish)",
		},
		cli.StringFlag{
			Name:        "status",
			Destination: &statusPipe,
			Usage:       "The location of the status pipe",
		},
	}

	app := cli.NewApp()
	app.Name = "virtual-kubelet-backend-titus-executor"
	// avoid os.Exit as much as possible to let deferred functions run
	defer time.Sleep(1 * time.Second)

	dockerCfg, dockerCfgFlags := docker.NewConfig()
	app.Flags = append(flags, dockerCfgFlags...)

	cfg, cfgFlags := config.NewConfig()
	app.Flags = append(app.Flags, cfgFlags...)
	app.Action = func(c *cli.Context) error {
		if err := mainWithError(podFileName, statusPipe, dockerCfg, cfg); err != nil {
			return cli.NewExitError(err, 1)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}

}

func mainWithError(podFileName string, statusPipe string, dockerCfg *docker.Config, cfg *config.Config) error {
	logrus.SetLevel(logrus.DebugLevel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))
	ctx = log.WithLogger(ctx, log.L)

	podFile, err := os.Open(podFileName)
	if err != nil {
		panic(err)
	}

	pod, err := backend.PodFromFile(podFile)
	if err != nil {
		panic(err)
	}
	log.G(ctx).WithField("pod", pod.Name).Debugf("Got pod %v", pod)

	pipe, err := os.OpenFile(statusPipe, os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	defer pipe.Close()
	log.G(ctx).WithField("pod", pod.Name).Debugf("Got pipe %v", statusPipe)

	log.G(ctx).WithField("pod", pod.Name).Debug("Starting metrics reporting...")
	m := metrics.New(ctx, logrus.StandardLogger(), tag.Defaults)
	m = runner.NewReporter(m)
	defer m.Flush()

	log.G(ctx).WithField("pod", pod.Name).Debugf("Getting uploaders from %+v", cfg.S3Uploaders)
	var logUploaders *uploader.Uploaders
	if logUploaders, err = uploader.NewUploaders(cfg, m); err != nil {
		return errors.Wrap(err, "cannot create log uploaders")
	}
	log.G(ctx).WithField("pod", pod.Name).Debugf("Got log uploaders %+v", logUploaders)

	dockerRunner, err := runner.New(ctx, m, logUploaders, *cfg, *dockerCfg)
	if err != nil {
		return errors.Wrap(err, "cannot create Titus executor")
	}

	err = backend.RunWithBackend(ctx, dockerRunner, pipe, pod)
	if err != nil {
		log.G(ctx).WithError(err).Fatal("Could not run container")
	}
	return nil
}
