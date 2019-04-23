package main

import (
	"context"
	"fmt"
	"github.com/Netflix/titus-executor/vk"
	"github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type cliOptions struct {
	address string
	logLevel      string
}


func main() {
	var options cliOptions
	app := cli.NewApp()
	app.Name = "titus-virtual-kubelet-web"
	defer time.Sleep(1 * time.Second)
	// avoid os.Exit as much as possible to let deferred functions run

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "address",
			Value:       "0.0.0.0:7212",
			Destination: &options.address,
		},
		cli.StringFlag{
			Name:        "log-level",
			Value:       "info",
			Destination: &options.logLevel,
		},
	}


	app.Action = func(c *cli.Context) error {
		return cli.NewExitError(mainWithError(c, &options), 1)
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func mainWithError(c *cli.Context, options *cliOptions) error { // nolint: gocyclo
	defer logrus.Info("titus virtual kubelet terminated")

	switch options.logLevel {
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	default:
		return fmt.Errorf("Unknown log level: %s", options.logLevel)
	}

	virtualKubelet, err := vk.NewVk()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr: options.address,
		Handler: virtualKubelet,
	}


	waitForShutdown  := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(waitForShutdown)
		term := make(chan os.Signal, 1) // buffered so we don't miss a signal
		signal.Notify(term, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
		<-term
		logrus.Warning("Terminating titus virtual kubelet")
		ctx2, cancel2 := context.WithTimeout(ctx, time.Second * 30)
		defer cancel2()
		if err := srv.Shutdown(ctx2); err != nil {
			logrus.WithError(err).Warning("Failed to shutdown")
		}
	}()

	if err := virtualKubelet.Maintain(ctx); err != nil {
		return err
	}

	logrus.Info("Starting titus virtual kubelet")
	if err := srv.ListenAndServe(); err == http.ErrServerClosed {
		select {
			case <-waitForShutdown:
			case <-time.After(time.Minute):
		}
		return nil
	} else {
		return err
	}
}

