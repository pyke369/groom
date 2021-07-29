package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
)

const (
	progname = "groom"
	version  = "1.1.1"
)

var (
	config          *uconfig.UConfig
	logger, slogger *ulog.ULog
	mode            string
	domains         = Domains()
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configuration>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	if config, err = uconfig.New(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration syntax error: %v - aborting\n", err)
		os.Exit(2)
	}
	slogger = ulog.New(config.GetString(progname+".log.access", ""))
	mode = config.GetString(progname+".mode", "agent")
	logger = ulog.New(config.GetString(progname+".log.system", "console(output=stdout)"))
	logger.Info(map[string]interface{}{"mode": mode, "event": "start", "config": os.Args[1], "pid": os.Getpid(), "version": version})

	switch mode {
	case "server":
		go server_run()
	case "agent":
		go agent_run()
	default:
		fmt.Fprintf(os.Stderr, "neither in server nor agent running mode - aborting\n")
		os.Exit(3)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for {
		<-signals
		if _, err = uconfig.New(os.Args[1]); err == nil {
			config.Load(os.Args[1])
			slogger.Load(config.GetString(progname+".log.access", ""))
			logger.Load(config.GetString(progname+".log.system", "console(output=stdout)"))
			logger.Info(map[string]interface{}{"mode": mode, "event": "reload", "config": os.Args[1], "pid": os.Getpid(), "version": version})
		} else {
			logger.Info(map[string]interface{}{"mode": mode, "event": "reload", "config": os.Args[1], "error": fmt.Sprintf("%v", err)})
		}
	}
}
