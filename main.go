package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
)

const (
	progname = "groom"
	version  = "1.0.6"
)

var (
	config  *uconfig.UConfig
	logger  *ulog.ULog
	mode    string
	domains = Domains()
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
	mode = config.GetString(progname+".mode", "agent")
	logger = ulog.New(config.GetString(progname+".log", "console(output=stdout)"))
	logger.Info(map[string]interface{}{"mode": mode, "event": "start", "config": os.Args[1], "pid": os.Getpid(), "version": version})

	switch mode {
	case "server":
		server_run()
	case "agent":
		agent_run()
	default:
		fmt.Fprintf(os.Stderr, "neither in server nor agent running mode - aborting\n")
		os.Exit(3)
	}
}
