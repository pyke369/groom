package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/pyke369/golang-support/acl"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
	"github.com/pyke369/golang-support/uuid"
)

const (
	progname = "groom"
	version  = "1.2.3"
)

var (
	config           *uconfig.UConfig
	logger, slogger  *ulog.ULog
	mode             string
	domains          = Domains()
	instance, secret = uuid.BUUID(), uuid.BUUID()
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configuration> | password [<secret> [<salt>]]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	if os.Args[1] == "password" {
		pick, secret, salt := true, "", ""
		if len(os.Args) > 2 {
			secret = os.Args[2]
			pick = false
		} else {
			value := make([]byte, 32)
			if _, err := rand.Read(value); err == nil {
				secret = base64.RawURLEncoding.EncodeToString(value)
			}
		}
		if len(os.Args) > 3 {
			salt = os.Args[3]
		} else {
			value := make([]byte, 6)
			rand.Read(value)
			if _, err := rand.Read(value); err == nil {
				salt = base64.RawStdEncoding.EncodeToString(value)
			}
		}
		if len(secret) < 8 || len(salt) < 8 {
			fmt.Fprintf(os.Stderr, "provided secret and/or salt are too short - aborting\n")
			os.Exit(1)
		}
		fmt.Printf("%s", acl.Crypt512(secret, salt, 0))
		if pick {
			fmt.Printf(" - %s", secret)
		}
		fmt.Printf("\n")
		os.Exit(0)
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
