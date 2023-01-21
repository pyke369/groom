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
	PROGNAME = "groom"
	VERSION  = "1.2.3"
)

var (
	Config           *uconfig.UConfig
	Logger           *ulog.ULog
	AccessLogger     *ulog.ULog
	Mode             string
	Domains          = NewDomains()
	Instance, Secret = uuid.BUUID(), uuid.BUUID()
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

	if Config, err = uconfig.New(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration syntax error: %v - aborting\n", err)
		os.Exit(2)
	}
	AccessLogger = ulog.New(Config.GetString(PROGNAME+".log.access", ""))
	Mode = Config.GetString(PROGNAME+".mode", "agent")
	Logger = ulog.New(Config.GetString(PROGNAME+".log.system", "console(output=stdout)"))
	Logger.Info(map[string]interface{}{"mode": Mode, "event": "start", "config": os.Args[1], "pid": os.Getpid(), "version": VERSION})

	switch Mode {
	case "server":
		go ServerRun()
	case "agent":
		go AgentRun()
	default:
		fmt.Fprintf(os.Stderr, "neither in server nor agent running mode - aborting\n")
		os.Exit(3)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	for {
		<-signals
		if _, err = uconfig.New(os.Args[1]); err == nil {
			Config.Load(os.Args[1])
			AccessLogger.Load(Config.GetString(PROGNAME+".log.access", ""))
			Logger.Load(Config.GetString(PROGNAME+".log.system", "console(output=stdout)"))
			Logger.Info(map[string]interface{}{"mode": Mode, "event": "reload", "config": os.Args[1], "pid": os.Getpid(), "version": VERSION})
		} else {
			Logger.Info(map[string]interface{}{"mode": Mode, "event": "reload", "config": os.Args[1], "error": fmt.Sprintf("%v", err)})
		}
	}
}
