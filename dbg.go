package main

import (
	"log"
	"os"
)

var (
	dbgLevel int
	dbgLogger *log.Logger
)

func dbgSet(lvl int) {
	dbgLevel = lvl
}

func dbg(lvl int, fmt string, v ...interface{}) {
	if lvl <= dbgLevel {
		dbgLogger.Printf(fmt, v...)
	}
}

func dbgErr(lvl int, err error) {
	if lvl <= dbgLevel {
		dbgLogger.Printf("error: %s\n", err.Error())
	}
}

func die(fmt string, v ...interface{}) {
	dbgLogger.Fatalf(fmt, v...)
}

func dieErr(msg string, err error) {
	dbgLogger.Fatalf("fatal error: %s: %s", msg, err.Error())
}

func init() {
	dbgLogger = log.New(os.Stderr, "", log.LstdFlags | log.LUTC)
}
