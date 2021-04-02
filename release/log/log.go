package main

import (
	"fmt"
	"log"
	"os"
)

const (
    LogDebug = iota
	LogInfo
	LogWarning
	LogError
)

var levelPrefix = map[int]string{LogInfo: "INFO ", LogDebug: "DEBUG ", LogWarning: "WARNING ", LogError: "ERROR "}

type OpsgenieFileLogger struct {
	Logger   *log.Logger
	LogFile  *os.File
	LogLevel int
}

func NewFileLogger(file *os.File, level int) *OpsgenieFileLogger {
	return &OpsgenieFileLogger{
		Logger:   log.New(file, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lmsgprefix),
		LogFile:  file,
		LogLevel: level,
	}
}

func (opsgenieFileLogger *OpsgenieFileLogger) log(level int, msg string) {
	if opsgenieFileLogger.Logger != nil {
		if level >= opsgenieFileLogger.LogLevel {
			opsgenieFileLogger.Logger.SetPrefix(levelPrefix[level])
			opsgenieFileLogger.Logger.Print(msg)
		}
	}
}

func (opsgenieFileLogger *OpsgenieFileLogger) Error(msg ...interface{}) {
	opsgenieFileLogger.log(LogError, fmt.Sprintln(msg...))
}

func (opsgenieFileLogger *OpsgenieFileLogger) Info(msg ...interface{}) {
	opsgenieFileLogger.log(LogInfo, fmt.Sprintln(msg...))
}

func (opsgenieFileLogger *OpsgenieFileLogger) Warning(msg ...interface{}) {
	opsgenieFileLogger.log(LogWarning, fmt.Sprintln(msg...))
}

func (opsgenieFileLogger *OpsgenieFileLogger) Debug(msg ...interface{}) {
	opsgenieFileLogger.log(LogDebug, fmt.Sprintln(msg...))
}