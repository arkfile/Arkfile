package logging

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var (
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
	WarningLogger *log.Logger
	DebugLogger   *log.Logger
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
)

type LogConfig struct {
	LogDir     string
	MaxSize    int64 // Maximum size of log file in bytes
	MaxBackups int   // Maximum number of old log files to retain
	LogLevel   LogLevel
}

func InitLogging(config *LogConfig) error {
	if config == nil {
		config = &LogConfig{
			LogDir:     "logs",
			MaxSize:    10 * 1024 * 1024, // 10MB
			MaxBackups: 5,
			LogLevel:   INFO,
		}
	}

	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create or open log file
	logFile := filepath.Join(config.LogDir, fmt.Sprintf("app_%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Configure loggers
	flags := log.Ldate | log.Ltime | log.LUTC

	// Configure loggers to write to the log file
	DebugLogger = log.New(file, "[DEBUG] ", flags)
	InfoLogger = log.New(file, "[INFO] ", flags)
	WarningLogger = log.New(file, "[WARNING] ", flags)
	ErrorLogger = log.New(file, "[ERROR] ", flags)

	// Start log rotation goroutine
	go monitorLogSize(config, logFile)

	return nil
}

// InitFallbackConsoleLogging initializes console-only loggers when file logging fails
func InitFallbackConsoleLogging() {
	// Configure loggers to write to stderr for systemd capture
	flags := log.Ldate | log.Ltime | log.LUTC

	DebugLogger = log.New(os.Stderr, "[DEBUG] ", flags)
	InfoLogger = log.New(os.Stderr, "[INFO] ", flags)
	WarningLogger = log.New(os.Stderr, "[WARNING] ", flags)
	ErrorLogger = log.New(os.Stderr, "[ERROR] ", flags)
}

func monitorLogSize(config *LogConfig, logFile string) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		if info, err := os.Stat(logFile); err == nil {
			if info.Size() > config.MaxSize {
				rotateLog(config, logFile)
			}
		}
	}
}

func rotateLog(config *LogConfig, logFile string) {
	// Rotate log files
	for i := config.MaxBackups - 1; i > 0; i-- {
		oldFile := fmt.Sprintf("%s.%d", logFile, i)
		newFile := fmt.Sprintf("%s.%d", logFile, i+1)
		os.Rename(oldFile, newFile)
	}

	// Rename current log file
	os.Rename(logFile, logFile+".1")

	// Create new log file
	InitLogging(config)
}

// Log formats and writes log messages with source file information - NO LEVEL FILTERING
func Log(level LogLevel, format string, v ...interface{}) {
	_, file, line, _ := runtime.Caller(2)
	message := fmt.Sprintf("%s:%d: %s", filepath.Base(file), line, fmt.Sprintf(format, v...))

	// ALWAYS output logs regardless of configured level - no more filtering!
	switch level {
	case DEBUG:
		if DebugLogger != nil {
			DebugLogger.Print(message)
		} else {
			log.Printf("DEBUG: %s", message)
		}
	case INFO:
		if InfoLogger != nil {
			InfoLogger.Print(message)
		} else {
			log.Printf("INFO: %s", message)
		}
	case WARNING:
		if WarningLogger != nil {
			WarningLogger.Print(message)
		} else {
			log.Printf("WARNING: %s", message)
		}
	case ERROR:
		if ErrorLogger != nil {
			ErrorLogger.Print(message)
		} else {
			log.Printf("ERROR: %s", message)
		}
	}
}
