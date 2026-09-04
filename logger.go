package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

type Logger struct {
	level  LogLevel
	json   bool
	mu     sync.Mutex
	output *log.Logger
}

type LogEntry struct {
	Time    string                 `json:"time"`
	Level   string                 `json:"level"`
	Message string                 `json:"message"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

func NewLogger(jsonOutput bool, levelStr string) *Logger {
	level := InfoLevel
	switch strings.ToLower(levelStr) {
	case "debug":
		level = DebugLevel
	case "info":
		level = InfoLevel
	case "warn":
		level = WarnLevel
	case "error":
		level = ErrorLevel
	}

	return &Logger{
		level:  level,
		json:   jsonOutput,
		output: log.New(os.Stderr, "", 0),
	}
}

func (l *Logger) Debug(msg string, fields ...interface{}) {
	l.log(DebugLevel, msg, fields...)
}

func (l *Logger) Info(msg string, fields ...interface{}) {
	l.log(InfoLevel, msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.log(WarnLevel, msg, fields...)
}

func (l *Logger) Error(msg string, fields ...interface{}) {
	l.log(ErrorLevel, msg, fields...)
}

func (l *Logger) log(level LogLevel, msg string, fields ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.json {
		entry := LogEntry{
			Time:    time.Now().Format(time.RFC3339Nano),
			Level:   l.levelString(level),
			Message: msg,
			Fields:  l.parseFields(fields...),
		}
		data, _ := json.Marshal(entry)
		l.output.Println(string(data))
	} else {
		prefix := l.levelPrefix(level)
		l.output.Printf("%s %s %s", time.Now().Format("2006-01-02 15:04:05"), prefix, msg)
	}
}

func (l *Logger) parseFields(fields ...interface{}) map[string]interface{} {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]interface{})
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			key, ok := fields[i].(string)
			if ok {
				result[key] = fields[i+1]
			}
		}
	}
	return result
}

func (l *Logger) levelString(level LogLevel) string {
	switch level {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func (l *Logger) levelPrefix(level LogLevel) string {
	switch level {
	case DebugLevel:
		return "\033[36mDEBUG\033[0m"
	case InfoLevel:
		return "\033[32mINFO\033[0m"
	case WarnLevel:
		return "\033[33mWARN\033[0m"
	case ErrorLevel:
		return "\033[31mERROR\033[0m"
	default:
		return "UNKNOWN"
	}
}
