package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger is a structured logger with file rotation capabilities
type Logger struct {
	*logrus.Logger
	logFile       *lumberjack.Logger
	runLogDir     string
	currentRunLog *os.File
	mu            sync.Mutex
}

// Config contains logger configuration
type Config struct {
	LogDir     string
	EnableFile bool
	Level      string
	MaxSize    int // MB
	MaxBackups int
	MaxAge     int // days
	Compress   bool
}

// New creates a new logger instance
func New(config Config) *Logger {
	logger := &Logger{
		Logger:    logrus.New(),
		runLogDir: filepath.Join(config.LogDir, "runs"),
	}

	// Configure formatter
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:    true,
		DisableColors:    false,
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05",
	})

	// Set log level
	level := logrus.InfoLevel
	switch config.Level {
	case "debug":
		level = logrus.DebugLevel
	case "info":
		level = logrus.InfoLevel
	case "warn":
		level = logrus.WarnLevel
	case "error":
		level = logrus.ErrorLevel
	}
	logger.SetLevel(level)

	// Configure output
	if config.EnableFile {
		// Ensure log directory exists
		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
			return logger
		}

		// Ensure run logs directory exists
		if err := os.MkdirAll(logger.runLogDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create run logs directory: %v\n", err)
		}

		// Setup log file with rotation
		logger.logFile = &lumberjack.Logger{
			Filename:   filepath.Join(config.LogDir, "dnsniper.log"),
			MaxSize:    config.MaxSize,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge,
			Compress:   config.Compress,
			LocalTime:  true,
		}

		// Create multi-writer to log to both file and stderr
		mw := io.MultiWriter(logger.logFile, os.Stderr)
		logger.SetOutput(mw)
	}

	return logger
}

// SetRunID sets the current run ID for separate run logging
func (l *Logger) SetRunID(runID int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Close any existing run log file
	if l.currentRunLog != nil {
		l.currentRunLog.Close()
		l.currentRunLog = nil
	}

	// If no run ID, just return
	if runID <= 0 {
		return nil
	}

	// Create run logs directory if it doesn't exist
	if err := os.MkdirAll(l.runLogDir, 0755); err != nil {
		return fmt.Errorf("failed to create run logs directory: %w", err)
	}

	// Open a new file for this run
	runLogFilename := fmt.Sprintf("run_%d.log", runID)
	filename := filepath.Join(l.runLogDir, filepath.Base(runLogFilename))

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open run log file: %w", err)
	}

	l.currentRunLog = f

	// Create a hook for run-specific logging
	hook := &runLogHook{file: f}
	l.AddHook(hook)

	return nil
}

// Close cleanly closes the logger
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentRunLog != nil {
		l.currentRunLog.Close()
		l.currentRunLog = nil
	}

	// We don't need to close logFile as lumberjack handles it
}

// runLogHook is a logrus hook that writes to the run-specific log file
type runLogHook struct {
	file *os.File
	mu   sync.Mutex
}

// Levels returns the log levels this hook should fire for
func (h *runLogHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}

// Fire is called when a log event occurs
func (h *runLogHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.file == nil {
		return nil
	}

	line, err := entry.String()
	if err != nil {
		return err
	}

	_, err = h.file.WriteString(line)
	if err != nil {
		// Don't fail on write errors, just return the error
		return fmt.Errorf("failed to write to run log: %w", err)
	}

	return nil
}
