package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger provides logging functionality
type Logger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	verbose     bool
	logFile     *os.File
	nextReqID   uint64
	reqIDMap    map[string]string // Maps clientIP:host to request ID
	mu          sync.Mutex        // Mutex to protect concurrent access to reqIDMap and nextReqID
}

// NewLogger creates a new logger
func NewLogger(logDir string, verbose bool) (*Logger, error) {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log file
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logPath := filepath.Join(logDir, fmt.Sprintf("certmitm_%s.log", timestamp))
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %v", err)
	}

	// Create multi-writer for console and file
	infoWriter := io.MultiWriter(os.Stdout, logFile)
	errorWriter := io.MultiWriter(os.Stderr, logFile)
	debugWriter := io.MultiWriter(logFile)
	if verbose {
		debugWriter = io.MultiWriter(os.Stdout, logFile)
	}

	// Create loggers
	infoLogger := log.New(infoWriter, "INFO: ", log.Ldate|log.Ltime)
	errorLogger := log.New(errorWriter, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	debugLogger := log.New(debugWriter, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)

	return &Logger{
		infoLogger:  infoLogger,
		errorLogger: errorLogger,
		debugLogger: debugLogger,
		verbose:     verbose,
		logFile:     logFile,
		nextReqID:   1,
		reqIDMap:    make(map[string]string),
	}, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// Infof logs an info message
func (l *Logger) Infof(format string, v ...interface{}) {
	l.infoLogger.Printf(format, v...)
}

// InfoWithRequestIDf logs an info message with a request ID
func (l *Logger) InfoWithRequestIDf(reqID, format string, v ...interface{}) {
	l.infoLogger.Printf("[%s] "+format, append([]interface{}{reqID}, v...)...)
}

// Errorf logs an error message
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
}

// ErrorWithRequestIDf logs an error message with a request ID
func (l *Logger) ErrorWithRequestIDf(reqID, format string, v ...interface{}) {
	l.errorLogger.Printf("[%s] "+format, append([]interface{}{reqID}, v...)...)
}

// Debugf logs a debug message
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.verbose {
		l.debugLogger.Printf(format, v...)
	}
}

// DebugWithRequestIDf logs a debug message with a request ID
func (l *Logger) DebugWithRequestIDf(reqID, format string, v ...interface{}) {
	if l.verbose {
		l.debugLogger.Printf("[%s] "+format, append([]interface{}{reqID}, v...)...)
	}
}

// Fatalf logs a fatal message and exits
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
	os.Exit(1)
}

// LogRequest logs an HTTP request
func (l *Logger) LogRequest(clientIP, method, host, path string, isSecure bool) {
	protocol := "HTTP"
	if isSecure {
		protocol = "HTTPS"
	}

	// Get or generate a request ID
	reqID := l.GetRequestID(clientIP, host)

	l.Infof("[%s][%s] %s %s %s from %s", reqID, protocol, method, host, path, clientIP)
	l.Debugf("[%s] Full request: %s %s %s%s from %s", reqID, protocol, method, host, path, clientIP)
}

// LogCertificateTest logs a certificate test
func (l *Logger) LogCertificateTest(clientIP, host string, testType string, accepted bool) {
	result := "REJECTED"
	if accepted {
		result = "ACCEPTED"
	}
	reqID := l.GetRequestID(clientIP, host)
	l.Infof("[%s][CERT] %s test for %s from %s: %s", reqID, testType, host, clientIP, result)
}

// GetRequestID returns a request ID for a client IP and host
// Always generates a new unique request ID for each call
func (l *Logger) GetRequestID(clientIP, host string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := clientIP + ":" + host

	// Generate a new request ID
	reqID := fmt.Sprintf("REQ-%04X", l.nextReqID)
	l.nextReqID++

	// Store the request ID
	l.reqIDMap[key] = reqID

	return reqID
}

// ClearRequestID removes a request ID for a client IP and host
func (l *Logger) ClearRequestID(clientIP, host string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := clientIP + ":" + host
	delete(l.reqIDMap, key)
}
