package main

import (
	"log"
	"os"
	"regexp"
)

// config for XSS detection
type Config struct {
	PayloadPatterns []string `json:"payload_patterns"`
}

var (
	xssPatterns []*regexp.Regexp
	logger      *log.Logger
)

// Initialize logging and XSS patterns
func init() {
	logFile, err := os.OpenFile("sxx_logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	logger = log.New(logFile, "XSS Detetction: ", log.LstdFlags)

	// Default Xss payload patterns

}
