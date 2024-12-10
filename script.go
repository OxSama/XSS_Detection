package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	PayloadPatterns []string `json:"payload_patterns"`
}

var (
	xssPatterns []*regexp.Regexp
	logger      *log.Logger
)

func init() {
	logFile, err := os.OpenFile("xss_logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	logger = log.New(logFile, "XSS DETECTION: ", log.LstdFlags|log.LUTC|log.Lmicroseconds)

	defaultPatterns := []string{
		`<script>.*</script>`,   // Inline script tags
		`javascript:.*`,         // Inline JavaScript
		`<img\s+.*onerror=.*>`,  // Malicious image onerror handlers
		`<iframe.*>.*</iframe>`, // Embedded iframes
		`(?i)<.*on\w+\s*=.*>`,
	}
	for _, pattern := range defaultPatterns {
		xssPatterns = append(xssPatterns, regexp.MustCompile(pattern))
	}

	config := loadConfig("xss_config.json")
	for _, pattern := range config.PayloadPatterns {
		xssPatterns = append(xssPatterns, regexp.MustCompile(pattern))
	}
}

func loadConfig(filename string) Config {
	var config Config
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("No custom configuration found: %v", err)
		return config
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Printf("Error reading configuration file: %v", err)
	}
	return config
}

func detectXSS(input string) bool {
	for _, pattern := range xssPatterns {
		if pattern.MatchString(strings.ToLower(input)) {
			return true
		}
	}
	return false
}

func logRequestDetails(r *http.Request, detected bool, paramName, payload string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()

	status := "SAFE"
	if detected {
		status = "XSS DETECTED"
	}

	logger.Printf("[%s] Status: %s | IP: %s | User-Agent: %s | Param: %s | Payload: %s\n",
		timestamp, status, ipAddress, userAgent, paramName, payload)
}

func handler(w http.ResponseWriter, r *http.Request) {
	var detected bool

	// Check GET parameters
	for key, values := range r.URL.Query() {
		for _, value := range values {
			if detectXSS(value) {
				detected = true
				logRequestDetails(r, detected, key, value)
			}
		}
	}

	// Check POST parameters
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse POST data", http.StatusBadRequest)
			return
		}
		for key, values := range r.PostForm {
			for _, value := range values {
				if detectXSS(value) {
					detected = true
					logRequestDetails(r, detected, key, value)
				}
			}
		}
	}

	// Respond to the client
	if detected {
		http.Error(w, "XSS payload detected", http.StatusBadRequest)
	} else {
		logRequestDetails(r, detected, "-", "-")
		fmt.Fprintln(w, "Input validated successfully")
	}
}

func main() {
	http.HandleFunc("/", handler)

	port := "8080"
	fmt.Printf("Server is running on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
