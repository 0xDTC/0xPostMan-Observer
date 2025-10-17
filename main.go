package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/yourusername/postman-observer/config"
	"github.com/yourusername/postman-observer/observer"
)

func main() {
	// Command line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	envFile := flag.String("env", ".env", "Path to .env file (optional)")
	useEnv := flag.Bool("use-env", false, "Use environment variables instead of config file")
	once := flag.Bool("once", false, "Run once and exit (for testing or cron jobs)")
	dryRun := flag.Bool("dry-run", false, "Search and scan only, don't send emails")
	logDir := flag.String("log-dir", "", "Directory to store log files")
	flag.Parse()

	// Load .env file if it exists (before setting up logging)
	if err := config.LoadEnvFile(*envFile); err != nil {
		log.Printf("⚠️  Warning: %v", err)
	}

	// Determine log directory
	logDirectory := *logDir
	if logDirectory == "" {
		logDirectory = config.GetEnv("LOG_DIR", "logs")
	}

	// Setup logging to both file and console
	if err := setupLogging(logDirectory); err != nil {
		log.Fatalf("❌ Failed to setup logging: %v", err)
	}

	// Load configuration
	var cfg *config.Config
	var err error

	if *useEnv {
		log.Println("📝 Loading configuration from environment variables")
		cfg, err = config.LoadConfigFromEnv()
		if err != nil {
			log.Fatalf("❌ Failed to load configuration from environment: %v", err)
		}
	} else {
		log.Printf("📝 Loading configuration from: %s", *configPath)
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("❌ Failed to load configuration: %v", err)
		}
	}

	// Create and start monitor
	mon := observer.NewMonitor(cfg)

	// Set dry-run mode if requested
	if *dryRun {
		log.Println("🧪 Running in DRY-RUN mode (no emails will be sent)")
		mon.SetDryRun(true)
	}

	if *once {
		log.Println("Running in single-check mode")
		if err := mon.RunOnce(); err != nil {
			log.Fatalf("❌ Check failed: %v", err)
		}
		log.Println("✅ Single check completed successfully")
		os.Exit(0)
	}

	// Run in continuous monitoring mode
	mon.Start()
}

// setupLogging configures logging to both file and console
func setupLogging(logDir string) error {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file with timestamp (includes time with AM/PM)
	timestamp := time.Now().Format("2006-01-02_03-04-05PM")
	logFile := filepath.Join(logDir, fmt.Sprintf("observer_%s.log", timestamp))

	// Open log file (create new file for each run)
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Setup multi-writer (console + file)
	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)

	// Set log format with date and time
	log.SetFlags(log.Ldate | log.Ltime)

	log.Printf("════════════════════════════════════════════════════════════")
	log.Printf("🔍 Postman Observer - Logging to: %s", logFile)
	log.Printf("════════════════════════════════════════════════════════════")

	return nil
}
