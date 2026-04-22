package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var managedShutdownOnce sync.Once

func shutdownManagedChildren() {
	managedShutdownOnce.Do(func() {
		if err := stopManagedTURNDaemon(5 * time.Second); err != nil {
			log.Printf("Failed to stop managed TURN daemon during shutdown: %v", err)
		}
		if err := stopManagedDaemon(5 * time.Second); err != nil {
			log.Printf("Failed to stop managed uwgsocks daemon during shutdown: %v", err)
		}
	})
}

func installManagedShutdownHandler() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signals
		log.Printf("Received %s, stopping managed daemons", sig)
		shutdownManagedChildren()
		os.Exit(0)
	}()
}
