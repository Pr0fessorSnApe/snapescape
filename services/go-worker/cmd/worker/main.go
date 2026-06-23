package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"snapescape/go-worker/internal/pipeline"
	"snapescape/go-worker/internal/queue"
)

func main() {
	printBanner()

	redisURL := getEnv("REDIS_URL", "redis://localhost:6379/0")
	workerID := getEnv("WORKER_ID", uuid.New().String()[:8])
	concurrency := 10

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q, err := queue.NewRedisQueue(redisURL)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer q.Close()

	executor := pipeline.NewExecutor(q, workerID)
	pool := pipeline.NewWorkerPool(executor, concurrency)

	log.Printf("[WORKER %s] Starting with concurrency=%d", workerID, concurrency)
	pool.Start(ctx)

	// Heartbeat
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				status := map[string]interface{}{
					"worker_id":   workerID,
					"status":      "alive",
					"timestamp":   time.Now().UTC().Format(time.RFC3339),
					"concurrency": concurrency,
				}
				data, _ := json.Marshal(status)
				q.Publish(ctx, "snapescape:telemetry", string(data))
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("[WORKER %s] Shutting down...", workerID)
	cancel()
	pool.Wait()
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func printBanner() {
	fmt.Println(`
   SNAPESCAPE Worker Node
   Created By: Pr0Fessor_SnApe
`)
}
