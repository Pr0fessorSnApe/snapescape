package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	TaskStream    = "snapescape:tasks"
	ResultStream  = "snapescape:results"
	TelemetryChan = "snapescape:telemetry"
	ConsumerGroup = "snapescape-workers"
)

type Task struct {
	ID       string                 `json:"id"`
	ScanID   string                 `json:"scan_id"`
	Phase    string                 `json:"phase"`
	Target   string                 `json:"target"`
	Payload  map[string]interface{} `json:"payload"`
	Priority int                    `json:"priority"`
}

type Result struct {
	TaskID    string                 `json:"task_id"`
	ScanID    string                 `json:"scan_id"`
	Phase     string                 `json:"phase"`
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data"`
	Error     string                 `json:"error,omitempty"`
	Timestamp string                 `json:"timestamp"`
	WorkerID  string                 `json:"worker_id"`
}

type RedisQueue struct {
	client *redis.Client
}

func NewRedisQueue(redisURL string) (*RedisQueue, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		opts = &redis.Options{Addr: "localhost:6379"}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	q := &RedisQueue{client: client}
	q.ensureConsumerGroup(context.Background())
	return q, nil
}

func (q *RedisQueue) ensureConsumerGroup(ctx context.Context) {
	err := q.client.XGroupCreateMkStream(ctx, TaskStream, ConsumerGroup, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		// ignore if already exists
	}
}

func (q *RedisQueue) Enqueue(ctx context.Context, task Task) error {
	data, err := json.Marshal(task)
	if err != nil {
		return err
	}
	return q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: TaskStream,
		Values: map[string]interface{}{"task": string(data)},
	}).Err()
}

func (q *RedisQueue) Dequeue(ctx context.Context, consumer string) (*Task, string, error) {
	streams, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    ConsumerGroup,
		Consumer: consumer,
		Streams:  []string{TaskStream, ">"},
		Count:    1,
		Block:    5 * time.Second,
	}).Result()

	if err == redis.Nil {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}

	for _, stream := range streams {
		for _, msg := range stream.Messages {
			taskJSON, ok := msg.Values["task"].(string)
			if !ok {
				continue
			}
			var task Task
			if err := json.Unmarshal([]byte(taskJSON), &task); err != nil {
				return nil, "", err
			}
			return &task, msg.ID, nil
		}
	}
	return nil, "", nil
}

func (q *RedisQueue) Ack(ctx context.Context, msgID string) error {
	return q.client.XAck(ctx, TaskStream, ConsumerGroup, msgID).Err()
}

func (q *RedisQueue) PublishResult(ctx context.Context, result Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: ResultStream,
		Values: map[string]interface{}{"result": string(data)},
	}).Err()
}

func (q *RedisQueue) Publish(ctx context.Context, channel, message string) error {
	return q.client.Publish(ctx, channel, message).Err()
}

func (q *RedisQueue) Close() error {
	return q.client.Close()
}
