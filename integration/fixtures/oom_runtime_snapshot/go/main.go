// Copyright 2026 The HuaTuo Authors
// Licensed under the Apache License, Version 2.0.

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
)

//go:noinline
func allocateSmall(count int) [][]byte {
	result := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		value := make([]byte, 256+(index%8)*64)
		value[0] = byte(index)
		result = append(result, value)
	}
	return result
}

//go:noinline
func allocateLarge(count int) [][]byte {
	result := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		value := make([]byte, 256<<10)
		value[0] = byte(index)
		result = append(result, value)
	}
	return result
}

func main() {
	var startSignal chan os.Signal
	if os.Getenv("HUATUO_FIXTURE_WAIT_SIGNAL") == "1" {
		startSignal = make(chan os.Signal, 1)
		signal.Notify(startSignal, syscall.SIGUSR1)
		defer signal.Stop(startSignal)
	}
	runtime.MemProfileRate = 1
	workers := envInt("HUATUO_FIXTURE_WORKERS", 4)
	small := envInt("HUATUO_FIXTURE_SMALL_OBJECTS", 50000)
	large := envInt("HUATUO_FIXTURE_LARGE_OBJECTS", 128)
	retained := make([][]byte, 0, small+large)
	var lock sync.Mutex
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			local := allocateSmall(small / workers)
			local = append(local, allocateLarge(large/workers)...)
			lock.Lock()
			retained = append(retained, local...)
			lock.Unlock()
		}()
	}
	wait.Wait()
	runtime.GC()
	fmt.Printf("READY %s objects=%d\n", runtime.Version(), len(retained))
	_ = os.Stdout.Sync()
	if os.Getenv("HUATUO_FIXTURE_OOM") == "1" {
		if startSignal != nil {
			<-startSignal
		}
		for {
			value := make([]byte, 8<<20)
			for offset := 0; offset < len(value); offset += 4096 {
				value[offset] = byte(offset)
			}
			retained = append(retained, value)
			time.Sleep(10 * time.Millisecond)
		}
	}
	time.Sleep(time.Minute)
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
