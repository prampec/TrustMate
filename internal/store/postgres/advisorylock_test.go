package postgres

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestWithAdvisoryLockSerializes checks the actual property
// cmd/trustmated's bootstrap wrapping depends on: two concurrent
// WithAdvisoryLock calls on the same key never run fn at the same time.
func TestWithAdvisoryLockSerializes(t *testing.T) {
	db := openTest(t)

	var (
		mu         sync.Mutex
		active     int
		sawOverlap bool
	)
	enter := func() {
		mu.Lock()
		active++
		if active > 1 {
			sawOverlap = true
		}
		mu.Unlock()
	}
	leave := func() {
		mu.Lock()
		active--
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithAdvisoryLock(context.Background(), db.db, 0x1234, func() error {
				enter()
				time.Sleep(20 * time.Millisecond)
				leave()
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if sawOverlap {
		t.Error("WithAdvisoryLock allowed two callers to run fn concurrently")
	}
}
