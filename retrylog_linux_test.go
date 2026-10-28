package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRetryLog(t *testing.T) {
	var r retryLog
	t0 := time.Unix(1000, 0)
	e := errors.New("dial unix x: no such file")
	if _, ok := r.next(t0, e); !ok {
		t.Fatal("first error must be logged")
	}
	for i := 1; i <= 29; i++ {
		if _, ok := r.next(t0.Add(time.Duration(i)*2*time.Second), e); ok {
			t.Fatalf("attempt %d inside the minute was logged", i)
		}
	}
	msg, ok := r.next(t0.Add(time.Minute), e)
	if !ok || !strings.Contains(msg, "[29 failed attempts not logged]") {
		t.Fatalf("got %q %v", msg, ok)
	}
}
