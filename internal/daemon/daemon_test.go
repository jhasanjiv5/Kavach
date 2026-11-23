package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jhasanjiv5/kavach/internal/engine"
	"github.com/jhasanjiv5/kavach/internal/types"
)

func TestDaemonUnixSocketAndVerdictCache(t *testing.T) {
	// t.TempDir() paths on macOS can exceed the 104-byte Unix socket limit, so use a short directory.
	kavachDir, err := os.MkdirTemp("", "kv")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(kavachDir) })
	eng, err := engine.New(engine.Options{KavachDir: kavachDir})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	sockPath := filepath.Join(kavachDir, "kavach.sock")
	srv := NewServer(eng)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, sockPath, "")
	}()

	// Wait briefly for socket to appear
	deadline := time.Now().Add(2 * time.Second)
	in := types.EvalInput{
		Event:   types.EventUserPromptSubmit,
		Content: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	}

	var v1 types.Verdict
	var ok bool
	for time.Now().Before(deadline) {
		v1, ok = EvaluateViaSocket(ctx, sockPath, in, time.Second)
		if ok {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("failed to reach daemon over unix socket")
	}
	if v1.Action != types.ActionBlock || v1.CacheHit {
		t.Fatalf("expected uncached BLOCK on first request, got action=%s cacheHit=%v", v1.Action, v1.CacheHit)
	}

	v2, ok := EvaluateViaSocket(ctx, sockPath, in, time.Second)
	if !ok || !v2.CacheHit || v2.Action != types.ActionBlock {
		t.Fatalf("expected cached BLOCK on second request, got ok=%v cacheHit=%v action=%s", ok, v2.CacheHit, v2.Action)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("ListenAndServe returned error: %v", err)
	}
}

func TestDaemonRejectsOverlongSocketPath(t *testing.T) {
	eng, err := engine.New(engine.Options{KavachDir: t.TempDir()})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	long := filepath.Join(os.TempDir(), strings.Repeat("x", 120), "kavach.sock")
	err = NewServer(eng).ListenAndServe(context.Background(), long, "")
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("expected a clear socket-path-length error, got %v", err)
	}
}
