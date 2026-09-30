package mcphost

import (
	"strings"
	"testing"
	"time"
)

func TestRunBoundedSuccess(t *testing.T) {
	res := runBounded(t.TempDir(), "echo hello", 5*time.Second, 64*1024)
	if res.exitCode != 0 || res.stdout != "hello\n" || res.timedOut || res.truncated {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestRunBoundedExitCode(t *testing.T) {
	res := runBounded(t.TempDir(), "exit 3", 5*time.Second, 64*1024)
	if res.exitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.exitCode)
	}
}

func TestRunBoundedTimeout(t *testing.T) {
	start := time.Now()
	res := runBounded(t.TempDir(), "sleep 30", 300*time.Millisecond, 64*1024)
	if !res.timedOut {
		t.Errorf("expected timeout, got %+v", res)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("run took too long: %v", time.Since(start))
	}
}

func TestRunBoundedTruncatesOutput(t *testing.T) {
	// 200KB of output against a 64KB budget.
	res := runBounded(t.TempDir(), "head -c 200000 /dev/zero | tr '\\0' x", 5*time.Second, 64*1024)
	if !res.truncated {
		t.Errorf("expected truncation, got %+v", res)
	}
	if len(res.stdout) > 64*1024 {
		t.Errorf("stdout %d bytes exceeds budget", len(res.stdout))
	}
}

func TestRunBoundedStderrSeparate(t *testing.T) {
	res := runBounded(t.TempDir(), "echo out; echo err >&2", 5*time.Second, 64*1024)
	if res.stdout != "out\n" || res.stderr != "err\n" {
		t.Errorf("streams mixed: %+v", res)
	}
}

func TestRunBoundedCombinedBudget(t *testing.T) {
	// Both streams share one budget: 100KB each against a 64KB total.
	res := runBounded(t.TempDir(),
		"head -c 100000 /dev/zero | tr '\\0' a; head -c 100000 /dev/zero | tr '\\0' b >&2",
		5*time.Second, 64*1024)
	if !res.truncated {
		t.Errorf("expected truncation on shared budget")
	}
	if total := len(res.stdout) + len(res.stderr); total > 64*1024 {
		t.Errorf("combined %d bytes exceeds budget", total)
	}
}

func TestRunBoundedWorkDir(t *testing.T) {
	dir := t.TempDir()
	res := runBounded(dir, "pwd", 5*time.Second, 64*1024)
	if strings.TrimSpace(res.stdout) != dir {
		t.Errorf("pwd = %q, want %q", strings.TrimSpace(res.stdout), dir)
	}
}
