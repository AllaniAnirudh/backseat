// Package mcphost: the bounded shell side-channel.
//
// The controller (and only the controller) may ask the MCP server to run
// shell commands in the session working directory. Every run is bounded:
// a caller-supplied timeout clamped to a host maximum, and a shared
// stdout+stderr byte budget after which output is truncated and flagged.
// Each run is reported to the novice's agent through the poll inbox, so
// exec is novice-visible by construction.
package mcphost

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// maxExecTimeout caps any single exec_request, no matter what the expert
// asks for.
const maxExecTimeout = 2 * time.Minute

// execResult is one finished command run.
type execResult struct {
	stdout    string
	stderr    string
	exitCode  int
	truncated bool
	timedOut  bool
}

// outputCap splits one byte budget across the two output streams.
type outputCap struct {
	mu        sync.Mutex
	remaining int64
	truncated bool
}

// append adds p to dst while budget lasts, then flags truncation.
func (c *outputCap) append(dst *bytes.Buffer, p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.truncated {
		return
	}
	if int64(len(p)) > c.remaining {
		dst.Write(p[:c.remaining])
		c.remaining = 0
		c.truncated = true
		return
	}
	dst.Write(p)
	c.remaining -= int64(len(p))
}

// capWriter is an io.Writer feeding one stream through the shared cap.
type capWriter struct {
	cap *outputCap
	dst *bytes.Buffer
}

func (w capWriter) Write(p []byte) (int, error) {
	w.cap.append(w.dst, p)
	return len(p), nil
}

// runBounded runs command via sh -c in dir, killing it after timeout and
// truncating combined stdout+stderr to maxOutput bytes.
func runBounded(dir, command string, timeout time.Duration, maxOutput int64) execResult {
	var res execResult
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = dir
	// Kill the whole process group on timeout: sh -c forks grandchildren
	// that inherit the output pipes, and killing only sh would leave
	// cmd.Wait blocked on pipe EOF until they exit on their own.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return cmd.Process.Kill()
	}
	cap := &outputCap{remaining: maxOutput}
	var so, se bytes.Buffer
	cmd.Stdout = capWriter{cap: cap, dst: &so}
	cmd.Stderr = capWriter{cap: cap, dst: &se}
	err := cmd.Run()
	res.stdout = so.String()
	res.stderr = se.String()
	res.truncated = cap.truncated
	res.timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	res.exitCode = 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.exitCode = ee.ExitCode()
		} else {
			res.exitCode = -1
			res.stderr += "exec start: " + err.Error()
		}
	}
	return res
}
