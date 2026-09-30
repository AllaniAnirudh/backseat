// Package pty wraps an agent command in a pseudo-terminal so backseat can
// capture and drive any CLI harness without integrating with its protocols.
package pty

import (
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

// Session runs one command inside a PTY and fans its output out to any
// number of subscribers (viewers, the relay pump, loggers).
type Session struct {
	cmd  *exec.Cmd
	ptmx *os.File

	mu     sync.Mutex
	subs   map[chan []byte]struct{}
	closed chan struct{}
	once   sync.Once
}

// Start launches command with args inside a new PTY.
func Start(command string, args ...string) (*Session, error) {
	cmd := exec.Command(command, args...)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cmd:    cmd,
		ptmx:   ptmx,
		subs:   make(map[chan []byte]struct{}),
		closed: make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

// readLoop copies PTY output to every subscriber until EOF or Close.
func (s *Session) readLoop() {
	buf := make([]byte, 32*1024)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.broadcast(buf[:n])
		}
		if err != nil {
			s.Close()
			return
		}
	}
}

// broadcast delivers a copy of p to each subscriber without blocking.
func (s *Session) broadcast(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		cp := make([]byte, len(p))
		copy(cp, p)
		select {
		case ch <- cp:
		default:
			// Slow subscriber: drop this chunk rather than stall the agent.
		}
	}
}

// Subscribe returns a channel receiving PTY output. Call Unsubscribe or
// Close to release it.
func (s *Session) Subscribe() <-chan []byte {
	ch := make(chan []byte, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber created by Subscribe.
func (s *Session) Unsubscribe(ch <-chan []byte) {
	s.mu.Lock()
	for c := range s.subs {
		if (<-chan []byte)(c) == ch {
			delete(s.subs, c)
			close(c)
			break
		}
	}
	s.mu.Unlock()
}

// Write sends input (keystrokes from the current controller) to the PTY.
func (s *Session) Write(p []byte) (int, error) {
	return s.ptmx.Write(p)
}

// Resize sets the PTY dimensions.
func (s *Session) Resize(cols, rows uint16) error {
	return pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
}

// Wait blocks until the agent process exits.
func (s *Session) Wait() error {
	return s.cmd.Wait()
}

// Close tears down the PTY, stops the read loop, and closes subscribers.
func (s *Session) Close() error {
	var err error
	s.once.Do(func() {
		close(s.closed)
		s.mu.Lock()
		for ch := range s.subs {
			close(ch)
			delete(s.subs, ch)
		}
		s.mu.Unlock()
		err = s.ptmx.Close()
	})
	return err
}

// Done reports when the session has ended.
func (s *Session) Done() <-chan struct{} {
	return s.closed
}

// PipeTo copies PTY output to w until the session ends. Handy for logging.
func (s *Session) PipeTo(w io.Writer) {
	ch := s.Subscribe()
	defer s.Unsubscribe(ch)
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				return
			}
			w.Write(b)
		case <-s.Done():
			return
		}
	}
}
