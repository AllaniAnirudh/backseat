// Package mcphost: local novice control channel.
//
// The MCP tool surface deliberately has no grant/deny tools: control
// decisions must be novice-confirmed out-of-band of the model's tool
// calls. ServeControl listens on a unix socket for a local `backseat-mcp
// ctl` invocation, the human's confirm path. The socket is filesystem
// permission-gated (same user) and never touches the network.
package mcphost

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// ctlRequest is one newline-delimited JSON command on the socket.
type ctlRequest struct {
	Cmd  string   `json:"cmd"`
	Args []string `json:"args,omitempty"`
}

// ctlResponse answers one command.
type ctlResponse struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Result string `json:"result,omitempty"`
}

// ServeControl listens on a unix socket at sockPath for novice commands:
// grant, deny [reason], yield, kick <name> [reason], end [reason],
// confirm-restore, deny-restore [reason], status. It returns when the
// session ends.
func (s *Session) ServeControl(sockPath string) error {
	_ = os.Remove(sockPath) // stale socket from a dead server
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("mcphost: control socket: %w", err)
	}
	// Filesystem-gated: only the local user may talk to the socket.
	if err := os.Chmod(sockPath, 0700); err != nil {
		ln.Close()
		os.Remove(sockPath)
		return fmt.Errorf("mcphost: control socket chmod: %w", err)
	}
	fmt.Fprintf(os.Stderr, "backseat: control socket %s\n", sockPath)
	defer ln.Close()
	defer os.Remove(sockPath)
	go func() {
		<-s.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.Done():
				return nil
			default:
				continue
			}
		}
		go s.serveCtlConn(conn)
	}
}

func (s *Session) serveCtlConn(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	if !sc.Scan() {
		return
	}
	var req ctlRequest
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		writeCtlResp(conn, ctlResponse{Error: "bad request: " + err.Error()})
		return
	}
	writeCtlResp(conn, s.handleCtl(req))
}

func writeCtlResp(conn net.Conn, resp ctlResponse) {
	raw, _ := json.Marshal(resp)
	raw = append(raw, '\n')
	conn.Write(raw)
}

// handleCtl runs one novice command.
func (s *Session) handleCtl(req ctlRequest) ctlResponse {
	arg := func(i int) string {
		if i < len(req.Args) {
			return req.Args[i]
		}
		return ""
	}
	rest := func(i int) string { return strings.Join(req.Args[i:], " ") }
	var err error
	switch strings.ToLower(req.Cmd) {
	case "grant":
		// grant [name]: the name must match the pending requester.
		if name := arg(0); name != "" && name != s.PendingControl() {
			return ctlResponse{Error: fmt.Sprintf("no pending control request from %q", name)}
		}
		err = s.Grant()
	case "deny":
		err = s.Deny(rest(0))
	case "yield":
		s.Yield()
	case "kick":
		if arg(0) == "" {
			return ctlResponse{Error: "usage: kick <name> [reason]"}
		}
		s.Kick(arg(0), rest(1))
	case "end":
		s.End(rest(0))
	case "confirm-restore":
		err = s.ConfirmRestore()
	case "deny-restore":
		err = s.DenyRestore(rest(0))
	case "status":
		st := s.Status()
		raw, _ := json.Marshal(st)
		return ctlResponse{OK: true, Result: string(raw)}
	default:
		return ctlResponse{Error: "unknown command: " + req.Cmd}
	}
	if err != nil {
		return ctlResponse{Error: err.Error()}
	}
	return ctlResponse{OK: true}
}
