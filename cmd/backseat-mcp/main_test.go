package main

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// errTestConfirmer is the sentinel error for the failing confirmer.
var errTestConfirmer = errors.New("test confirmer error")

// TestConfirmSessionCreationDenied: a refused human answer gates creation;
// no session exists afterwards.
func TestConfirmSessionCreationDenied(t *testing.T) {
	old := humanConfirmer
	humanConfirmer = func(string) (bool, error) { return false, nil }
	defer func() { humanConfirmer = old }()

	if err := confirmSessionCreation("demo"); err == nil {
		t.Fatal("denied confirmation should error")
	}
	if sess != nil {
		t.Fatal("session must not exist after a denial")
	}
}

// TestConfirmSessionCreationError fails closed on confirmer errors.
func TestConfirmSessionCreationError(t *testing.T) {
	old := humanConfirmer
	humanConfirmer = func(string) (bool, error) { return false, errTestConfirmer }
	defer func() { humanConfirmer = old }()

	if err := confirmSessionCreation("demo"); err == nil {
		t.Fatal("confirmer error should fail closed")
	}
}

// TestAssumeYesBypassesPrompt: BACKSEAT_ASSUME_YES=1 answers yes without a
// TTY, so headless runs and tests never block on /dev/tty.
func TestAssumeYesBypassesPrompt(t *testing.T) {
	t.Setenv("BACKSEAT_ASSUME_YES", "1")
	ok, err := humanConfirmTTY("anything? [y/N]")
	if err != nil || !ok {
		t.Fatalf("assume-yes: ok=%v err=%v", ok, err)
	}
}

// TestDefaultCtlSockUnpredictable: socket names are 32 random hex chars,
// never the PID, and differ run to run.
func TestDefaultCtlSockUnpredictable(t *testing.T) {
	a, b := defaultCtlSock(), defaultCtlSock()
	if a == b {
		t.Fatal("socket names must differ between calls")
	}
	base := filepath.Base(a)
	name := strings.TrimSuffix(strings.TrimPrefix(base, "backseat-mcp-"), ".sock")
	if len(name) != 32 {
		t.Fatalf("socket name %q does not carry 32 hex chars", base)
	}
	for _, c := range name {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("socket name %q is not hex", base)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

// TestToolAnnotations: every exposed tool is registered by name and carries
// all four MCP annotations with values matching its handler's behaviour.
// (M8ven Trust Index finding: 7/7 tools were missing annotations.)
func TestToolAnnotations(t *testing.T) {
	want := map[string]mcp.ToolAnnotation{
		// Creates a session and dials the relay: mutating, not idempotent,
		// reaches the network.
		"backseat__create_session": {
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(false),
			IdempotentHint:  boolPtr(false),
			OpenWorldHint:   boolPtr(true),
		},
		// Forwards an event to every enrolled expert over the network.
		"backseat__publish_event": {
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(false),
			IdempotentHint:  boolPtr(false),
			OpenWorldHint:   boolPtr(true),
		},
		// Drains AND clears the local inbox: mutating, not idempotent.
		"backseat__poll": {
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(false),
			IdempotentHint:  boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
		// Creates a pending approval request answered by the remote expert.
		"backseat__request_approval": {
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(false),
			IdempotentHint:  boolPtr(false),
			OpenWorldHint:   boolPtr(true),
		},
		// Writes a snapshot of the working directory to disk.
		"backseat__checkpoint": {
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(false),
			IdempotentHint:  boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
		// Pure read of session state.
		"backseat__session_status": {
			ReadOnlyHint:    boolPtr(true),
			DestructiveHint: boolPtr(false),
			IdempotentHint:  boolPtr(true),
			OpenWorldHint:   boolPtr(false),
		},
		// Tears the session down: invalidates the invite and disconnects
		// experts (destructive), guarded by sync.Once so repeats are safe.
		"backseat__end_session": {
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(true),
			IdempotentHint:  boolPtr(true),
			OpenWorldHint:   boolPtr(true),
		},
	}

	got := buildMCPServer().ListTools()
	if len(got) != len(want) {
		t.Fatalf("registered %d tools, want %d", len(got), len(want))
	}
	for name, wantAnn := range want {
		st, ok := got[name]
		if !ok {
			t.Errorf("tool %q not registered", name)
			continue
		}
		if !reflect.DeepEqual(st.Tool.Annotations, wantAnn) {
			t.Errorf("tool %q annotations = %+v, want %+v", name, st.Tool.Annotations, wantAnn)
		}
	}
}
