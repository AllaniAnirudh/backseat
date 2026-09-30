package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
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
