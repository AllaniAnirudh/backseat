// Package adapters defines the harness-agnostic transcript interface.
// Backseat drives every agent through the PTY (universal layer) and uses
// one thin adapter per harness to parse that harness's transcript or
// session files into structured events (side channel).
package adapters

import "time"

// EventKind classifies a parsed transcript event.
type EventKind string

const (
	EventPrompt     EventKind = "prompt"
	EventToolCall   EventKind = "tool_call"
	EventToolResult EventKind = "tool_result"
	EventApproval   EventKind = "approval"
	EventText       EventKind = "text"
)

// Event is one structured fact extracted from a harness transcript.
type Event struct {
	Kind   EventKind
	Text   string
	Fields map[string]any
	At     time.Time
}

// TranscriptAdapter parses one harness's session files into Events.
// Implementations must be best effort: unknown lines become EventText or
// are skipped, never fatal.
type TranscriptAdapter interface {
	// Name returns the harness identifier, e.g. "claude".
	Name() string
	// ParseEvent parses one transcript line or record into an Event.
	ParseEvent(line []byte) (Event, error)
}
