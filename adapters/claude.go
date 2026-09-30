package adapters

import "errors"

// ClaudeAdapter parses claude session transcripts. Not implemented yet.
type ClaudeAdapter struct{}

func (a *ClaudeAdapter) Name() string { return "claude" }

func (a *ClaudeAdapter) ParseEvent(line []byte) (Event, error) {
	return Event{}, errors.New("claude adapter: not implemented")
}
