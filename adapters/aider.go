package adapters

import "errors"

// AiderAdapter parses aider session transcripts. Not implemented yet.
type AiderAdapter struct{}

func (a *AiderAdapter) Name() string { return "aider" }

func (a *AiderAdapter) ParseEvent(line []byte) (Event, error) {
	return Event{}, errors.New("aider adapter: not implemented")
}
