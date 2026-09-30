package adapters

import "errors"

// OpencodeAdapter parses opencode session transcripts. Not implemented yet.
type OpencodeAdapter struct{}

func (a *OpencodeAdapter) Name() string { return "opencode" }

func (a *OpencodeAdapter) ParseEvent(line []byte) (Event, error) {
	return Event{}, errors.New("opencode adapter: not implemented")
}
