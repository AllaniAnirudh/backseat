package adapters

import "errors"

// CopilotAdapter parses copilot session transcripts. Not implemented yet.
type CopilotAdapter struct{}

func (a *CopilotAdapter) Name() string { return "copilot" }

func (a *CopilotAdapter) ParseEvent(line []byte) (Event, error) {
	return Event{}, errors.New("copilot adapter: not implemented")
}
