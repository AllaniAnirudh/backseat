// Package host: approval prompt detection.
//
// Agents constantly stop to ask "run this command? [y/n]". The approval
// matcher watches the PTY output stream for those prompts and turns them
// into structured ApprovalRequests the expert can answer with one tap,
// instead of watching the terminal and typing.
//
// The matcher is deliberately extensible: RegisterApprovalPattern adds a
// new prompt shape without touching the core loop. Matching runs against
// ANSI-stripped text because prompts often arrive with color codes, and
// against a rolling tail buffer because a prompt can be split across PTY
// read chunks.
package host

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ApprovalPattern describes one recognizable approval prompt shape.
type ApprovalPattern struct {
	// Name identifies the pattern in logs and tests.
	Name string
	// Re matches the prompt. It should anchor near the end of the text
	// ($ with (?m) or \z) so only live prompts fire, not scrollback.
	Re *regexp.Regexp
	// Approve and Deny are the exact bytes written to the PTY for each
	// decision.
	Approve []byte
	Deny    []byte
	// Tool labels the card in the expert UI.
	Tool string
}

// ApprovalMatch is one detected prompt.
type ApprovalMatch struct {
	Pattern ApprovalPattern
	// Prompt is the matched raw text, trimmed.
	Prompt string
}

var (
	approvalMu       sync.RWMutex
	approvalPatterns []ApprovalPattern
)

func init() {
	// Classic [y/n] / (y/n) / [Y/n] confirmation. Anchored to the very
	// end of the stream (\z): a prompt followed by more output is stale.
	RegisterApprovalPattern(ApprovalPattern{
		Name:    "yes-no-bracket",
		Re:      regexp.MustCompile(`(?i)([^\n]{1,200}?)\s*[\[\(]\s*y\s*/\s*n\s*[\]\)]\s*:?\s*\z`),
		Approve: []byte("y\n"),
		Deny:    []byte("n\n"),
		Tool:    "terminal",
	})
	// Bare question words: "Approve?", "Proceed?", "Continue?", "Allow?".
	RegisterApprovalPattern(ApprovalPattern{
		Name:    "question-word",
		Re:      regexp.MustCompile(`(?i)([^\n]{0,200}?\b(approve|proceed|continue|allow|confirm)\b[^\n]{0,60}\?)\s*\z`),
		Approve: []byte("y\n"),
		Deny:    []byte("n\n"),
		Tool:    "terminal",
	})
	// "Do you want to ..." questions.
	RegisterApprovalPattern(ApprovalPattern{
		Name:    "do-you-want",
		Re:      regexp.MustCompile(`(?i)(do you want to[^\n]{1,200}\?)\s*\z`),
		Approve: []byte("y\n"),
		Deny:    []byte("n\n"),
		Tool:    "terminal",
	})
	// Numbered choice menus: "1. Yes, proceed" / "2. No".
	RegisterApprovalPattern(ApprovalPattern{
		Name:    "numbered-yes-no",
		Re:      regexp.MustCompile(`(?im)(^\s*1\.\s*yes[^\n]*\n\s*2\.\s*(no|cancel)[^\n]*)\s*\z`),
		Approve: []byte("1\n"),
		Deny:    []byte("2\n"),
		Tool:    "terminal",
	})
}

// RegisterApprovalPattern adds a prompt shape to the matcher. It is safe
// for concurrent use.
func RegisterApprovalPattern(p ApprovalPattern) {
	approvalMu.Lock()
	defer approvalMu.Unlock()
	approvalPatterns = append(approvalPatterns, p)
}

// approvalPatternsSnapshot returns the registered patterns in order.
func approvalPatternsSnapshot() []ApprovalPattern {
	approvalMu.RLock()
	defer approvalMu.RUnlock()
	out := make([]ApprovalPattern, len(approvalPatterns))
	copy(out, approvalPatterns)
	return out
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]|\x1b\\][^\x07]*\x07|\x1b[()][0-9A-B]|\r")

// stripANSI removes terminal escape sequences so prompts match on their
// visible text.
func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// MatchApprovalPrompt scans text for a live approval prompt and returns
// the first matching pattern's match, or nil.
func MatchApprovalPrompt(text string) *ApprovalMatch {
	clean := stripANSI(text)
	for _, p := range approvalPatternsSnapshot() {
		m := p.Re.FindStringSubmatch(clean)
		if m == nil {
			continue
		}
		prompt := ""
		if len(m) > 1 {
			prompt = strings.TrimSpace(m[1])
		}
		if prompt == "" {
			prompt = strings.TrimSpace(m[0])
		}
		return &ApprovalMatch{Pattern: p, Prompt: prompt}
	}
	return nil
}

// approvalTTL bounds how long a forwarded prompt stays answerable. After
// that the expert's answer is dropped: the novice may have answered
// locally in the meantime, and a stale "y" must never fire.
const approvalTTL = 2 * time.Minute

// pendingApproval is one forwarded prompt awaiting a decision.
type pendingApproval struct {
	id        string
	prompt    string
	approve   []byte
	deny      []byte
	tool      string
	createdAt time.Time
}

// newApprovalID mints an opaque approval identifier.
func newApprovalID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "appr-" + hex.EncodeToString(b)
}

// expired reports whether the approval is too old to answer safely.
func (p *pendingApproval) expired(now time.Time) bool {
	return now.Sub(p.createdAt) > approvalTTL
}
