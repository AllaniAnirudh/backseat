package host

import (
	"regexp"
	"testing"
	"time"
)

func TestMatchApprovalPrompt(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    bool
		pattern string
	}{
		{"bracket yn", "Do you want to proceed? [y/n] ", true, "yes-no-bracket"},
		{"paren yn", "Run tests (y/n): ", true, "yes-no-bracket"},
		{"capital Y", "Delete everything? [Y/n]", true, "yes-no-bracket"},
		{"question word", "Approve?", true, "question-word"},
		{"proceed question", "Do you want to continue with the deployment?", true, "question-word"},
		{"do-you-want", "Do you want to delete the cluster?", true, "do-you-want"},
		{"numbered menu", "Choose:\n1. Yes, proceed\n2. No, cancel\n", true, "numbered-yes-no"},
		{"ansi colored", "\x1b[33mDo you want to proceed? [y/n]\x1b[0m ", true, "yes-no-bracket"},
		{"plain output", "Compiling 42 files...\ndone.", false, ""},
		{"y in prose", "yesterday we shipped", false, ""},
		{"question no prompt", "what is your name?", false, ""},
		{"stale scrollback", "Do you want to proceed? [y/n]\nuser typed y\nmoving on\n", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := MatchApprovalPrompt(c.input)
			if c.want && m == nil {
				t.Fatalf("expected a match for %q", c.input)
			}
			if !c.want && m != nil {
				t.Fatalf("unexpected match %q for %q", m.Pattern.Name, c.input)
			}
			if c.want && m.Pattern.Name != c.pattern {
				t.Fatalf("pattern = %q, want %q", m.Pattern.Name, c.pattern)
			}
			if c.want && m.Prompt == "" {
				t.Fatal("empty prompt text")
			}
		})
	}
}

func TestMatchApprovalPromptAnswers(t *testing.T) {
	m := MatchApprovalPrompt("Deploy to prod? [y/n]")
	if m == nil {
		t.Fatal("no match")
	}
	if string(m.Pattern.Approve) != "y\n" || string(m.Pattern.Deny) != "n\n" {
		t.Fatalf("bad answers: %q %q", m.Pattern.Approve, m.Pattern.Deny)
	}
	m = MatchApprovalPrompt("1. Yes, run it\n2. No\n")
	if m == nil {
		t.Fatal("no match for numbered menu")
	}
	if string(m.Pattern.Approve) != "1\n" {
		t.Fatalf("numbered approve = %q", m.Pattern.Approve)
	}
}

func TestRegisterApprovalPattern(t *testing.T) {
	RegisterApprovalPattern(ApprovalPattern{
		Name:    "test-custom",
		Re:      regexp.MustCompile(`(?im)(shall we dance\?)\s*$`),
		Approve: []byte("oh yes\n"),
		Deny:    []byte("no\n"),
		Tool:    "test",
	})
	m := MatchApprovalPrompt("Shall we dance?")
	if m == nil || m.Pattern.Name != "test-custom" {
		t.Fatalf("custom pattern not used: %+v", m)
	}
	if string(m.Pattern.Approve) != "oh yes\n" {
		t.Fatalf("custom approve = %q", m.Pattern.Approve)
	}
}

func TestPendingApprovalExpiry(t *testing.T) {
	p := &pendingApproval{id: "x", createdAt: time.Now()}
	if p.expired(time.Now()) {
		t.Fatal("fresh approval reported expired")
	}
	p.createdAt = time.Now().Add(-3 * time.Minute)
	if !p.expired(time.Now()) {
		t.Fatal("stale approval not reported expired")
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[1;32mOK\x1b[0m \x1b]0;title\x07done\r\n"
	if got := stripANSI(in); got != "OK done\n" {
		t.Fatalf("stripANSI = %q", got)
	}
}
