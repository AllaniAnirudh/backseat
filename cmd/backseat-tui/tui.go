// Bubble Tea expert TUI: transcript viewport, approval cards, chat,
// checkpoints, and control state, all over the same encrypted relay
// protocol as the browser expert page.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

// outbound is the set of wire actions the model can take. *Client
// implements it against the relay; tests use a recording fake.
type outbound interface {
	decide(approvalID string, req protocol.ApprovalRequest, approved bool)
	chat(text string)
	checkpoint(label string)
	restore(label string)
	requestControl()
	yieldControl()
	exec(cmd string)
}

type connState int

const (
	connConnecting connState = iota
	connLive
	connEnded
)

type focus int

const (
	focusTranscript focus = iota
	focusApprovals
)

type inputKind int

const (
	inputNone inputKind = iota
	inputChat
	inputCheckpoint
	inputExec
	inputRestoreLabel
)

// approvalTTL is the fallback decision window when the request carries no
// explicit deadline. The host enforces fail-closed; the TUI mirrors it by
// refusing to answer expired cards.
const approvalTTL = 2 * time.Minute

type approvalCard struct {
	req      protocol.ApprovalRequest
	received time.Time
	details  bool
}

// deadline returns the card's decision deadline.
func (c approvalCard) deadline() time.Time {
	if c.req.ExpiresAt > 0 {
		return time.Unix(c.req.ExpiresAt, 0)
	}
	return c.received.Add(approvalTTL)
}

// remaining formats the TTL countdown; negative means expired.
func (c approvalCard) remaining(now time.Time) time.Duration {
	return time.Until(c.deadline())
}

// tline is one transcript row: a styling kind plus plain text. Lines are
// re-wrapped on resize from the plain text.
type tline struct {
	kind string // sys, agent, tool, result, chat, warn, appr, ckpt, exec
	text string
}

type model struct {
	out        outbound
	sessionID  string
	expertName string

	conn     connState
	connNote string
	driving  bool
	harness  string
	experts  map[string]bool
	latency  time.Duration

	lines []tline
	vp    viewport.Model

	approvals []approvalCard
	focus     focus
	sel       int

	inputKind inputKind
	input     textinput.Model

	picking        bool
	picker         list.Model
	checkpoints    []string
	pendingRestore string

	help         bool
	width        int
	height       int
	quitting     bool
	disconnected string
}

type tickMsg time.Time
type clientEventMsg struct{ ev clientEvent }

func newModel(out outbound, sessionID, expertName string) *model {
	ti := textinput.New()
	ti.CharLimit = 2000
	vp := viewport.New(80, 20)
	delegate := list.NewDefaultDelegate()
	picker := list.New([]list.Item{}, delegate, 40, 10)
	picker.SetShowTitle(false)
	picker.SetShowStatusBar(false)
	picker.SetShowHelp(false)
	return &model{
		out:        out,
		sessionID:  sessionID,
		expertName: expertName,
		conn:       connConnecting,
		connNote:   "connecting",
		experts:    map[string]bool{expertName: true},
		vp:         vp,
		input:      ti,
		picker:     picker,
	}
}

func (m *model) Init() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// addLine appends a transcript row and refreshes the viewport content,
// keeping the scroll pinned to the bottom only if it was already there.
func (m *model) addLine(kind, text string) {
	atBottom := m.vp.AtBottom()
	m.lines = append(m.lines, tline{kind: kind, text: text})
	if len(m.lines) > 5000 {
		m.lines = m.lines[len(m.lines)-5000:]
	}
	m.renderLines()
	if atBottom {
		m.vp.GotoBottom()
	}
}

func (m *model) renderLines() {
	w := m.vp.Width
	if w <= 0 {
		w = 80
	}
	var sb strings.Builder
	for i, l := range m.lines {
		if i > 0 {
			sb.WriteByte('\n')
		}
		for j, wl := range wrapLine(l.text, w) {
			if j > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(styleLine(l.kind, wl))
		}
	}
	m.vp.SetContent(sb.String())
}

// wrapLine wraps s to width w on spaces, preserving words.
func wrapLine(s string, w int) []string {
	if w < 10 {
		w = 10
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		for runewidth.StringWidth(para) > w {
			cut := w
			// Prefer a space boundary.
			for cut > w/2 && para[cut] != ' ' {
				cut--
			}
			if cut <= w/2 {
				cut = w
			}
			// Cut on a rune boundary.
			for cut > 0 && !isRuneStart(para[cut]) {
				cut--
			}
			out = append(out, strings.TrimRight(para[:cut], " "))
			para = strings.TrimLeft(para[cut:], " ")
		}
		out = append(out, para)
	}
	return out
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

var (
	styleSys    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleAgent  = lipgloss.NewStyle()
	styleTool   = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	styleResult = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleChat   = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styleAppr   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	styleCkpt   = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
	styleExec   = lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	styleCard   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("3"))
	styleBar    = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("7"))
)

func styleLine(kind, s string) string {
	switch kind {
	case "sys":
		return styleSys.Render(s)
	case "tool":
		return styleTool.Render(s)
	case "result":
		return styleResult.Render(s)
	case "chat":
		return styleChat.Render(s)
	case "warn":
		return styleWarn.Render(s)
	case "appr":
		return styleAppr.Render(s)
	case "ckpt":
		return styleCkpt.Render(s)
	case "exec":
		return styleExec.Render(s)
	default:
		return styleAgent.Render(s)
	}
}

// ---------- Update ----------

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case tickMsg:
		m.onTick(time.Time(msg))
		return m, tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
	case clientEventMsg:
		m.onClientEvent(msg.ev)
		if m.quitting {
			return m, tea.Quit
		}
		return m, nil
	case tea.KeyMsg:
		return m.onKey(msg)
	}

	// Route other messages (cursor blink etc.) to the active widget.
	if m.inputKind != inputNone {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	if m.picking {
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		return m, cmd
	}
	if m.focus == focusTranscript {
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	}
	return m, nil
}

// onTick expires approval cards (fail closed, mirrored client-side) and
// refreshes the latency readout.
func (m *model) onTick(now time.Time) {
	changed := false
	keep := m.approvals[:0]
	for _, card := range m.approvals {
		if card.remaining(now) <= 0 {
			m.addLine("warn", fmt.Sprintf("approval %q expired, fail closed (no decision sent)",
				shortSummary(card.req)))
			changed = true
			continue
		}
		keep = append(keep, card)
	}
	if len(keep) != len(m.approvals) {
		m.approvals = keep
		m.clampSel()
		changed = true
	}
	if c, ok := m.out.(*Client); ok {
		if d := c.Latency(); d != m.latency {
			m.latency = d
			changed = true
		}
	}
	if changed {
		m.layout()
	}
}

func (m *model) clampSel() {
	if m.sel >= len(m.approvals) {
		m.sel = len(m.approvals) - 1
	}
	if m.sel < 0 {
		m.sel = 0
	}
	if len(m.approvals) == 0 {
		m.focus = focusTranscript
	}
}

// ---------- Keys ----------

func (m *model) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Modal text input has priority.
	if m.inputKind != inputNone {
		return m.onInputKey(msg)
	}
	// Rewind picker has priority over global keys.
	if m.picking {
		return m.onPickerKey(msg)
	}
	// Pending restore confirmation.
	if m.pendingRestore != "" {
		switch msg.String() {
		case "y", "Y":
			label := m.pendingRestore
			m.pendingRestore = ""
			m.out.restore(label)
			m.addLine("ckpt", fmt.Sprintf("rewind to %q requested, waiting on the novice", label))
		case "n", "N", "esc":
			m.pendingRestore = ""
		}
		m.layout()
		return m, nil
	}
	// Help overlay.
	if m.help {
		if msg.String() == "?" || msg.String() == "esc" || msg.String() == "q" {
			m.help = false
			m.layout()
		}
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c", "q":
		m.quitting = true
		if c, ok := m.out.(*Client); ok {
			c.Close()
		}
		return m, tea.Quit
	case "?":
		// In the approvals pane ? toggles the selected card's details;
		// everywhere else it opens the help overlay.
		if m.focus == focusApprovals && len(m.approvals) > 0 {
			card := &m.approvals[m.sel]
			card.details = !card.details
			m.layout()
		} else {
			m.help = true
			m.layout()
		}
		return m, nil
	case "tab":
		if len(m.approvals) > 0 {
			if m.focus == focusTranscript {
				m.focus = focusApprovals
			} else {
				m.focus = focusTranscript
			}
			m.layout()
		}
		return m, nil
	case "y", "Y":
		m.decideSelected(true)
		return m, nil
	case "n", "N":
		m.decideSelected(false)
		return m, nil
	case "d", "D":
		if len(m.approvals) > 0 {
			m.approvals[m.sel].details = !m.approvals[m.sel].details
			m.layout()
		}
		return m, nil
	case "up", "k":
		if m.focus == focusApprovals && len(m.approvals) > 0 {
			if m.sel > 0 {
				m.sel--
				m.layout()
			}
			return m, nil
		}
	case "down", "j":
		if m.focus == focusApprovals && len(m.approvals) > 0 {
			if m.sel < len(m.approvals)-1 {
				m.sel++
				m.layout()
			}
			return m, nil
		}
	case "/":
		m.openInput(inputChat, "chat: ")
		return m, nil
	case "c", "C":
		m.openInput(inputCheckpoint, "checkpoint label: ")
		return m, nil
	case "x", "X":
		if !m.driving {
			m.connNote = "need control (g) before running commands"
			m.layout()
			return m, nil
		}
		m.openInput(inputExec, "exec $ ")
		return m, nil
	case "r", "R":
		m.openPicker()
		return m, nil
	case "g", "G":
		if m.conn != connLive {
			return m, nil
		}
		if m.driving {
			m.out.yieldControl()
			m.driving = false
			m.addLine("sys", "control returned to the novice")
		} else {
			m.out.requestControl()
			m.connNote = "control requested, waiting for the novice"
		}
		m.layout()
		return m, nil
	}

	// Transcript scrolling.
	if m.focus == focusTranscript {
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	}
	return m, nil
}

// decideSelected answers the selected approval card. Expired cards are
// never answered: the host fails closed and the TUI mirrors that.
func (m *model) decideSelected(approved bool) {
	if len(m.approvals) == 0 || m.conn != connLive {
		return
	}
	card := m.approvals[m.sel]
	if card.remaining(time.Now()) <= 0 {
		return
	}
	m.out.decide(card.req.ApprovalID, card.req, approved)
	verb := "denied"
	if approved {
		verb = "approved"
	}
	m.addLine("appr", fmt.Sprintf("you %s %q", verb, shortSummary(card.req)))
	m.approvals = append(m.approvals[:m.sel], m.approvals[m.sel+1:]...)
	m.clampSel()
	m.layout()
}

func shortSummary(req protocol.ApprovalRequest) string {
	if req.Summary != "" {
		return req.Summary
	}
	if req.Tool != "" {
		return req.Tool
	}
	return req.ApprovalID
}

// ---------- Text input ----------

func (m *model) openInput(kind inputKind, prompt string) {
	m.inputKind = kind
	m.input.Prompt = prompt
	m.input.SetValue("")
	m.input.Focus()
	m.layout()
}

func (m *model) onInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.inputKind = inputNone
		m.input.Blur()
		m.layout()
		return m, nil
	case "enter":
		val := strings.TrimSpace(m.input.Value())
		kind := m.inputKind
		m.inputKind = inputNone
		m.input.Blur()
		m.submitInput(kind, val)
		m.layout()
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *model) submitInput(kind inputKind, val string) {
	if val == "" {
		return
	}
	switch kind {
	case inputChat:
		m.out.chat(val)
		m.addLine("chat", fmt.Sprintf("%s: %s", m.expertName, val))
	case inputCheckpoint:
		m.out.checkpoint(val)
		m.addLine("ckpt", fmt.Sprintf("checkpoint %q requested", val))
	case inputExec:
		m.out.exec(val)
		m.addLine("exec", "$ "+val)
	case inputRestoreLabel:
		m.pendingRestore = val
	}
}

// ---------- Rewind picker ----------

type ckptItem string

func (i ckptItem) FilterValue() string { return string(i) }
func (i ckptItem) Title() string       { return string(i) }
func (i ckptItem) Description() string { return "" }

func (m *model) openPicker() {
	items := make([]list.Item, 0, len(m.checkpoints)+1)
	for _, c := range m.checkpoints {
		items = append(items, ckptItem(c))
	}
	items = append(items, ckptItem("type a label manually"+"\u2026"))
	m.picker.SetItems(items)
	m.picking = true
	m.layout()
}

func (m *model) onPickerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.picking = false
		m.layout()
		return m, nil
	case "enter":
		it, ok := m.picker.SelectedItem().(ckptItem)
		m.picking = false
		if !ok {
			m.layout()
			return m, nil
		}
		label := string(it)
		if strings.HasPrefix(label, "type a label") {
			m.openInput(inputRestoreLabel, "rewind to checkpoint: ")
		} else {
			m.pendingRestore = label
		}
		m.layout()
		return m, nil
	}
	var cmd tea.Cmd
	m.picker, cmd = m.picker.Update(msg)
	return m, cmd
}

// ---------- Client events ----------

func (m *model) onClientEvent(ev clientEvent) {
	switch e := ev.(type) {
	case evEnrolled:
		m.conn = connLive
		m.connNote = "connected, encrypted"
		m.addLine("sys", "enrolled, channel encrypted end to end")
	case evLatency:
		m.latency = e.d
	case evError:
		m.connNote = "error: " + e.code
		if e.message != "" {
			m.connNote += ": " + e.message
		}
		m.addLine("warn", m.connNote)
	case evSessionEnd:
		m.conn = connEnded
		m.connNote = "session ended"
		if e.reason != "" {
			m.connNote += ": " + e.reason
		}
		m.addLine("warn", m.connNote)
		m.disconnected = m.connNote
	case evClosed:
		m.conn = connEnded
		m.connNote = "disconnected"
		m.addLine("warn", "disconnected from relay")
		m.disconnected = m.connNote
	case evMessage:
		m.onMessage(e.msg, e.plain)
	}
	m.layout()
}

func (m *model) onMessage(msg protocol.Message, plain []byte) {
	switch msg.Type {
	case protocol.TypeSessionAnnounce:
		var ann protocol.SessionAnnounce
		if json.Unmarshal(plain, &ann) == nil {
			m.harness = ann.Harness
			m.addLine("sys", fmt.Sprintf("watching %s (%s), encrypted", ann.Harness, ann.AgentCmd))
		}
	case protocol.TypeTranscriptEvent:
		var te protocol.TranscriptEvent
		if json.Unmarshal(plain, &te) == nil {
			m.onTranscriptEvent(te)
		}
	case protocol.TypeApprovalRequest:
		var ar protocol.ApprovalRequest
		if json.Unmarshal(plain, &ar) == nil {
			m.onApprovalRequest(ar)
		}
	case protocol.TypeApprovalResponse:
		var resp protocol.ApprovalResponse
		if json.Unmarshal(plain, &resp) == nil && resp.Broadcast {
			m.dismissApproval(resp.ApprovalID, resp.Responder, resp.Approved)
		}
	case protocol.TypeApprovalDecision:
		// Another expert answered from an in-harness client; the MCP
		// server broadcasts the decision so all cards stay in sync.
		var dec protocol.ApprovalDecision
		if json.Unmarshal(plain, &dec) == nil {
			m.dismissApproval(dec.ApprovalID, dec.DecidedBy, dec.Decision == protocol.ApprovalApprove)
		}
	case protocol.TypeControlGrant:
		var g protocol.ControlGrant
		if json.Unmarshal(plain, &g) == nil && g.ExpertName == m.expertName {
			m.driving = true
			m.connNote = "you have control"
			m.addLine("sys", "you have control")
		}
	case protocol.TypeControlDeny:
		var d protocol.ControlDeny
		if json.Unmarshal(plain, &d) == nil && d.ExpertName == m.expertName {
			m.connNote = "control denied"
			if d.Reason != "" {
				m.connNote += ": " + d.Reason
			}
			m.addLine("warn", m.connNote)
		}
	case protocol.TypeControlYield:
		m.driving = false
		m.connNote = "connected, encrypted"
		m.addLine("sys", "control returned to the novice")
	case protocol.TypeCheckpointEvent:
		var ce protocol.CheckpointEvent
		if json.Unmarshal(plain, &ce) == nil {
			m.onCheckpointEvent(ce)
		}
	case protocol.TypeExecOutput:
		var eo protocol.ExecOutput
		if json.Unmarshal(plain, &eo) == nil {
			m.onExecOutput(eo)
		}
	case protocol.TypeTermOutput:
		// PTY fallback path: the host mirrors raw terminal bytes too.
		var to protocol.TermOutput
		if json.Unmarshal(plain, &to) == nil && to.Data != "" {
			m.addLine("result", "[pty] "+to.Data)
		}
	}
}

// onTranscriptEvent renders a structured watch-plane event into the
// transcript, tool calls inline.
func (m *model) onTranscriptEvent(te protocol.TranscriptEvent) {
	summary := ""
	if te.Fields != nil {
		if s, ok := te.Fields["summary"].(string); ok {
			summary = s
		}
	}
	switch te.Kind {
	case "tool_call":
		tool := fieldStr(te.Fields, "tool")
		line := "▸ " + tool
		if summary != "" {
			line += ": " + summary
		} else if te.Text != "" {
			line += ": " + te.Text
		}
		m.addLine("tool", line)
	case "tool_result":
		text := te.Text
		if summary != "" {
			text = summary
		}
		m.addLine("result", "  ↳ "+text)
	case "prompt":
		m.addLine("agent", "◈ "+te.Text)
	case "approval":
		m.addLine("appr", "approval raised by harness: "+te.Text)
	default:
		m.addLine("agent", te.Text)
	}
}

func fieldStr(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	s, _ := fields[key].(string)
	return s
}

// onApprovalRequest adds a card, deduped by approval id like the browser.
func (m *model) onApprovalRequest(ar protocol.ApprovalRequest) {
	if ar.ApprovalID == "" {
		return
	}
	for _, c := range m.approvals {
		if c.req.ApprovalID == ar.ApprovalID {
			return
		}
	}
	m.approvals = append(m.approvals, approvalCard{req: ar, received: time.Now()})
	m.focus = focusApprovals
	m.sel = len(m.approvals) - 1
	m.addLine("appr", fmt.Sprintf("approval requested: %s", shortSummary(ar)))
}

// dismissApproval removes the card answered elsewhere (broadcast) so every
// client stays in sync.
func (m *model) dismissApproval(id, responder string, approved bool) {
	for i, c := range m.approvals {
		if c.req.ApprovalID == id {
			m.approvals = append(m.approvals[:i], m.approvals[i+1:]...)
			m.clampSel()
			verb := "denied"
			if approved {
				verb = "approved"
			}
			who := responder
			if who == "" {
				who = "another expert"
			}
			if who == m.expertName {
				who = "you"
			}
			m.addLine("appr", fmt.Sprintf("%s %s %q", who, verb, shortSummary(c.req)))
			return
		}
	}
}

func (m *model) onCheckpointEvent(ce protocol.CheckpointEvent) {
	switch ce.Action {
	case "created":
		if ce.Label != "" {
			m.addCheckpoint(ce.Label)
		}
		m.addLine("ckpt", fmt.Sprintf("[checkpoint] created %q", ce.Label))
	case "restored":
		m.addLine("ckpt", fmt.Sprintf("[checkpoint] restored %q", ce.Label))
	case "restore_requested":
		m.addLine("ckpt", fmt.Sprintf("rewind to %q requested, waiting on the novice", ce.Label))
	case "restore_denied":
		m.addLine("warn", fmt.Sprintf("rewind to %q denied: %s", ce.Label, ce.Message))
	case "restore_expired":
		m.addLine("warn", fmt.Sprintf("rewind to %q expired: %s", ce.Label, ce.Message))
	case "failed":
		m.addLine("warn", fmt.Sprintf("checkpoint failed: %s", ce.Message))
	default:
		m.addLine("ckpt", fmt.Sprintf("[checkpoint] %s %q %s", ce.Action, ce.Label, ce.Message))
	}
}

func (m *model) addCheckpoint(label string) {
	for _, c := range m.checkpoints {
		if c == label {
			return
		}
	}
	m.checkpoints = append(m.checkpoints, label)
}

func (m *model) onExecOutput(eo protocol.ExecOutput) {
	if eo.Stdout != "" {
		m.addLine("exec", "$ →\n"+strings.TrimRight(eo.Stdout, "\n"))
	}
	if eo.Stderr != "" {
		m.addLine("warn", strings.TrimRight(eo.Stderr, "\n"))
	}
	status := fmt.Sprintf("[exit %d]", eo.ExitCode)
	if eo.Truncated {
		status += " (truncated)"
	}
	m.addLine("sys", status)
}

// ---------- Layout & view ----------

func (m *model) layout() {
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	used := 1 + 1 // header + status bar
	used += m.approvalsHeight()
	if m.inputKind != inputNone {
		used += 2
	}
	if m.pendingRestore != "" {
		used += 2
	}
	vh := h - used
	if vh < 3 {
		vh = 3
	}
	m.vp.Width = w
	m.vp.Height = vh
	m.renderLines()
	m.input.Width = w - len(m.input.Prompt) - 2
	m.picker.SetSize(w/2, 10)
}

// approvalsHeight is the vertical space the cards pane needs.
func (m *model) approvalsHeight() int {
	if len(m.approvals) == 0 {
		return 0
	}
	h := 0
	for _, c := range m.approvals {
		h += 3
		if c.details {
			h += 2
		}
	}
	if h > 14 {
		h = 14
	}
	return h
}

func (m *model) View() string {
	if m.width == 0 {
		return "starting…"
	}
	var sb strings.Builder
	sb.WriteString(m.headerView())
	sb.WriteString("\n")
	if m.picking {
		sb.WriteString(m.pickerView())
	} else {
		sb.WriteString(m.approvalsView())
		sb.WriteString(m.vp.View())
	}
	if m.pendingRestore != "" {
		sb.WriteString("\n")
		sb.WriteString(styleWarn.Render(
			fmt.Sprintf("Rewind to %q? The novice must confirm. [y]es / [n]o", m.pendingRestore)))
	}
	if m.inputKind != inputNone {
		sb.WriteString("\n")
		sb.WriteString(m.input.View())
	}
	sb.WriteString("\n")
	sb.WriteString(m.statusView())
	if m.help {
		sb.WriteString("\n")
		sb.WriteString(m.helpView())
	}
	if m.disconnected != "" && m.conn == connEnded {
		sb.WriteString("\n")
		sb.WriteString(styleWarn.Render(m.disconnected + " — press q to quit"))
	}
	return sb.String()
}

func (m *model) headerView() string {
	title := lipgloss.NewStyle().Bold(true).Render("backseat")
	sub := fmt.Sprintf("session %s · %s", m.sessionID, m.expertName)
	if m.harness != "" {
		sub += " · watching " + m.harness
	}
	return title + "  " + styleSys.Render(sub)
}

func (m *model) approvalsView() string {
	if len(m.approvals) == 0 {
		return ""
	}
	var sb strings.Builder
	now := time.Now()
	for i, card := range m.approvals {
		rem := card.remaining(now)
		ttl := fmt.Sprintf("%dm%02ds", int(rem.Minutes()), int(rem.Seconds())%60)
		if rem < 0 {
			ttl = "expired"
		}
		marker := "  "
		if m.focus == focusApprovals && i == m.sel {
			marker = "▸ "
		}
		head := fmt.Sprintf("%sApproval needed · %s · %s left", marker, shortSummary(card.req), ttl)
		body := fmt.Sprintf("  %s", shortSummary(card.req))
		if card.req.Prompt != "" && card.req.Prompt != shortSummary(card.req) {
			body = "  " + firstLine(card.req.Prompt)
		}
		keys := "  [y] approve  [n] deny  [d/?] details"
		rendered := head + "\n" + body + "\n" + keys
		if card.details {
			rendered += m.approvalDetails(card)
		}
		sb.WriteString(styleCard.Render(rendered))
		sb.WriteString("\n")
	}
	return sb.String()
}

// approvalDetails renders the expanded card body. The answer bytes stay
// server-side; the TUI shows only what the expert needs to decide.
func (m *model) approvalDetails(c approvalCard) string {
	var sb strings.Builder
	if c.req.Tool != "" {
		sb.WriteString(fmt.Sprintf("\n  tool: %s", c.req.Tool))
	}
	if c.req.Command != "" {
		sb.WriteString(fmt.Sprintf("\n  command: %s", c.req.Command))
	}
	if len(c.req.Options) > 0 {
		sb.WriteString(fmt.Sprintf("\n  options: %s", strings.Join(c.req.Options, ", ")))
	}
	if c.req.Prompt != "" {
		sb.WriteString("\n  --\n  " + c.req.Prompt)
	}
	return sb.String()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (m *model) pickerView() string {
	title := lipgloss.NewStyle().Bold(true).Render("Rewind to checkpoint")
	hint := styleSys.Render("enter: select · esc: cancel")
	return title + "\n" + m.picker.View() + "\n" + hint + "\n"
}

func (m *model) statusView() string {
	conn := "○ " + m.connNote
	if m.conn == connLive {
		conn = "● " + m.connNote
	}
	mode := "WATCHING"
	if m.driving {
		mode = "DRIVING"
	}
	lat := ""
	if m.latency > 0 {
		lat = fmt.Sprintf(" · rtt %dms", m.latency.Milliseconds())
	}
	bar := fmt.Sprintf("%s · %s · experts %d%s", conn, mode, len(m.experts), lat)
	return styleBar.Render(bar)
}

func (m *model) helpView() string {
	rows := [][2]string{
		{"y / n", "approve / deny the selected card"},
		{"tab", "move focus between transcript and approval cards"},
		{"↑↓ / j k", "select card (in approvals) · scroll (in transcript)"},
		{"? / d", "toggle card details (? opens this help in transcript)"},
		{"c", "create checkpoint"},
		{"r", "rewind to a checkpoint (novice confirms)"},
		{"/", "chat with the agent"},
		{"x", "run a shell command (needs control)"},
		{"g", "request / yield control"},
		{"q", "quit"},
	}
	var sb strings.Builder
	sb.WriteString(lipgloss.NewStyle().Bold(true).Render("Keys"))
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("\n  %-16s %s", r[0], r[1]))
	}
	sb.WriteString("\n\n  " + styleSys.Render("? or esc closes this overlay"))
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	return "\n" + box.Render(sb.String())
}
