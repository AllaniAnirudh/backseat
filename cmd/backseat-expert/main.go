// Command backseat-expert serves the expert web UI. Opening an invite link
// joins the session as a viewer; the Request control button asks the novice
// for the wheel, and terminal input is forwarded only while control is held.
//
// The browser completes the HMAC enrollment with the invite secret from the
// URL fragment, derives the directional AES-GCM keys locally, and from then
// on every host<->expert payload is end-to-end encrypted: the relay only
// ever sees opaque envelopes plus routing metadata.
package main

import (
	"embed"
	"flag"
	"log"
	"net/http"
	"strings"
)

//go:embed static
var staticFS embed.FS

const pageTemplate = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backseat</title>
<link rel="stylesheet" href="/static/xterm.css">
<style>
[hidden] { display: none !important; }
body { background: #0d1117; color: #c9d1d9; font-family: system-ui, sans-serif; margin: 0; }
#bar { display: flex; gap: 12px; align-items: center; padding: 10px 16px; border-bottom: 1px solid #30363d; flex-wrap: wrap; }
#status { color: #8b949e; }
#status.secure { color: #3fb950; }
#mode { font-weight: bold; color: #d29922; }
#mode.driving { color: #3fb950; }
button { background: #238636; color: #fff; border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; }
button:disabled { background: #30363d; cursor: default; }
#term { height: calc(100vh - 60px); padding: 8px; }
#transcript { height: calc(100vh - 220px); overflow-y: auto; padding: 8px 16px; font-family: monospace; white-space: pre-wrap; }
#transcript .tk-tool { color: #79c0ff; }
#transcript .tk-result { color: #8b949e; }
#transcript .tk-agent { color: #d2a8ff; }
#transcript .tk-sys { color: #3fb950; }
#chatbar { display: flex; gap: 8px; padding: 8px 16px; border-top: 1px solid #30363d; }
#chatbar input { flex: 1; background: #161b22; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 8px; }
#execpanel { padding: 8px 16px 16px; border-top: 1px solid #30363d; }
#execpanel input { width: 60%; background: #161b22; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 8px; font-family: monospace; }
#execout { font-family: monospace; white-space: pre-wrap; margin-top: 8px; max-height: 220px; overflow-y: auto; }
#execout div { margin-bottom: 10px; border-left: 2px solid #30363d; padding-left: 8px; }
#approvals { display: flex; flex-direction: column; gap: 8px; padding: 8px 16px; }
.appr { background: #161b22; border: 1px solid #d29922; border-radius: 8px; padding: 10px 12px; }
.appr .q { font-family: monospace; white-space: pre-wrap; margin: 6px 0 10px; }
.appr button { margin-right: 8px; }
.appr .deny { background: #a40e26; }
.appr .ttl { color: #d29922; margin-left: 8px; font-size: 0.9em; }

</style>
</head>
<body>
<div id="bar">
  <strong>Backseat</strong>
  <span id="mode">VIEWING</span>
  <span id="status">connecting…</span>
  <button id="req">Request control</button>
  <button id="yield" disabled>Yield control</button>
  <button id="ckpt">Checkpoint</button>
  <button id="rewind">Rewind</button>
</div>
<div id="approvals"></div>
<div id="transcript" hidden></div>
<div id="term"></div>
<div id="chatbar" hidden>
  <input id="chatinput" type="text" placeholder="Message the agent..." autocomplete="off">
  <button id="sendchat">Send</button>
</div>
<div id="execpanel" hidden>
  <div><strong>Exec</strong> <span style="color:#8b949e">runs shell as the novice user (controller only)</span></div>
  <div style="display:flex;gap:8px;margin-top:6px">
    <input id="execinput" type="text" placeholder="shell command..." autocomplete="off" spellcheck="false">
    <button id="runexec">Run</button>
  </div>
  <div id="execout"></div>
</div>
<script src="/static/xterm.js"></script>
<script src="/static/crypto.js"></script>
<script>
(function () {
  var q = new URLSearchParams(location.search);
  var sessionId = q.get('session') || '';
  if (!sessionId) {
    var parts = location.pathname.split('/').filter(Boolean);
    if (parts[0] === 'join' && parts[1]) sessionId = parts[1];
  }
  var secret = '';
  var hash = location.hash.charAt(0) === '#' ? location.hash.slice(1) : location.hash;
  hash.split('&').forEach(function (kv) {
    var i = kv.indexOf('=');
    if (i > 0 && kv.slice(0, i) === 'secret') secret = kv.slice(i + 1);
  });

  var status = document.getElementById('status');
  var mode = document.getElementById('mode');
  var reqBtn = document.getElementById('req');
  var yieldBtn = document.getElementById('yield');
  var ckptBtn = document.getElementById('ckpt');
  var rewindBtn = document.getElementById('rewind');
  var approvalsBox = document.getElementById('approvals');
  var termBox = document.getElementById('term');
  var transcriptBox = document.getElementById('transcript');
  var chatBar = document.getElementById('chatbar');
  var chatInput = document.getElementById('chatinput');
  var sendChatBtn = document.getElementById('sendchat');
  var execPanel = document.getElementById('execpanel');
  var execInput = document.getElementById('execinput');
  var runExecBtn = document.getElementById('runexec');
  var execOut = document.getElementById('execout');
  var execBlocks = {}; // exec_request id -> result div
  var inHarness = false; // set once session_announce says harness === 'mcp'
  var term = new Terminal({ cursorBlink: true });
  term.open(document.getElementById('term'));

  if (!sessionId) { status.textContent = 'no session in link'; return; }
  if (!secret) { status.textContent = 'no invite secret in link'; return; }

  var C = window.BackseatCrypto;
  var secretBytes = C.b64urlToBytes(secret);
  var myName = prompt('Your name:', 'expert') || 'expert';
  var driving = false;
  var enrolled = false;
  var keys = null;
  var msgId = 0;

  function setMode(isDriving, label) {
    driving = isDriving;
    mode.textContent = label;
    mode.className = isDriving ? 'driving' : '';
    reqBtn.disabled = isDriving;
    yieldBtn.disabled = !isDriving;
  }
  function setSecure(label) {
    status.textContent = label;
    status.className = 'secure';
  }
  // Plaintext envelope (join + enrollment handshake only).
  function send(type, payload) {
    ws.send(JSON.stringify({ type: type, id: 'e' + (++msgId), ts: Date.now(),
      from: myName, to: 'host', payload: payload }));
  }
  // Encrypted envelope for everything after enrollment.
  async function sendEncrypted(type, obj) {
    var env = await C.seal(keys.expertToHost, new TextEncoder().encode(JSON.stringify(obj)));
    ws.send(JSON.stringify({ type: type, id: 'e' + (++msgId), ts: Date.now(),
      from: myName, to: 'host', payload: JSON.parse(env) }));
  }
  function unb64(s) {
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  term.writeln('Joining session ' + sessionId + ' as ' + myName + '…');
  var ws = null;
  var joinAttempts = 0;

  function join() {
    joinAttempts++;
    // No secret in the join: the host verifies possession via the HMAC
    // enrollment instead.
    send('room_join', { session_id: sessionId, expert_name: myName });
  }

  function connect() {
    ws = new WebSocket('__BACKSEAT_RELAY__');
    ws.onopen = function () { join(); };
    ws.onclose = onClose;
    ws.onmessage = function (ev) { onMessage(ev).catch(function () {}); };
  }

  function onClose() {
    if (status.textContent.indexOf('ended') < 0 && status.textContent.indexOf('Error') < 0 &&
        status.textContent.indexOf('retrying') < 0)
      status.textContent = 'disconnected';
  }

  async function onEnroll(msg) {
    var p = msg.payload || {};
    if (p.phase === 1 && p.challenge) {
      status.textContent = 'enrolling…';
      var challenge = C.b64ToBytes(p.challenge);
      var resp = await C.hmacResponse(secretBytes, challenge);
      keys = await C.deriveKeys(secretBytes, challenge);
      send('pairing_enroll', { session_id: sessionId, phase: 2,
        response: C.bytesToB64(resp) });
    } else if (p.phase === 3) {
      enrolled = true;
      setSecure('connected - encrypted');
    }
  }

  // In-harness mode: no PTY exists, so swap the terminal for the
  // structured transcript pane plus chat and exec. PTY sessions keep
  // the terminal byte-for-byte; this only runs for harness === 'mcp'.
  function enterInHarnessMode() {
    if (inHarness) return;
    inHarness = true;
    termBox.hidden = true;
    transcriptBox.hidden = false;
    chatBar.hidden = false;
    addTranscript('tk-sys', 'In-harness session: no terminal here. Watch the transcript, ' +
      'use chat and the approval cards; exec unlocks after a control grant.');
  }

  function addTranscript(cls, text) {
    var div = document.createElement('div');
    if (cls) div.className = cls;
    div.textContent = text;
    transcriptBox.appendChild(div);
    transcriptBox.scrollTop = transcriptBox.scrollHeight;
  }

  function fieldStr(f, k) {
    return (f && typeof f[k] === 'string') ? f[k] : '';
  }

  // Mirrors the TUI's transcript rendering: kind + text, tool calls inline.
  function renderTranscriptEvent(p) {
    var summary = fieldStr(p.fields, 'summary');
    var tool = fieldStr(p.fields, 'tool');
    switch (p.kind) {
      case 'tool_call':
        addTranscript('tk-tool', '▸ ' + (tool || 'tool') + ': ' + (summary || p.text || ''));
        break;
      case 'tool_result':
        addTranscript('tk-result', '  ↳ ' + (summary || p.text || ''));
        break;
      case 'prompt':
        addTranscript('tk-agent', '◈ ' + (p.text || ''));
        break;
      case 'approval':
        addTranscript('tk-sys', 'approval raised by harness: ' + (p.text || ''));
        break;
      default:
        addTranscript('tk-agent', p.text || '');
    }
  }

  function renderExecOutput(p) {
    var block = execBlocks[p.id];
    if (block) delete execBlocks[p.id];
    else { block = document.createElement('div'); execOut.appendChild(block); }
    var out = '';
    if (p.stdout) out += p.stdout.replace(/\s+$/, '') + '\n';
    if (p.stderr) out += '[stderr] ' + p.stderr.replace(/\s+$/, '') + '\n';
    out += '[exit ' + p.exit_code + ']' + (p.truncated ? ' (truncated)' : '');
    block.textContent = '$ ' + (block.dataset.cmd || p.id) + '\n' + out;
    execOut.scrollTop = execOut.scrollHeight;
  }

  async function onMessage(ev) {
    var msg = JSON.parse(ev.data);
    if (msg.type === 'error') {
      var pe = msg.payload || {};
      if (pe.code === 'no_session' && joinAttempts < 6) {
        // Host's announce may still be propagating; reconnect and retry.
        status.textContent = 'session not up yet - retrying…';
        setTimeout(connect, 700);
        return;
      }
      status.textContent = 'Error: ' + (pe.message || pe.code);
      reqBtn.disabled = true;
      yieldBtn.disabled = true;
      ckptBtn.disabled = true;
      rewindBtn.disabled = true;
      return;
    }
    if (msg.type === 'session_end') {
      var ps = msg.payload || {};
      setMode(false, 'ENDED');
      status.textContent = 'session ended' + (ps.reason ? ': ' + ps.reason : '');
      ws.close();
      return;
    }
    if (msg.type === 'pairing_enroll') { await onEnroll(msg); return; }
    if (!enrolled || !keys) return;
    var pt;
    try {
      pt = await C.open(keys.hostToExpert, JSON.stringify(msg.payload));
    } catch (e) {
      return; // tampered or misaddressed: drop
    }
    var p = JSON.parse(new TextDecoder().decode(pt));
    if (p.session_id && p.session_id !== sessionId) return;
    if (msg.type === 'session_announce' && p.harness) {
      if (p.harness === 'mcp') enterInHarnessMode();
      setSecure('watching ' + p.harness + ' (' + (p.agent_cmd || '') + ') - encrypted');
      term.writeln('Attached. Session harness: ' + p.harness + ' (encrypted channel)');
    }
    else if (msg.type === 'transcript_event' && inHarness) renderTranscriptEvent(p);
    else if (msg.type === 'term_output' && p.data) term.write(unb64(p.data));
    else if (msg.type === 'control_grant' && p.expert_name === myName) {
      setMode(true, 'DRIVING');
      if (inHarness) {
        setSecure('you have control: chat, approve, exec');
        execPanel.hidden = false;
        addTranscript('tk-sys', 'You have control: chat, approve, exec.');
      } else {
        setSecure('you have control - type in the terminal');
      }
    }
    else if (msg.type === 'control_deny' && p.expert_name === myName) {
      status.textContent = 'control denied' + (p.reason ? ': ' + p.reason : '');
      status.className = '';
    }
    else if (msg.type === 'control_yield') {
      setMode(false, 'VIEWING');
      if (inHarness) execPanel.hidden = true;
      setSecure('control returned to the novice - encrypted');
    }
    else if (msg.type === 'approval_request') showApproval(p);
    else if (msg.type === 'approval_response' && p.broadcast) dismissApproval(p.approval_id);
    else if (msg.type === 'approval_decision' && inHarness) {
      // Another expert answered from an in-harness client; keep cards in sync.
      dismissApproval(p.approval_id);
      if (p.approval_id) addTranscript('tk-sys',
        (p.decided_by || 'another expert') + ' ' +
        (p.decision === 'approve' ? 'approved' : 'denied') +
        ' approval ' + p.approval_id);
    }
    else if (msg.type === 'exec_output' && inHarness) renderExecOutput(p);
    else if (msg.type === 'checkpoint_event') {
      term.writeln('');
      term.writeln('[checkpoint] ' + (p.action || '') +
        (p.label ? ' "' + p.label + '"' : '') +
        (p.message ? ': ' + p.message : ''));
    }
  }

  function showApproval(p) {
    if (!p.approval_id || document.getElementById('appr-' + p.approval_id)) return;
    var card = document.createElement('div');
    card.className = 'appr';
    card.id = 'appr-' + p.approval_id;
    var title = document.createElement('div');
    title.innerHTML = '<strong>Approval needed</strong>' +
      (p.tool ? ' <span style="color:#8b949e">(' + esc(p.tool) + ')</span>' : '');
    var q = document.createElement('div');
    q.className = 'q';
    q.textContent = p.prompt || p.summary || '';
    var ok = document.createElement('button');
    ok.textContent = p.approve_label || 'Approve';
    var no = document.createElement('button');
    no.className = 'deny';
    no.textContent = p.deny_label || 'Deny';
    ok.onclick = function () { answerApproval(p.approval_id, true, p.expires_at); };
    no.onclick = function () { answerApproval(p.approval_id, false, p.expires_at); };
    card.appendChild(title);
    card.appendChild(q);
    card.appendChild(ok);
    card.appendChild(no);
    approvalsBox.appendChild(card);
    // Fail closed: auto-dismiss when the host-side TTL passes. In-harness
    // the TUI shows a visible countdown and falls back to 2 minutes when the
    // request carries no expiry; mirror both here.
    var ttlMs;
    if (inHarness) {
      ttlMs = (p.expires_at ? p.expires_at * 1000 : Date.now() + 120000) - Date.now();
      var ttl = document.createElement('span');
      ttl.className = 'ttl';
      title.appendChild(ttl);
      var tick = function () {
        if (!document.getElementById('appr-' + p.approval_id)) return;
        var ms = (p.expires_at ? p.expires_at * 1000 : Date.now() + 120000) - Date.now();
        if (ms <= 0) { ttl.textContent = 'expired'; return; }
        var s = Math.ceil(ms / 1000);
        ttl.textContent = Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2) + ' left';
        setTimeout(tick, 1000);
      };
      tick();
    } else if (p.expires_at) {
      ttlMs = p.expires_at * 1000 - Date.now();
    }
    if (ttlMs > 0) setTimeout(function () { dismissApproval(p.approval_id); }, ttlMs + 1000);
  }

  function dismissApproval(id) {
    var el = document.getElementById('appr-' + id);
    if (el) el.remove();
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  async function answerApproval(id, approved, expiresAt) {
    dismissApproval(id);
    if (!enrolled) return;
    if (inHarness) {
      // The MCP server ignores approval_response; answer with the
      // structured in-harness decision (decision + approval id + decider).
      await sendEncrypted('approval_decision', { session_id: sessionId,
        approval_id: id,
        decision: approved ? 'approve' : 'deny',
        decided_by: myName,
        decided_at: Math.floor(Date.now() / 1000),
        expires_at: expiresAt || undefined });
    } else {
      await sendEncrypted('approval_response', { session_id: sessionId,
        approval_id: id, approved: approved });
    }
  }

  term.onData(function (d) {
    if (!driving || !enrolled) return;
    sendEncrypted('term_input', { session_id: sessionId,
      data: C.bytesToB64(new TextEncoder().encode(d)) });
  });

  // In-harness chat: messages land in the novice agent's inbox via
  // expert_chat. Chat and approvals need no control grant; only exec is
  // controller-gated.
  function sendChat() {
    var text = chatInput.value.trim();
    if (!text || !enrolled) return;
    chatInput.value = '';
    sendEncrypted('expert_chat', { session_id: sessionId,
      expert_name: myName, text: text });
    addTranscript('tk-agent', 'you: ' + text);
  }
  sendChatBtn.onclick = sendChat;
  chatInput.addEventListener('keydown', function (ev) {
    if (ev.key === 'Enter') sendChat();
  });

  // In-harness exec side channel: controller-only, enforced host-side.
  function hexId() {
    var b = crypto.getRandomValues(new Uint8Array(8));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  }
  function runExec() {
    var cmd = execInput.value.trim();
    if (!cmd || !enrolled || !driving) return;
    var id = hexId();
    var block = document.createElement('div');
    block.dataset.cmd = cmd;
    block.textContent = '$ ' + cmd + '\n(running...)';
    execOut.appendChild(block);
    execOut.scrollTop = execOut.scrollHeight;
    execBlocks[id] = block;
    execInput.value = '';
    sendEncrypted('exec_request', { session_id: sessionId, id: id, command: cmd });
  }
  runExecBtn.onclick = runExec;
  execInput.addEventListener('keydown', function (ev) {
    if (ev.key === 'Enter') runExec();
  });

  reqBtn.onclick = function () {
    if (!enrolled) { status.textContent = 'still enrolling…'; return; }
    sendEncrypted('control_request', { session_id: sessionId, expert_name: myName });
    status.textContent = 'control requested - waiting for the novice…';
    status.className = '';
  };
  yieldBtn.onclick = function () {
    sendEncrypted('control_yield', { session_id: sessionId, expert_name: myName });
    setMode(false, 'VIEWING');
    setSecure('control returned to the novice - encrypted');
  };
  ckptBtn.onclick = function () {
    if (!enrolled) { status.textContent = 'still enrolling…'; return; }
    var label = prompt('Checkpoint label:', 'before-change');
    if (!label) return;
    sendEncrypted('checkpoint_create', { session_id: sessionId, label: label });
    status.textContent = 'checkpoint "' + label + '" requested…';
  };
  rewindBtn.onclick = function () {
    if (!enrolled) { status.textContent = 'still enrolling…'; return; }
    var label = prompt('Rewind to checkpoint:', '');
    if (!label) return;
    if (!confirm('Rewind to "' + label + '"? The novice must confirm. Files changed since the checkpoint will be reverted.')) return;
    sendEncrypted('checkpoint_restore', { session_id: sessionId, label: label });
    status.textContent = 'rewind to "' + label + '" requested - waiting on the novice…';
  };

  connect();
})();
</script>
</body>
</html>`

func main() {
	port := flag.String("port", ":8081", "listen address for the expert web UI")
	relayWS := flag.String("relay-ws", "ws://localhost:8080/ws", "relay WebSocket URL handed to the browser")
	flag.Parse()

	page := strings.ReplaceAll(pageTemplate, "__BACKSEAT_RELAY__", *relayWS)

	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	}
	mux.HandleFunc("/", serve)
	mux.HandleFunc("/join/", serve)
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("backseat expert UI on %s (open an invite link here)", *port)
	log.Fatal(http.ListenAndServe(*port, mux))
}
