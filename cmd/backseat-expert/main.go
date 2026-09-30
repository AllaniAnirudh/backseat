// Command backseat-expert serves a minimal web UI for the expert. Opening
// an invite link shows the live terminal, a Request control button, and
// (once granted) a driving terminal plus approval buttons. Placeholder UI:
// pairing crypto and transcript panes arrive in later milestones.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

const page = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backseat</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.5.0/css/xterm.min.css">
<style>
body { background: #0d1117; color: #c9d1d9; font-family: system-ui, sans-serif; margin: 0; }
#bar { display: flex; gap: 12px; align-items: center; padding: 10px 16px; border-bottom: 1px solid #30363d; }
#status { color: #8b949e; }
button { background: #238636; color: #fff; border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; }
button:disabled { background: #30363d; cursor: default; }
#term { height: calc(100vh - 120px); padding: 8px; }
#approvals { padding: 10px 16px; border-top: 1px solid #30363d; min-height: 40px; color: #8b949e; }
</style>
</head>
<body>
<div id="bar">
  <strong>Backseat</strong>
  <span id="status">connecting…</span>
  <button id="req">Request control</button>
  <button id="yield" disabled>Yield control</button>
</div>
<div id="term"></div>
<div id="approvals">Approval prompts from the agent will appear here.</div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.5.0/lib/xterm.min.js"></script>
<script>
(function () {
  var parts = location.pathname.split('/').filter(Boolean);
  var sessionId = parts[parts.length - 1] || '';
  var hash = location.hash.charAt(0) === '#' ? location.hash.slice(1) : location.hash;
  var secret = '';
  hash.split('&').forEach(function (kv) {
    var i = kv.indexOf('=');
    if (i > 0 && kv.slice(0, i) === 'secret') secret = kv.slice(i + 1);
  });
  var status = document.getElementById('status');
  var term = new Terminal({ cursorBlink: true });
  term.open(document.getElementById('term'));
  term.writeln('Backseat expert client. Session: ' + sessionId);
  if (!secret) term.writeln('WARNING: no invite secret in link. Pairing not possible.');

  var wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  var relay = (window.BACKSEAT_RELAY || wsProto + '//' + location.hostname + ':8080') + '/ws';
  var ws = new WebSocket(relay);
  var controlled = false;
  var msgId = 0;

  function send(type, payload) {
    ws.send(JSON.stringify({ type: type, id: 'e' + (++msgId), ts: Date.now(), payload: payload }));
  }
  function b64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function unb64(s) {
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  ws.onopen = function () { status.textContent = 'connected, viewing'; };
  ws.onclose = function () { status.textContent = 'disconnected'; };
  ws.onmessage = function (ev) {
    var msg = JSON.parse(ev.data), p = msg.payload || {};
    if (p.session_id && p.session_id !== sessionId) return;
    if (msg.type === 'term_output' && p.data) term.write(unb64(p.data));
    else if (msg.type === 'control_grant') {
      controlled = true;
      status.textContent = 'driving the session';
      document.getElementById('req').disabled = true;
      document.getElementById('yield').disabled = false;
    }
    else if (msg.type === 'control_deny') { status.textContent = 'control denied'; }
    else if (msg.type === 'approval_request') showApproval(p);
    else if (msg.type === 'session_end') { status.textContent = 'session ended'; ws.close(); }
  };

  term.onData(function (d) {
    if (!controlled) return;
    var enc = new TextEncoder().encode(d);
    send('term_input', { session_id: sessionId, data: b64(enc) });
  });

  document.getElementById('req').onclick = function () {
    var name = prompt('Your name:', 'expert') || 'expert';
    send('control_request', { session_id: sessionId, expert_name: name });
    status.textContent = 'control requested, waiting for novice…';
  };
  document.getElementById('yield').onclick = function () {
    send('control_yield', { session_id: sessionId, expert_name: 'expert' });
    controlled = false;
    status.textContent = 'viewing';
    document.getElementById('req').disabled = false;
    this.disabled = true;
  };

  function showApproval(p) {
    var box = document.getElementById('approvals');
    box.innerHTML = '';
    var label = document.createElement('span');
    label.textContent = 'Approve "' + p.tool + '": ' + p.summary + ' ';
    var yes = document.createElement('button'); yes.textContent = 'Approve';
    var no = document.createElement('button'); no.textContent = 'Deny'; no.style.background = '#da3633';
    yes.onclick = function () { send('approval_response', { session_id: sessionId, approval_id: p.approval_id, approved: true }); box.textContent = 'approved.'; };
    no.onclick = function () { send('approval_response', { session_id: sessionId, approval_id: p.approval_id, approved: false }); box.textContent = 'denied.'; };
    box.appendChild(label); box.appendChild(yes); box.appendChild(no);
  }
})();
</script>
</body>
</html>`

func main() {
	port := flag.String("port", ":8081", "listen address for the expert web UI")
	flag.Parse()

	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	}
	mux.HandleFunc("/", serve)
	mux.HandleFunc("/join/", serve)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("backseat expert UI on %s (open an invite link here)", *port)
	log.Fatal(http.ListenAndServe(*port, mux))
}
