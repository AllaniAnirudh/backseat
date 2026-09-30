// Command backseat-expert serves the expert web UI. Opening an invite link
// joins the session as a viewer; the Request control button asks the novice
// for the wheel, and terminal input is forwarded only while control is held.
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
body { background: #0d1117; color: #c9d1d9; font-family: system-ui, sans-serif; margin: 0; }
#bar { display: flex; gap: 12px; align-items: center; padding: 10px 16px; border-bottom: 1px solid #30363d; flex-wrap: wrap; }
#status { color: #8b949e; }
#mode { font-weight: bold; color: #d29922; }
#mode.driving { color: #3fb950; }
button { background: #238636; color: #fff; border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; }
button:disabled { background: #30363d; cursor: default; }
#term { height: calc(100vh - 60px); padding: 8px; }
</style>
</head>
<body>
<div id="bar">
  <strong>Backseat</strong>
  <span id="mode">VIEWING</span>
  <span id="status">connecting…</span>
  <button id="req">Request control</button>
  <button id="yield" disabled>Yield control</button>
</div>
<div id="term"></div>
<script src="/static/xterm.js"></script>
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
  var term = new Terminal({ cursorBlink: true });
  term.open(document.getElementById('term'));

  if (!sessionId) { status.textContent = 'no session in link'; return; }
  if (!secret) { status.textContent = 'no invite secret in link'; return; }

  var myName = prompt('Your name:', 'expert') || 'expert';
  var driving = false;
  var msgId = 0;

  function setMode(isDriving, label) {
    driving = isDriving;
    mode.textContent = label;
    mode.className = isDriving ? 'driving' : '';
    reqBtn.disabled = isDriving;
    yieldBtn.disabled = !isDriving;
  }
  function send(type, payload) {
    ws.send(JSON.stringify({ type: type, id: 'e' + (++msgId), ts: Date.now(), payload: payload }));
  }
  function unb64(s) {
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64encode(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  term.writeln('Joining session ' + sessionId + ' as ' + myName + '…');
  var ws = null;
  var joinAttempts = 0;

  function join() {
    joinAttempts++;
    ws.send(JSON.stringify({ type: 'room_join', id: 'e' + (++msgId), ts: Date.now(),
      payload: { session_id: sessionId, expert_name: myName, secret: secret } }));
  }

  function connect() {
    ws = new WebSocket('__BACKSEAT_RELAY__');
    ws.onopen = function () { join(); };
    ws.onclose = onClose;
    ws.onmessage = onMessage;
  }

  function onClose() {
    if (status.textContent.indexOf('ended') < 0 && status.textContent.indexOf('Error') < 0 &&
        status.textContent.indexOf('retrying') < 0)
      status.textContent = 'disconnected';
  }
  function onMessage(ev) {
    var msg = JSON.parse(ev.data), p = msg.payload || {};
    if (p.session_id && p.session_id !== sessionId) return;
    if (msg.type === 'error') {
      if (p.code === 'no_session' && joinAttempts < 6) {
        // Host's announce may still be propagating; reconnect and retry.
        status.textContent = 'session not up yet — retrying…';
        setTimeout(connect, 700);
        return;
      }
      status.textContent = 'Error: ' + (p.message || p.code);
      reqBtn.disabled = true;
      yieldBtn.disabled = true;
    }
    else if (msg.type === 'session_announce' && p.harness) {
      status.textContent = 'watching ' + p.harness + ' (' + (p.agent_cmd || '') + ')';
      term.writeln('Attached. Session harness: ' + p.harness);
    }
    else if (msg.type === 'term_output' && p.data) term.write(unb64(p.data));
    else if (msg.type === 'control_grant' && p.expert_name === myName) {
      setMode(true, 'DRIVING');
      status.textContent = 'you have control — type in the terminal';
    }
    else if (msg.type === 'control_deny' && p.expert_name === myName) {
      status.textContent = 'control denied' + (p.reason ? ': ' + p.reason : '');
    }
    else if (msg.type === 'control_yield') {
      setMode(false, 'VIEWING');
      status.textContent = 'control returned to the novice';
    }
    else if (msg.type === 'session_end') {
      setMode(false, 'ENDED');
      status.textContent = 'session ended' + (p.reason ? ': ' + p.reason : '');
      ws.close();
    }
  }

  term.onData(function (d) {
    if (!driving) return;
    send('term_input', { session_id: sessionId, data: b64encode(new TextEncoder().encode(d)) });
  });

  reqBtn.onclick = function () {
    send('control_request', { session_id: sessionId, expert_name: myName });
    status.textContent = 'control requested — waiting for the novice…';
  };
  yieldBtn.onclick = function () {
    send('control_yield', { session_id: sessionId, expert_name: myName });
    setMode(false, 'VIEWING');
    status.textContent = 'control returned to the novice';
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
