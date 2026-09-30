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
body { background: #0d1117; color: #c9d1d9; font-family: system-ui, sans-serif; margin: 0; }
#bar { display: flex; gap: 12px; align-items: center; padding: 10px 16px; border-bottom: 1px solid #30363d; flex-wrap: wrap; }
#status { color: #8b949e; }
#status.secure { color: #3fb950; }
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
      setSecure('connected — encrypted');
    }
  }

  async function onMessage(ev) {
    var msg = JSON.parse(ev.data);
    if (msg.type === 'error') {
      var pe = msg.payload || {};
      if (pe.code === 'no_session' && joinAttempts < 6) {
        // Host's announce may still be propagating; reconnect and retry.
        status.textContent = 'session not up yet — retrying…';
        setTimeout(connect, 700);
        return;
      }
      status.textContent = 'Error: ' + (pe.message || pe.code);
      reqBtn.disabled = true;
      yieldBtn.disabled = true;
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
      setSecure('watching ' + p.harness + ' (' + (p.agent_cmd || '') + ') — encrypted');
      term.writeln('Attached. Session harness: ' + p.harness + ' (encrypted channel)');
    }
    else if (msg.type === 'term_output' && p.data) term.write(unb64(p.data));
    else if (msg.type === 'control_grant' && p.expert_name === myName) {
      setMode(true, 'DRIVING');
      setSecure('you have control — type in the terminal');
    }
    else if (msg.type === 'control_deny' && p.expert_name === myName) {
      status.textContent = 'control denied' + (p.reason ? ': ' + p.reason : '');
      status.className = '';
    }
    else if (msg.type === 'control_yield') {
      setMode(false, 'VIEWING');
      setSecure('control returned to the novice — encrypted');
    }
  }

  term.onData(function (d) {
    if (!driving || !enrolled) return;
    sendEncrypted('term_input', { session_id: sessionId,
      data: C.bytesToB64(new TextEncoder().encode(d)) });
  });

  reqBtn.onclick = function () {
    if (!enrolled) { status.textContent = 'still enrolling…'; return; }
    sendEncrypted('control_request', { session_id: sessionId, expert_name: myName });
    status.textContent = 'control requested — waiting for the novice…';
    status.className = '';
  };
  yieldBtn.onclick = function () {
    sendEncrypted('control_yield', { session_id: sessionId, expert_name: myName });
    setMode(false, 'VIEWING');
    setSecure('control returned to the novice — encrypted');
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
