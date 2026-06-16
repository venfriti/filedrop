package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.org/x/term"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	serviceName     = "filedrop"
	serviceDispName = "FileDrop LAN Server"
	cookieName      = "fd_sess"
	sessionTTL      = 24 * time.Hour
	maxUploadBytes  = 10 << 30 // 10 GB
	defaultPort     = 5743
	defaultUpload   = `D:\host`
)

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="200" height="200">
  <rect width="200" height="200" rx="36" fill="#110F0D"/>
  <rect x="52" y="128" width="96" height="20" rx="3" fill="none" stroke="#9A7D4A" stroke-width="3" stroke-linejoin="round"/>
  <line x1="52" y1="128" x2="52" y2="104" stroke="#9A7D4A" stroke-width="3" stroke-linecap="round"/>
  <line x1="148" y1="128" x2="148" y2="104" stroke="#9A7D4A" stroke-width="3" stroke-linecap="round"/>
  <rect x="74" y="48" width="52" height="66" rx="4" fill="#1C1915" stroke="#D4CFC8" stroke-width="2.5"/>
  <path d="M108,48 L126,66 L108,66 Z" fill="#110F0D" stroke="#D4CFC8" stroke-width="2.5" stroke-linejoin="round"/>
  <line x1="54" y1="58" x2="66" y2="58" stroke="#5A554E" stroke-width="2" stroke-linecap="round"/>
  <line x1="54" y1="70" x2="66" y2="70" stroke="#5A554E" stroke-width="2" stroke-linecap="round"/>
  <line x1="54" y1="82" x2="66" y2="82" stroke="#3A3530" stroke-width="2" stroke-linecap="round"/>
</svg>`

// ─── Config ───────────────────────────────────────────────────────────────────

type Config struct {
	PasswordHash  string `json:"password_hash"`
	Secret        string `json:"secret"`
	UploadDir     string `json:"upload_dir"`
	Port          int    `json:"port"`
	ExportDir     string `json:"export_dir,omitempty"`
	SessionCookie string `json:"session_cookie,omitempty"`
}

var (
	cfg     Config
	cfgPath string
	logger  *log.Logger
)

func loadConfig() error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &cfg)
}

func mustLoadConfig() {
	if err := loadConfig(); err != nil {
		fmt.Fprintln(os.Stderr, "config not found — run: filedrop.exe setup")
		os.Exit(1)
	}
}

func saveConfig() error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, data, 0600)
}

// ─── Session Auth ─────────────────────────────────────────────────────────────

func secretKey() []byte {
	b, err := hex.DecodeString(cfg.Secret)
	if err != nil {
		log.Fatal("invalid secret in config.json")
	}
	return b
}

func sessionMAC(expiry string) string {
	h := hmac.New(sha256.New, secretKey())
	h.Write([]byte(expiry))
	return hex.EncodeToString(h.Sum(nil))
}

func makeSessionValue() string {
	expiry := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	return expiry + ":" + sessionMAC(expiry)
}

func validSession(value string) bool {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, mac := parts[0], parts[1]
	if !hmac.Equal([]byte(mac), []byte(sessionMAC(expiry))) {
		return false
	}
	ts, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < ts
}

func isAuthed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return validSession(c.Value)
}

func setSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    makeSessionValue(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// sessionHoursLeft reads the session cookie and returns whole hours remaining.
func sessionHoursLeft(r *http.Request) int {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return 0
	}
	parts := strings.SplitN(c.Value, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0
	}
	h := int(time.Until(time.Unix(ts, 0)).Hours())
	if h < 0 {
		return 0
	}
	return h
}

// ─── Templates ────────────────────────────────────────────────────────────────

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FileDrop</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon.png" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=IBM+Plex+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#110f0d;--surface:#181511;--text:#d4cfc8;--muted:#5a554e;--faint:#2a2721;--rule:#221f1b;--gold:#9a7d4a;--gold-dim:#3d3020}
body{background:var(--bg);color:var(--text);font-family:'Libre Baskerville',Georgia,serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
.wrap{width:100%;max-width:360px}
.label{font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;letter-spacing:.12em;color:var(--muted);text-transform:uppercase;margin-bottom:1.75rem}
h1{font-size:1.6rem;font-weight:700;color:var(--text);margin-bottom:.2rem}
h1 span{color:var(--gold);font-weight:400;font-style:italic}
.card{background:var(--surface);border:1px solid var(--rule);border-radius:6px;padding:2rem;margin-top:1.5rem}
input[type=password]{width:100%;padding:.8rem 1rem;background:var(--bg);border:1px solid var(--faint);border-radius:4px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:.9rem;outline:none;transition:border-color .15s}
input[type=password]:focus{border-color:#3a3530}
input[type=password]::placeholder{color:var(--muted)}
button{width:100%;margin-top:.875rem;padding:.8rem 1rem;background:var(--text);color:var(--bg);border:none;border-radius:4px;font-family:'IBM Plex Mono',monospace;font-size:.8rem;font-weight:500;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.88}
.err{margin-top:.875rem;font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;color:#9a5a4a;letter-spacing:.04em}
</style>
</head>
<body>
<div class="wrap">
  <p class="label">Local Network &#xB7; Private</p>
  <h1>File<span>Drop</span></h1>
  <div class="card">
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="password" autofocus autocomplete="current-password">
      <button type="submit">Unlock</button>
      {{if .Error}}<p class="err">// incorrect password</p>{{end}}
    </form>
  </div>
</div>
</body>
</html>`))

var uploadTmpl = template.Must(template.New("upload").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FileDrop</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon.png" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=IBM+Plex+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

/* ── Dark (default) ── */
:root{
  --bg:#100e0b;--surface:#1a1714;--card:#1e1b16;
  --text:#e8ddc8;--muted:#9a8e7a;--faint:#2a2420;
  --rule:#3a3428;--gold:#c8922a;--gold-dim:#5a4420;
  --note-bg:#1e1b16;--note-border:#3a3428;
  --copy-ok:#4a8a4a
}

/* ── Light ── */
body.light{
  --bg:#f4efe6;--surface:#ede7db;--card:#e6dfd2;
  --text:#2c2520;--muted:#8a7d6e;--faint:#d4cbbe;
  --rule:#d8cfc2;--gold:#8a6830;--gold-dim:#e8d8b4;
  --note-bg:#eee8db;--note-border:#d4c8b4;
  --copy-ok:#3a6e3a
}

html,body{min-height:100%}
body{background:var(--bg);color:var(--text);font-family:'Libre Baskerville',Georgia,serif;line-height:1.6;transition:background .2s,color .2s}
.shell{max-width:980px;margin:0 auto;padding:0 2rem}

header{display:flex;justify-content:space-between;align-items:center;padding:1.75rem 0;border-bottom:1px solid var(--rule)}
.wordmark{font-size:1.1rem;font-weight:700;letter-spacing:.04em;color:var(--text)}
.wordmark span{color:var(--gold);font-weight:400;font-style:italic}
.header-meta{display:flex;align-items:center;gap:.875rem;flex-wrap:wrap}
.pill{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.06em;color:var(--muted);border:1px solid var(--faint);padding:.3rem .8rem;border-radius:999px;white-space:nowrap}
.pill.active{color:var(--gold);border-color:var(--gold-dim)}
.theme-btn{background:none;border:1px solid var(--faint);color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.06em;padding:.3rem .8rem;border-radius:999px;cursor:pointer;white-space:nowrap;transition:color .15s,border-color .15s}
.theme-btn:hover{color:var(--text);border-color:var(--rule)}
.hdr-mobile-meta{display:none;align-items:center;gap:.5rem}
.session-pill{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.06em;color:var(--muted);border:1px solid var(--faint);padding:.2rem .5rem;border-radius:999px;white-space:nowrap}
.hdr-icons{display:flex;align-items:center;gap:.05rem}
.hdr-icon-btn{background:none;border:none;color:var(--muted);font-size:1.6rem;cursor:pointer;padding:.1rem .3rem;line-height:1;display:flex;align-items:center;transition:color .15s;font-family:system-ui,-apple-system,sans-serif}
.hdr-icon-btn:hover{color:var(--text)}
.hdr-connected{font-size:1.6rem;color:#4caf50;padding:.1rem .3rem;line-height:1;display:flex;align-items:center;font-family:system-ui,-apple-system,sans-serif}

.upload-section{padding:2.5rem 0 1.5rem}
.drop-card{background:var(--surface);border:1px solid var(--rule);border-radius:6px;padding:3rem 2rem;text-align:center;cursor:pointer;transition:border-color .2s,background .2s}
.drop-card.over{border-color:var(--faint);background:var(--card)}
.drop-icon{width:40px;height:40px;margin:0 auto 1.25rem;border:1px solid var(--faint);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:var(--muted)}
.drop-label{font-size:1.2rem;font-weight:400;font-style:italic;color:var(--text);margin-bottom:.4rem}
.drop-sub{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;letter-spacing:.07em;color:var(--muted)}
#file-input{display:none}

/* compact upload row (mobile) */
.upload-compact{display:none;align-items:center;gap:1rem;padding:.875rem 1.25rem;background:var(--surface);border:1px solid var(--rule);border-radius:6px;cursor:pointer;transition:border-color .2s,background .2s}
.upload-compact:active{background:var(--card)}
.uc-icon{width:42px;height:42px;background:var(--card);border:1px solid var(--faint);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;color:var(--muted);flex-shrink:0}
.uc-text{flex:1;min-width:0}
.uc-title{font-size:.95rem;font-weight:400;font-style:italic;color:var(--text);font-family:'Libre Baskerville',Georgia,serif}
.uc-sub{font-family:'IBM Plex Mono',monospace;font-size:.68rem;font-weight:500;letter-spacing:.05em;color:var(--muted);margin-top:.15rem}
.uc-chevron{color:var(--muted);font-size:1.1rem;flex-shrink:0}
.note-btns{display:flex;gap:.5rem;flex-shrink:0}

/* progress */
#progress-wrap{display:none;margin:1.25rem 0 0}
#bar-track{background:var(--card);height:2px;overflow:hidden;margin-bottom:.5rem}
#bar{background:var(--gold);height:100%;width:0;transition:width .08s linear}
#pct{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;color:var(--muted);text-align:right}
#msg{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;min-height:1.2rem;margin-top:.75rem;letter-spacing:.04em}
#msg.ok{color:var(--copy-ok)}
#msg.err{color:#9a5a4a}

/* note input */
.note-wrap{margin-top:1rem}
.note-field{width:100%;background:var(--note-bg);border:1px solid var(--note-border);border-radius:6px;padding:1rem 1.25rem;display:flex;gap:.75rem;align-items:flex-end}
#note-input{flex:1;background:none;border:none;outline:none;resize:none;font-family:'Libre Baskerville',Georgia,serif;font-size:.95rem;color:var(--text);line-height:1.6;min-height:2.4rem;max-height:10rem;overflow-y:auto;padding:0}
#note-input::placeholder{color:var(--muted);font-style:italic}
.note-divider{display:none;height:1px;background:var(--rule)}
#paste-btn,#note-submit{background:none;border:1px solid var(--faint);color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.06em;padding:.4rem .9rem;border-radius:4px;cursor:pointer;white-space:nowrap;flex-shrink:0;transition:color .15s,border-color .15s}
#note-submit:hover{color:var(--gold);border-color:var(--gold-dim)}

/* divider */
.divider{display:flex;align-items:center;gap:1rem;margin:1.5rem 0}
.divider-line{flex:1;height:1px;background:var(--rule)}
.divider-text{font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;letter-spacing:.1em;color:var(--muted);text-transform:uppercase;white-space:nowrap}
.breadcrumb{display:none;align-items:center;gap:.3rem;margin-bottom:.75rem;flex-wrap:wrap}
.bc-item{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;color:var(--muted);cursor:pointer;transition:color .15s}
.bc-item:hover{color:var(--text)}
.bc-root{color:var(--muted)}
.bc-current{color:var(--text);cursor:default}
.bc-sep{font-family:'IBM Plex Mono',monospace;font-size:.72rem;color:var(--faint)}
.ft-dir{background:var(--card);font-family:'IBM Plex Mono',monospace;font-size:.65rem;font-weight:500;letter-spacing:.06em;color:var(--gold);border-color:var(--gold-dim)}
.dir-name{color:var(--gold) !important}
.dir-item:hover .dir-name{opacity:.8}

/* file/note list */
.file-list{display:flex;flex-direction:column}

.file-item:hover{background:var(--surface)}
.file-item+.file-item{border-top:1px solid var(--faint)}

/* note item overrides — no thumb column, spans full row */
.note-item{display:grid;grid-template-columns:1fr auto auto;align-items:center;gap:1.25rem;padding:1rem 1.25rem;border-radius:5px;background:var(--note-bg);border:1px solid var(--note-border);margin:.25rem 0;transition:background .15s;position:relative}
.note-item:hover{background:var(--card)}
.note-snippet{font-family:'Libre Baskerville',Georgia,serif;font-size:.95rem;color:var(--text);line-height:1.5;word-break:break-word}
.note-meta{font-family:'IBM Plex Mono',monospace;font-size:.68rem;font-weight:500;color:var(--muted);margin-top:.2rem;letter-spacing:.04em}
.note-actions{display:flex;align-items:center;gap:.5rem;flex-shrink:0}

.file-thumb{width:50px;height:50px;border-radius:5px;border:1px solid var(--faint);flex-shrink:0;display:flex;align-items:center;justify-content:center;overflow:hidden}
.file-thumb img{width:100%;height:100%;object-fit:cover;display:block}
.ft-pdf{background:var(--card);font-family:'IBM Plex Mono',monospace;font-size:.65rem;font-weight:500;letter-spacing:.06em;color:#6b5c3e;border-color:var(--faint)}
.ft-vid{background:var(--card);font-family:'IBM Plex Mono',monospace;font-size:.65rem;font-weight:500;letter-spacing:.06em;color:#5a4e6b;border-color:var(--faint)}
.ft-aud{background:var(--card);font-family:'IBM Plex Mono',monospace;font-size:.65rem;font-weight:500;letter-spacing:.06em;color:#3e6b56;border-color:var(--faint)}
.ft-arc{background:var(--card);font-family:'IBM Plex Mono',monospace;font-size:.65rem;font-weight:500;letter-spacing:.06em;color:#5a5a3e;border-color:var(--faint)}
.ft-file{background:var(--card);font-family:'IBM Plex Mono',monospace;font-size:.65rem;font-weight:500;letter-spacing:.06em;color:var(--muted);border-color:var(--faint)}

.file-info-col{cursor:pointer}
.file-name{font-size:1.05rem;font-weight:400;color:var(--text);line-height:1.3;word-break:break-all;transition:color .15s}
.file-info-col:hover .file-name{color:var(--gold)}
.file-name-ext{color:var(--muted)}
.file-type-date{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.04em;color:var(--muted);margin-top:.2rem}
.file-size{font-family:'IBM Plex Mono',monospace;font-size:.8rem;font-weight:400;color:var(--muted);white-space:nowrap;min-width:58px;text-align:right;opacity:.6}
.file-item{display:grid;grid-template-columns:52px 1fr auto;align-items:center;gap:1.25rem;padding:1rem;border-radius:5px;transition:background .15s;margin:0 -1rem;position:relative}
.dir-item{grid-template-columns:52px 1fr auto}
.file-actions{display:flex;align-items:center;gap:.4rem}
.action-sep{width:1px;height:1rem;background:var(--rule);flex-shrink:0;margin:0 .15rem}
.view-btn,.dl-btn,.copy-btn,.export-btn,.menu-btn{background:none;border:none;padding:.25rem .15rem;cursor:pointer;font-family:'IBM Plex Mono',monospace;font-size:1.05rem;font-weight:500;letter-spacing:.05em;white-space:nowrap;transition:color .15s}
.view-btn{color:var(--muted);font-size:.82rem}.view-btn:hover{color:var(--text)}
.dl-btn{color:var(--muted)}.dl-btn:hover{color:var(--gold)}
.export-btn{color:var(--muted)}.export-btn:hover{color:var(--gold)}
.export-btn:disabled{opacity:0;cursor:default;pointer-events:none}
.copy-btn{color:var(--muted)}.copy-btn:hover{color:var(--text)}
.copy-btn.copied{color:var(--copy-ok)}
.menu-btn{display:none;color:var(--muted);font-size:1.1rem;padding:.2rem .5rem;letter-spacing:0;line-height:1}
.menu-btn:hover{color:var(--text)}

.folder-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem;justify-content:space-between}
.folder-left{display:flex;align-items:center;gap:.75rem;flex:1;min-width:0}
.btn-lbl{font-size:.68rem;letter-spacing:.04em}

#disk-bar-wrap{display:flex;align-items:center;gap:.6rem}
#disk-bar-track{width:80px;height:3px;background:var(--faint);border-radius:2px;overflow:hidden}
#disk-bar-fill{height:100%;background:var(--gold);border-radius:2px;transition:width .3s}
#disk-label{font-family:'IBM Plex Mono',monospace;font-size:.68rem;color:var(--muted)}

.empty-state{padding:2rem 1rem;font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;color:var(--muted);letter-spacing:.06em;text-align:center}

footer{padding:1.75rem 0;border-top:1px solid var(--rule);margin-top:2rem;display:flex;justify-content:space-between;align-items:center;gap:1rem}
.ft-l{font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;letter-spacing:.07em;color:var(--muted)}
.ft-r{font-family:'IBM Plex Mono',monospace;font-size:.7rem;letter-spacing:.05em;color:var(--muted);opacity:.5;word-break:break-all}

/* search */
.search-wrap{margin-top:1rem}
.search-field{display:flex;align-items:center;background:var(--surface);border:1px solid var(--rule);border-radius:6px;padding:.5rem 1rem;gap:.5rem}
.search-icon{color:var(--muted);font-size:.9rem;flex-shrink:0}
#search-input{flex:1;background:none;border:none;outline:none;font-family:'IBM Plex Mono',monospace;font-size:.82rem;color:var(--text);min-width:0}
#search-input::placeholder{color:var(--muted)}
#search-clear{background:none;border:none;color:var(--muted);cursor:pointer;font-size:1rem;padding:0 .25rem;line-height:1;flex-shrink:0;transition:color .15s}
#search-clear:hover{color:var(--text)}
.search-snippet{font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:var(--muted);margin-top:.2rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;opacity:.8}

/* ⋮ row menu */
.row-menu{position:absolute;right:0;top:calc(100% + 2px);z-index:50;background:var(--card);border:1px solid var(--faint);border-radius:6px;min-width:150px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,.35)}
.row-menu-item{display:flex;align-items:center;gap:.6rem;padding:.65rem 1rem;font-family:'IBM Plex Mono',monospace;font-size:.78rem;font-weight:500;color:var(--muted);cursor:pointer;white-space:nowrap;background:none;border:none;width:100%;text-align:left;transition:background .1s,color .1s}
.row-menu-item:hover{background:var(--faint);color:var(--text)}

/* bulk delete */
.row-check{display:flex;align-items:center;justify-content:center}
.row-check input[type=checkbox]{width:15px;height:15px;accent-color:var(--gold);cursor:pointer;flex-shrink:0}
#select-trigger{display:none;color:#9a5a4a;background:none;border:none;cursor:pointer;padding:.1rem .15rem;line-height:1;margin-left:auto;transition:color .15s}
#select-trigger:hover{color:#c06050}
#select-bar{display:none;position:fixed;bottom:0;left:0;right:0;z-index:60;background:var(--surface);border-top:1px solid var(--rule);padding:.875rem 2rem;align-items:center;justify-content:space-between;gap:1rem}
#select-bar-count{font-family:'IBM Plex Mono',monospace;font-size:.78rem;font-weight:500;color:var(--muted);letter-spacing:.04em}
#select-bar-actions{display:flex;gap:.75rem}

/* desktop: show Delete trigger + select mode grids */
@media (min-width:641px){
  #select-trigger{display:flex;align-items:center}
  .file-list.selecting .file-item:not(.dir-item){grid-template-columns:20px 52px 1fr auto}
  .file-list.selecting .dir-item{grid-template-columns:20px 52px 1fr auto}
  .file-list.selecting .note-item{grid-template-columns:20px 1fr auto auto}
}

/* mobile: ⋮ only */
@media (max-width:640px){
  .file-item,.dir-item{grid-template-columns:52px 1fr auto!important}
  .note-item{grid-template-columns:1fr auto!important}
  .view-btn,.dl-btn,.export-btn,.note-actions,.action-sep{display:none!important}
  .menu-btn{display:flex!important;align-items:center}
  #hdr-desktop{display:none!important}
  .hdr-mobile-meta{display:flex!important}
  #select-trigger{display:none!important}
  .drop-card{display:none}
  .upload-compact{display:flex;border-radius:12px}
  .uc-icon{border-radius:8px}
  .upload-section{padding:1.25rem 0 1rem}
  .note-field{flex-direction:column;align-items:stretch;gap:0;padding:0;border-radius:12px}
  #note-input{padding:14px 16px 10px;min-height:4.5rem;max-height:8rem}
  .note-divider{display:block}
  .note-btns{align-self:stretch;padding:10px 12px;gap:8px}
  #paste-btn{flex:1;text-align:center;padding:.6rem 0;border-radius:8px}
  #note-submit{flex:1;text-align:center;padding:.6rem 0;border-radius:8px;background:#9a7d4a;color:#100e0b;border:none;font-weight:500}
  #note-submit:hover{color:var(--bg);border-color:transparent}
}

/* modal */
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;align-items:center;justify-content:center;padding:1.5rem}
#modal.open{display:flex}
#modal-box{background:var(--card);border:1px solid var(--faint);border-radius:8px;max-width:90vw;max-height:90vh;overflow:auto;display:flex;flex-direction:column;min-width:320px}
#modal-header{display:flex;align-items:center;justify-content:space-between;padding:.875rem 1.25rem;border-bottom:1px solid var(--rule);flex-shrink:0}
#modal-filename{font-family:'IBM Plex Mono',monospace;font-size:.8rem;font-weight:500;color:var(--text);word-break:break-all;padding-right:1rem}
#modal-close{background:none;border:none;color:var(--muted);font-size:1.4rem;cursor:pointer;line-height:1;padding:.1rem .3rem;transition:color .15s;flex-shrink:0}
#modal-close:hover{color:var(--text)}
#modal-content{padding:1.25rem;display:flex;align-items:center;justify-content:center;min-height:120px}
#modal-content img{max-width:80vw;max-height:70vh;display:block;border-radius:4px}
#modal-content video{max-width:80vw;max-height:70vh;display:block;border-radius:4px;outline:none}
#modal-content audio{width:420px;max-width:80vw;outline:none}
#modal-content iframe{width:75vw;height:70vh;border:none;display:block}
#modal-content pre{font-family:'IBM Plex Mono',monospace;font-size:.85rem;color:var(--text);white-space:pre-wrap;word-break:break-word;max-width:70vw;max-height:65vh;overflow:auto;line-height:1.7}
#modal-footer{padding:.875rem 1.25rem;border-top:1px solid var(--rule);display:flex;justify-content:flex-end;gap:.75rem;flex-shrink:0}
#modal-dl{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;letter-spacing:.06em;color:var(--muted);background:none;border:1px solid var(--faint);padding:.45rem 1rem;border-radius:4px;cursor:pointer;transition:color .15s,border-color .15s}
#modal-dl:hover{color:var(--gold);border-color:var(--gold-dim)}
#modal-copy{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;letter-spacing:.06em;color:var(--muted);background:none;border:1px solid var(--faint);padding:.45rem 1rem;border-radius:4px;cursor:pointer;transition:color .15s,border-color .15s;display:none}
#modal-copy:hover{color:var(--text);border-color:var(--rule)}
</style>
</head>
<body>
<div class="shell">
  <header>
    <div class="wordmark">File<span>Drop</span></div>
    <div class="header-meta" id="hdr-desktop">
      <span class="pill active">&#x25CF; Connected</span>
      <span class="pill">:{{.Port}}</span>
      <span class="pill">Session {{.SessionHours}}h left</span>
      <button class="theme-btn" id="qr-btn" onclick="showQR()">&#x25A6; QR</button>
      <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">&#9728; Light</button>
    </div>
    <div class="hdr-mobile-meta" id="hdr-mobile">
      <span class="session-pill">{{.SessionHours}}h left</span>
      <div class="hdr-icons">
        <button class="hdr-icon-btn" id="theme-btn-m" onclick="toggleTheme()">&#9728;&#xFE0E;</button>
        <button class="hdr-icon-btn" onclick="showQR()">&#x25A6;&#xFE0E;</button>
        <span class="hdr-connected">&#x2299;</span>
      </div>
    </div>
  </header>

  <div class="upload-section">
    <div class="drop-card" id="drop">
      <div class="drop-icon">&#x2193;</div>
      <p class="drop-label">Drop files to upload</p>
      <p class="drop-sub">any format &nbsp;&#xB7;&nbsp; up to 10 GB &nbsp;&#xB7;&nbsp; click to browse</p>
      <input type="file" id="file-input" multiple>
    </div>
    <div class="upload-compact" onclick="document.getElementById('file-input').click()">
      <div class="uc-icon">&#x2191;</div>
      <div class="uc-text">
        <div class="uc-title">Upload files</div>
        <div class="uc-sub">any format · up to 10 GB</div>
      </div>
      <span class="uc-chevron">&#x203A;</span>
    </div>
    <div id="progress-wrap">
      <div id="bar-track"><div id="bar"></div></div>
      <div id="pct">0%</div>
    </div>
    <div id="msg"></div>

    <div class="note-wrap">
      <div class="note-field">
        <textarea id="note-input" rows="3" placeholder="Add a note or paste text..."></textarea>
        <div class="note-divider"></div>
        <div class="note-btns"><button id="paste-btn">⇳ Paste</button><button id="note-submit">&#x23CE; Save note</button></div>
      </div>
    </div>
  </div>

  <div class="search-wrap">
    <div class="search-field">
      <span class="search-icon">&#x2315;</span>
      <input id="search-input" type="search" placeholder="Search names and file contents...">
      <button id="search-clear" style="display:none">&#xD7;</button>
    </div>
  </div>

  <div class="divider">
    <div class="divider-line"></div>
    <span class="divider-text" id="divider-text">Loading...</span>
    <div class="divider-line"></div>
  </div>

  <div class="folder-row">
    <div class="breadcrumb" id="breadcrumb" style="margin-bottom:0;flex:1"></div>
    <button id="select-trigger" onclick="enterSelectMode()" title="Select to delete"><svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="2,4 14,4"/><path d="M5 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M13 4l-.8 10H3.8L3 4"/><line x1="6.5" y1="7" x2="6.5" y2="11"/><line x1="9.5" y1="7" x2="9.5" y2="11"/></svg></button>
  </div>
  <div class="file-list" id="file-list"></div>

  <footer>
    <span class="ft-l">FileDrop &nbsp;&#xB7;&nbsp; LAN only</span>
    <div id="disk-bar-wrap" style="display:none">
      <div id="disk-bar-track"><div id="disk-bar-fill" style="width:0%"></div></div>
      <span id="disk-label"></span>
    </div>
    <span class="ft-r">{{.UploadDir}}</span>
  </footer>
</div>

<div id="select-bar">
  <span id="select-bar-count">0 selected</span>
  <div id="select-bar-actions">
    <button class="folder-btn" onclick="exitSelectMode()">Cancel</button>
    <button class="folder-btn" id="select-bar-delete" style="color:#9a5a4a;border-color:#9a5a4a" onclick="confirmBulkDelete()" disabled>Delete selected</button>
  </div>
</div>

<div id="modal">
  <div id="modal-box">
    <div id="modal-header">
      <span id="modal-filename"></span>
      <button id="modal-close" onclick="closeModal()">&#xD7;</button>
    </div>
    <div id="modal-content"></div>
    <div id="modal-footer">
      <button id="modal-copy">&#x2398; Copy text</button>
      <button id="modal-dl">&#x2193; Download</button>
    </div>
  </div>
</div>

<script>

var drop = document.getElementById('drop');
var fi   = document.getElementById('file-input');
var bar  = document.getElementById('bar');
var pct  = document.getElementById('pct');
var prog = document.getElementById('progress-wrap');
var msg  = document.getElementById('msg');
var list = document.getElementById('file-list');
var divT = document.getElementById('divider-text');
var breadcrumbEl = document.getElementById('breadcrumb');
var modal    = document.getElementById('modal');
var mName    = document.getElementById('modal-filename');
var mContent = document.getElementById('modal-content');
var mDl      = document.getElementById('modal-dl');
var mCopy    = document.getElementById('modal-copy');
var activeFile = '';
var noteFullText = '';
var currentPath = '';
var currentFiles = [];
var selectMode = false;
var selectedPaths = new Set();
var activeMenu = null;

// ── ⋮ menu ────────────────────────────────────────────────────────────────────
function openMenu(btn, actions) {
  closeMenu();
  var menu = document.createElement('div');
  menu.className = 'row-menu';
  actions.forEach(function(a) {
    var item = document.createElement('button');
    item.className = 'row-menu-item';
    item.textContent = a.label;
    item.addEventListener('click', function(e) { e.stopPropagation(); a.fn(); });
    menu.appendChild(item);
  });
  btn.parentElement.appendChild(menu);
  activeMenu = menu;
}
function closeMenu() {
  if (activeMenu) { activeMenu.remove(); activeMenu = null; }
}
document.addEventListener('click', function(e) {
  if (activeMenu && !activeMenu.contains(e.target)) closeMenu();
});

// ── Bulk delete ───────────────────────────────────────────────────────────────
function enterSelectMode() {
  selectMode = true;
  list.classList.add('selecting');
  document.getElementById('select-bar').style.display = 'flex';
  document.getElementById('select-trigger').style.display = 'none';
  updateSelectBar();
  renderList(currentFiles);
}
function exitSelectMode() {
  selectMode = false;
  selectedPaths.clear();
  list.classList.remove('selecting');
  document.getElementById('select-bar').style.display = 'none';
  document.getElementById('select-trigger').style.display = '';
  renderList(currentFiles);
}
function toggleSelect(path, checked) {
  if (checked) { selectedPaths.add(path); } else { selectedPaths.delete(path); }
  updateSelectBar();
}
function updateSelectBar() {
  var n = selectedPaths.size;
  document.getElementById('select-bar-count').textContent = n + ' selected';
  document.getElementById('select-bar-delete').disabled = n === 0;
}
function confirmBulkDelete() {
  if (!selectedPaths.size) return;
  var paths = Array.from(selectedPaths);
  var done = 0, failed = 0;
  function next(i) {
    if (i >= paths.length) {
      exitSelectMode();
      loadFiles();
      if (failed > 0) { msg.className='err'; msg.textContent='// '+done+' deleted, '+failed+' failed (non-empty folders cannot be deleted)'; }
      return;
    }
    fetch('/delete?name='+encodeURIComponent(paths[i]), {method:'POST'})
      .then(function(r){ if(r.ok) done++; else failed++; next(i+1); })
      .catch(function(){ failed++; next(i+1); });
  }
  next(0);
}

function deleteItem(path) {
  fetch('/delete?name='+encodeURIComponent(path), {method:'POST'})
    .then(function(r){
      if (r.ok) { loadFiles(); }
      else { r.text().then(function(t){ msg.className='err'; msg.textContent='// delete: '+t; }); }
    })
    .catch(function(){ msg.className='err'; msg.textContent='// delete: network error'; });
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportFile(path, btn) {
  if (btn) btn.disabled = true;
  var orig = btn ? btn.textContent : '';
  fetch('/export?name='+encodeURIComponent(path), {method:'POST'})
    .then(function(r) {
      if (r.ok) {
        closeMenu();
        if (btn) { btn.textContent = '✓'; setTimeout(function() { btn.textContent = orig; btn.disabled = false; }, 1800); }
      } else {
        r.text().then(function(t){ msg.className='err'; msg.textContent='// export: '+t; });
        if (btn) btn.disabled = false;
        closeMenu();
      }
    })
    .catch(function() { msg.className='err'; msg.textContent='// export: network error'; if (btn) btn.disabled = false; closeMenu(); });
}


// ── QR code ───────────────────────────────────────────────────────────────────
function showQR() {
  mName.textContent = 'Scan to open on this device';
  mContent.innerHTML = '<img src="/qr.png" alt="QR" style="width:220px;height:220px;image-rendering:pixelated">';
  mDl.style.display = 'none';
  mCopy.style.display = 'none';
  modal.classList.add('open');
  document.body.style.overflow = 'hidden';
}

// ── Disk usage ────────────────────────────────────────────────────────────────
function loadDisk() {
  fetch('/disk').then(function(r){return r.json();}).then(function(d){
    if (!d.total) return;
    var used = d.total - d.free;
    var pct = Math.round(used / d.total * 100);
    var wrap = document.getElementById('disk-bar-wrap');
    document.getElementById('disk-bar-fill').style.width = pct + '%';
    document.getElementById('disk-label').textContent = fmtSize(d.free) + ' free';
    wrap.style.display = 'flex';
  }).catch(function(){});
}

// ── Theme ──────────────────────────────────────────────────────────────────────
function toggleTheme() {
  var light = document.body.classList.toggle('light');
  document.getElementById('theme-btn').textContent = light ? '\u263e Dark' : '\u2600 Light';
  var m = document.getElementById('theme-btn-m');
  if (m) m.textContent = light ? '\u263e\ufe0e' : '\u2600\ufe0e';
  try { localStorage.setItem('fd_theme', light ? 'light' : 'dark'); } catch(e){}
}
(function(){
  try {
    if (localStorage.getItem('fd_theme') === 'light') {
      document.body.classList.add('light');
      document.getElementById('theme-btn').textContent = '\u263e Dark';
      var m = document.getElementById('theme-btn-m');
      if (m) m.textContent = '\u263e\ufe0e';
    }
  } catch(e){}
})();

// ── Clipboard helper — works on HTTP ─────────────────────────────────────────
function copyText(text, btn, originalLabel) {
  function done() {
    if (btn) {
      btn.textContent = '\u2714 copied';
      btn.classList.add('copied');
      setTimeout(function(){ btn.textContent = originalLabel; btn.classList.remove('copied'); }, 1800);
    }
  }
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(fallback);
  } else {
    fallback();
  }
  function fallback() {
    var el = document.createElement('textarea');
    el.value = text;
    el.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
    document.body.appendChild(el);
    el.focus(); el.select();
    try { document.execCommand('copy'); done(); } catch(e) {}
    document.body.removeChild(el);
  }
}

// ── Drag and drop ──────────────────────────────────────────────────────────────
drop.addEventListener('click', function(e){ if(e.target!==fi) fi.click(); });
drop.addEventListener('dragover', function(e){ e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', function(e){ if(!drop.contains(e.relatedTarget)) drop.classList.remove('over'); });
drop.addEventListener('drop', function(e){ e.preventDefault(); drop.classList.remove('over'); upload(e.dataTransfer.files); });
fi.addEventListener('change', function(){ upload(fi.files); fi.value=''; });

// ── Upload ────────────────────────────────────────────────────────────────────
function upload(files) {
  if (!files || !files.length) return;
  var fd = new FormData();
  for (var i=0; i<files.length; i++) fd.append('files', files[i]);
  prog.style.display='block'; bar.style.width='0'; pct.textContent='0%';
  msg.className=''; msg.textContent='';
  var url = '/upload' + (currentPath ? '?path=' + encodeURIComponent(currentPath) : '');
  var xhr = new XMLHttpRequest();
  xhr.upload.addEventListener('progress', function(e){
    if (e.lengthComputable){ var p=Math.round(e.loaded/e.total*100); bar.style.width=p+'%'; pct.textContent=p+'%'; }
  });
  xhr.addEventListener('load', function(){
    prog.style.display='none';
    if (xhr.status===200){ msg.className='ok'; msg.textContent='// uploaded'; loadFiles(); }
    else { msg.className='err'; msg.textContent='// failed: '+xhr.responseText; }
  });
  xhr.addEventListener('error', function(){ prog.style.display='none'; msg.className='err'; msg.textContent='// network error'; });
  xhr.open('POST', url); xhr.send(fd);
}

// ── Note ──────────────────────────────────────────────────────────────────────
var noteInput  = document.getElementById('note-input');
var noteSubmit = document.getElementById('note-submit');
var pasteBtn   = document.getElementById('paste-btn');

noteInput.addEventListener('input', function(){
  this.style.height='auto';
  this.style.height=Math.min(this.scrollHeight, 160)+'px';
});
noteInput.addEventListener('keydown', function(e){
  if (e.key==='Enter' && !e.shiftKey){ e.preventDefault(); saveNote(); }
});
noteSubmit.addEventListener('click', saveNote);

// Paste event on note field — images upload directly, text pastes normally
noteInput.addEventListener('paste', function(e) {
  var items = e.clipboardData && e.clipboardData.items;
  if (!items) return;
  var imageFile = null;
  for (var i = 0; i < items.length; i++) {
    if (items[i].type.indexOf('image') !== -1) {
      imageFile = items[i].getAsFile();
      break;
    }
  }
  if (!imageFile) return;
  e.preventDefault();
  var ext = imageFile.type.split('/')[1] || 'png';
  var named = new File([imageFile], 'clipboard_' + Date.now() + '.' + ext, {type: imageFile.type});
  upload([named]);
  var orig = pasteBtn.textContent;
  pasteBtn.textContent = '\u2713 image captured';
  setTimeout(function(){ pasteBtn.textContent = orig; }, 1800);
});


// Paste button — reads clipboard if available (HTTPS/localhost), otherwise focuses textarea
pasteBtn.addEventListener('click', function() {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.readText().then(function(text) {
      noteInput.value = text;
      noteInput.style.height = 'auto';
      noteInput.style.height = Math.min(noteInput.scrollHeight, 160) + 'px';
      noteInput.focus();
    }).catch(function() {
      focusForManualPaste();
    });
  } else {
    focusForManualPaste();
  }
});

function focusForManualPaste() {
  noteInput.focus();
  noteInput.select();
  pasteBtn.textContent = '\u23ce paste here';
  setTimeout(function(){ pasteBtn.textContent = '\u21f3 Paste'; }, 2000);
}

function saveNote() {
  var text = noteInput.value.trim();
  if (!text) return;
  fetch('/note', {method:'POST', body:text})
    .then(function(r){
      if (r.ok){ noteInput.value=''; noteInput.style.height=''; loadFiles(); }
      else { msg.className='err'; msg.textContent='// note save failed'; }
    })
    .catch(function(){ msg.className='err'; msg.textContent='// network error'; });
}

// ── Folder navigation ─────────────────────────────────────────────────────────
function navigateTo(path) {
  currentPath = path;
  renderBreadcrumb();
  loadFiles();
}

function renderBreadcrumb() {
  if (!breadcrumbEl) return;
  var parts = currentPath ? currentPath.split('/').filter(Boolean) : [];
  if (parts.length === 0) {
    breadcrumbEl.style.display = 'none';
    return;
  }
  breadcrumbEl.style.display = 'flex';
  var html = '<span class="bc-item bc-root" data-path="">root</span>';
  var cumPath = '';
  for (var i = 0; i < parts.length; i++) {
    cumPath += (cumPath ? '/' : '') + parts[i];
    var isLast = i === parts.length - 1;
    html += '<span class="bc-sep">/</span>';
    if (isLast) {
      html += '<span class="bc-item bc-current">' + esc(parts[i]) + '</span>';
    } else {
      html += '<span class="bc-item" data-path="' + esc(cumPath) + '">' + esc(parts[i]) + '</span>';
    }
  }
  breadcrumbEl.innerHTML = html;
  breadcrumbEl.querySelectorAll('[data-path]').forEach(function(el) {
    el.addEventListener('click', function() { navigateTo(this.dataset.path); });
  });
}

// ── File list ─────────────────────────────────────────────────────────────────
function loadFiles() {
  var url = '/files' + (currentPath ? '?path=' + encodeURIComponent(currentPath) : '');
  fetch(url).then(function(r){return r.json();}).then(function(files){
    currentFiles = files || [];
    lastFilesJSON = JSON.stringify(files);
    renderList(currentFiles);
  }).catch(function(){ list.innerHTML='<div class="empty-state">// error loading</div>'; });
}

function renderList(files) {
  list.innerHTML='';
  if (!files||!files.length){
    divT.textContent = currentPath ? 'Empty folder' : 'Empty';
    list.innerHTML='<div class="empty-state">// nothing here yet</div>';
    return;
  }
  var totalBytes=0, fileCount=0;
  for (var i=0;i<files.length;i++) {
    if (!files[i].is_note && !files[i].is_dir) { totalBytes+=files[i].size; fileCount++; }
  }
  var dirCount = files.filter(function(f){return f.is_dir;}).length;
  var label = '';
  if (dirCount) label += dirCount + ' folder' + (dirCount!==1?'s':'');
  if (fileCount) label += (label?' · ':'')+fileCount+' file'+(fileCount!==1?'s':'');
  if (totalBytes) label += ' · '+fmtSize(totalBytes);
  divT.textContent = label || 'Empty';
  for (var i=0;i<files.length;i++){
    if (files[i].is_dir) list.appendChild(makeDirRow(files[i]));
    else if (files[i].is_note) list.appendChild(makeNoteRow(files[i]));
    else list.appendChild(makeFileRow(files[i]));
  }
}

function makeDirRow(f) {
  var el = document.createElement('div');
  el.className = 'file-item dir-item';
  el.style.cursor = 'pointer';
  var dirPath = currentPath ? currentPath+'/'+f.name : f.name;
  var displayName = f.name.split('/').pop();
  var parentDir = f.name.includes('/') ? f.name.slice(0, f.name.lastIndexOf('/')) : '';
  var checkHtml = selectMode ? '<label class="row-check"><input type="checkbox"'+(selectedPaths.has(dirPath)?' checked':'')+' data-path="'+esc(dirPath)+'"></label>' : '';
  el.innerHTML =
    checkHtml+
    '<div class="file-thumb ft-dir">DIR</div>'+
    '<div class="file-info-col" style="cursor:pointer">'+
      '<div class="file-name dir-name">'+esc(displayName)+'</div>'+
      '<div class="file-type-date">Folder \u00B7 '+fmtDate(f.modified)+(parentDir?' \u00B7 <span style="opacity:.6">'+esc(parentDir)+'</span>':'')+'</div>'+
    '</div>'+
    '<div class="file-actions">'+
      '<button class="view-btn" title="Open">\u25B7 <span class="btn-lbl">open</span></button>'+
      '<button class="menu-btn" title="Options">\u22EE</button>'+
    '</div>';
  if (selectMode) {
    var cb = el.querySelector('input[type=checkbox]');
    el.addEventListener('click', function(e) {
      if (e.target.tagName==='BUTTON'||e.target.tagName==='INPUT'||e.target.tagName==='LABEL') return;
      cb.checked = !cb.checked; toggleSelect(dirPath, cb.checked);
    });
    cb.addEventListener('change', function() { toggleSelect(dirPath, this.checked); });
  } else {
    var enterDir = (function(p){ return function(){ navigateTo(p); }; })(dirPath);
    el.querySelector('.view-btn').addEventListener('click', function(e){ e.stopPropagation(); enterDir(); });
    el.addEventListener('click', function(e){
      if (e.target.closest('button,input,label')) return;
      enterDir();
    });
    el.querySelector('.menu-btn').addEventListener('click', (function(p){ return function(e){
      e.stopPropagation();
      openMenu(e.currentTarget, [
        {label:'↗ Export folder', fn:function(){ exportFile(p,null); }},
        {label:'✕ Delete', fn:function(){ deleteItem(p); closeMenu(); }}
      ]);
    }; })(dirPath));
  }
  return el;
}

function makeNoteRow(f) {
  var el = document.createElement('div');
  el.className = 'note-item';
  var notePath = currentPath ? currentPath+'/'+f.name : f.name;
  var parentDir = f.name.includes('/') ? f.name.slice(0, f.name.lastIndexOf('/')) : '';
  var checkHtml = selectMode ? '<label class="row-check"><input type="checkbox"'+(selectedPaths.has(notePath)?' checked':'')+' data-path="'+esc(notePath)+'"></label>' : '';
  el.innerHTML =
    checkHtml+
    '<div>'+
      '<div class="note-snippet">'+esc(f.snippet||'')+'</div>'+
      '<div class="note-meta">Note \u00B7 '+fmtDate(f.modified)+(parentDir?' \u00B7 <span style="opacity:.6">'+esc(parentDir)+'</span>':'')+'</div>'+
    '</div>'+
    '<div class="note-actions">'+
      '<button class="copy-btn" title="Copy text">\u2398 <span class="btn-lbl">copy</span></button>'+
      '<div class="action-sep"></div>'+
      '<button class="view-btn" title="Preview">\u25B7 <span class="btn-lbl">view</span></button>'+
      '<div class="action-sep"></div>'+
      '<button class="export-btn" title="Copy to export folder">\u2197 <span class="btn-lbl">upl</span></button>'+
    '</div>'+
    '<button class="menu-btn" title="Options">\u22EE</button>';
  if (selectMode) {
    var cb = el.querySelector('input[type=checkbox]');
    el.addEventListener('click', function(e) {
      if (e.target.tagName==='BUTTON'||e.target.tagName==='INPUT'||e.target.tagName==='LABEL') return;
      cb.checked = !cb.checked; toggleSelect(notePath, cb.checked);
    });
    cb.addEventListener('change', function() { toggleSelect(notePath, this.checked); });
  } else {
    var copyBtn = el.querySelector('.copy-btn');
    copyBtn.addEventListener('click', (function(p,btn){
      return function(e){
        e.stopPropagation();
        fetch('/file?name='+encodeURIComponent(p)).then(function(r){return r.text();}).then(function(text){
          copyText(text, btn, '\u2398');
        });
      };
    })(notePath, copyBtn));
    el.querySelector('.view-btn').addEventListener('click', function(e){ e.stopPropagation(); openNotePreview(notePath); });
    var expBtn = el.querySelector('.export-btn');
    expBtn.addEventListener('click', (function(p,b){ return function(e){ e.stopPropagation(); exportFile(p,b); }; })(notePath, expBtn));
    el.addEventListener('click', function(e){
      if (e.target.closest('button,input,label')) return;
      openNotePreview(notePath);
    });
    el.querySelector('.menu-btn').addEventListener('click', (function(p){ return function(e){
      e.stopPropagation();
      openMenu(e.currentTarget, [
        {label:'\u2398 Copy text', fn:function(){
          fetch('/file?name='+encodeURIComponent(p)).then(function(r){return r.text();}).then(function(t){ copyText(t,null,''); closeMenu(); });
        }},
        {label:'\u2197 Export', fn:function(){ exportFile(p,null); }},
        {label:'✕ Delete', fn:function(){ deleteItem(p); closeMenu(); }}
      ]);
    }; })(notePath));
  }
  return el;
}

function makeFileRow(f) {
  var displayName = f.name.split('/').pop();
  var ext = displayName.includes('.') ? displayName.split('.').pop().toLowerCase() : '';
  var base = ext ? displayName.slice(0,displayName.length-ext.length-1) : displayName;
  var kind = previewKind(ext);
  var filePath = currentPath ? currentPath+'/'+f.name : f.name;
  var parentDir = f.name.includes('/') ? f.name.slice(0, f.name.lastIndexOf('/')) : '';
  var checkHtml = selectMode ? '<label class="row-check"><input type="checkbox"'+(selectedPaths.has(filePath)?' checked':'')+' data-path="'+esc(filePath)+'"></label>' : '';
  var el = document.createElement('div');
  el.className = 'file-item';
  var metaLine = fileType(ext)+' \u00B7 '+fmtDate(f.modified)+' \u00B7 '+fmtSize(f.size)+(parentDir?' \u00B7 <span style="opacity:.6">'+esc(parentDir)+'</span>':'');
  el.innerHTML =
    checkHtml+
    '<div class="file-thumb '+thumbCls(ext)+'">'+thumb(displayName,ext,filePath)+'</div>'+
    '<div class="file-info-col">'+
      '<div class="file-name">'+esc(base)+'<span class="file-name-ext">'+(ext?'.'+esc(ext):'')+'</span></div>'+
      '<div class="file-type-date">'+metaLine+'</div>'+
      (f.snippet?'<div class="search-snippet">'+esc(f.snippet)+'</div>':'')+
    '</div>'+
    '<div class="file-actions">'+
      (kind ? '<button class="view-btn" title="Preview">&#x25B7; <span class="btn-lbl">view</span></button><div class="action-sep"></div>' : '')+
      '<button class="export-btn" title="Copy to export folder">&#x2197; <span class="btn-lbl">upl</span></button>'+
      '<button class="dl-btn" title="Download">&#x2193; <span class="btn-lbl">dl</span></button>'+
      '<button class="menu-btn" title="Options">&#x22EE;</button>'+
    '</div>';
  if (selectMode) {
    var cb = el.querySelector('input[type=checkbox]');
    el.addEventListener('click', function(e) {
      if (e.target.tagName==='BUTTON'||e.target.tagName==='INPUT'||e.target.tagName==='LABEL') return;
      cb.checked = !cb.checked; toggleSelect(filePath, cb.checked);
    });
    cb.addEventListener('change', function() { toggleSelect(filePath, this.checked); });
  } else {
    if (!kind) el.querySelector('.file-info-col').style.cursor = 'default';
    el.addEventListener('click', (function(p,k){ return function(e){
      if (e.target.closest('button,input,label')) return;
      if (k) openPreview(p);
    }; })(filePath, kind));
    if (kind) el.querySelector('.view-btn').addEventListener('click',(function(p){return function(e){ e.stopPropagation(); openPreview(p); };})(filePath));
    el.querySelector('.dl-btn').addEventListener('click',(function(p){return function(e){ e.stopPropagation(); dlFile(p); };})(filePath));
    var expBtn = el.querySelector('.export-btn');
    expBtn.addEventListener('click',(function(p,b){return function(e){ e.stopPropagation(); exportFile(p,b); };})(filePath,expBtn));
    el.querySelector('.menu-btn').addEventListener('click', (function(p){ return function(e){
      e.stopPropagation();
      openMenu(e.currentTarget, [
        {label:'↓ Download', fn:function(){ dlFile(p); closeMenu(); }},
        {label:'↗ Export', fn:function(){ exportFile(p,null); }},
        {label:'✕ Delete', fn:function(){ deleteItem(p); closeMenu(); }}
      ]);
    }; })(filePath));
  }
  return el;
}

// ── Preview ───────────────────────────────────────────────────────────────────
function openNotePreview(path) {
  fetch('/file?name='+encodeURIComponent(path)).then(function(r){return r.text();}).then(function(text){
    noteFullText = text;
    activeFile = path;
    mName.textContent = 'Note';
    mContent.innerHTML = '<pre>'+esc(text)+'</pre>';
    mDl.style.display='none';
    mCopy.style.display='';
    mCopy.textContent = '\u2398 Copy text';
    mCopy.onclick = function(){ copyText(noteFullText, mCopy, '\u2398 Copy text'); };
    modal.classList.add('open');
    document.body.style.overflow='hidden';
  });
}

function openPreview(path) {
  var ext = path.includes('.') ? path.split('.').pop().toLowerCase() : '';
  var kind = previewKind(ext);
  if (!kind){ dlFile(path); return; }
  var url='/file?name='+encodeURIComponent(path);
  var html='';
  if (kind==='image') html='<img src="'+url+'" alt="'+esc(path)+'">';
  else if (kind==='video') html='<video src="'+url+'" controls autoplay></video>';
  else if (kind==='audio') html='<audio src="'+url+'" controls autoplay></audio>';
  else if (kind==='pdf') html='<iframe src="'+url+'"></iframe>';
  activeFile=path;
  mName.textContent=path.split('/').pop();
  mContent.innerHTML=html;
  mDl.style.display='';
  mCopy.style.display='none';
  mDl.onclick=function(){ dlFile(activeFile); };
  modal.classList.add('open');
  document.body.style.overflow='hidden';
}

function closeModal() {
  modal.classList.remove('open');
  mContent.innerHTML='';
  activeFile=''; noteFullText='';
  document.body.style.overflow='';
}

function dlFile(path){ window.location.href='/file?name='+encodeURIComponent(path)+'&dl=1'; }

modal.addEventListener('click',function(e){ if(e.target===modal) closeModal(); });
document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeModal(); });

// ── Helpers ───────────────────────────────────────────────────────────────────
function thumb(name,ext,path){
  if (['jpg','jpeg','png','gif','webp','svg'].indexOf(ext)!==-1)
    return '<img src="/file?name='+encodeURIComponent(path)+'" alt="" loading="lazy">';
  return esc((ext||'?').toUpperCase().slice(0,4));
}
function thumbCls(ext){
  if (['jpg','jpeg','png','gif','webp','svg'].indexOf(ext)!==-1) return '';
  if (ext==='pdf') return 'ft-pdf';
  if (['mp4','webm','mov','m4v','ogg'].indexOf(ext)!==-1) return 'ft-vid';
  if (['mp3','wav','flac','aac','m4a','opus'].indexOf(ext)!==-1) return 'ft-aud';
  if (['zip','rar','7z','tar','gz','bz2'].indexOf(ext)!==-1) return 'ft-arc';
  return 'ft-file';
}
function fileType(ext){
  if (['jpg','jpeg','png','gif','webp','svg','bmp','tiff'].indexOf(ext)!==-1) return 'Image';
  if (['mp4','webm','mov','avi','mkv','m4v'].indexOf(ext)!==-1) return 'Video';
  if (['mp3','wav','ogg','flac','aac','m4a','opus'].indexOf(ext)!==-1) return 'Audio';
  if (ext==='pdf') return 'PDF';
  if (['doc','docx','txt','md','rtf'].indexOf(ext)!==-1) return 'Document';
  if (['xls','xlsx','csv'].indexOf(ext)!==-1) return 'Spreadsheet';
  if (['zip','rar','7z','tar','gz','bz2'].indexOf(ext)!==-1) return 'Archive';
  if (['js','ts','go','py','rs','kt','java','c','cpp','css','html','json'].indexOf(ext)!==-1) return 'Code';
  return 'File';
}
function previewKind(ext){
  if (['jpg','jpeg','png','gif','webp','svg'].indexOf(ext)!==-1) return 'image';
  if (['mp4','webm','mov','m4v'].indexOf(ext)!==-1) return 'video';
  if (['mp3','wav','ogg','flac','aac','m4a','opus'].indexOf(ext)!==-1) return 'audio';
  if (ext==='pdf') return 'pdf';
  return null;
}
function fmtSize(b){
  if (b<1024) return b+' B';
  if (b<1048576) return (b/1024).toFixed(1)+' KB';
  if (b<1073741824) return (b/1048576).toFixed(1)+' MB';
  return (b/1073741824).toFixed(2)+' GB';
}
function fmtDate(iso){
  var d=new Date(iso),now=new Date(),diff=now-d,mins=Math.floor(diff/60000);
  if (mins<1) return 'Just now';
  if (mins<60) return mins+'m ago';
  var hrs=Math.floor(mins/60);
  if (hrs<24) return hrs+'h ago';
  var days=Math.floor(hrs/24);
  if (days<7) return days+'d ago';
  return d.toLocaleDateString();
}
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Search ────────────────────────────────────────────────────────────────────
var searchInput = document.getElementById('search-input');
var searchClear = document.getElementById('search-clear');
var searchTimer = null;

searchInput.addEventListener('input', function() {
  var q = this.value.trim();
  searchClear.style.display = q ? '' : 'none';
  clearTimeout(searchTimer);
  searchTimer = setTimeout(function() {
    if (q) { loadSearch(q); } else { loadFiles(); }
  }, 300);
});

searchClear.addEventListener('click', function() {
  searchInput.value = '';
  searchClear.style.display = 'none';
  loadFiles();
});

function loadSearch(q) {
  fetch('/search?q='+encodeURIComponent(q))
    .then(function(r){return r.json();})
    .then(function(files){
      currentFiles = files || [];
      list.innerHTML = '';
      if (!currentFiles.length) {
        divT.textContent = 'No results for "'+q+'"';
        list.innerHTML = '<div class="empty-state">// nothing matched</div>';
        return;
      }
      divT.textContent = currentFiles.length+' result'+(currentFiles.length!==1?'s':'')+' for "'+q+'"';
      for (var i=0;i<currentFiles.length;i++){
        if (currentFiles[i].is_dir) list.appendChild(makeDirRow(currentFiles[i]));
        else if (currentFiles[i].is_note) list.appendChild(makeNoteRow(currentFiles[i]));
        else list.appendChild(makeFileRow(currentFiles[i]));
      }
    })
    .catch(function(){ list.innerHTML='<div class="empty-state">// search error</div>'; });
}

loadFiles();
loadDisk();
var lastFilesJSON = '';
setInterval(function(){
  if (searchInput.value.trim() || selectMode) return;
  var url = '/files' + (currentPath ? '?path=' + encodeURIComponent(currentPath) : '');
  fetch(url).then(function(r){ return r.json(); }).then(function(files){
    var json = JSON.stringify(files);
    if (json !== lastFilesJSON) {
      lastFilesJSON = json;
      currentFiles = files || [];
      renderList(currentFiles);
    }
  }).catch(function(){});
}, 5000);

</script>
</body>
</html>`))

// ─── Handlers ─────────────────────────────────────────────────────────────────

var faviconPNG []byte
var appleTouchPNG []byte

func buildIcon(sz int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	bg   := color.RGBA{17, 15, 13, 255}
	gold := color.RGBA{154, 125, 74, 255}
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			img.Set(x, y, bg)
		}
	}
	fill := func(x, y, w, h int) {
		for row := y; row < y+h; row++ {
			for col := x; col < x+w; col++ {
				if col >= 0 && col < sz && row >= 0 && row < sz {
					img.Set(col, row, gold)
				}
			}
		}
	}
	// Scale all coordinates relative to sz
	s := func(v int) int { return v * sz / 32 }
	// Stem
	fill(s(14), s(4), s(4), s(16))
	// Arrowhead tiers
	for i, a := range [][2]int{{8, 24}, {10, 22}, {12, 20}, {14, 18}} {
		fill(s(a[0]), s(20)+i*(sz/32), s(a[1]-a[0]), sz/32)
	}
	// Tray
	fill(s(5), s(27), s(22), s(2))
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func init() {
	faviconPNG   = buildIcon(32)
	appleTouchPNG = buildIcon(180)
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	fmt.Fprint(w, faviconSVG)
}

func handleFaviconPNG(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(faviconPNG)
}

func handleAppleTouchIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(appleTouchPNG)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		loginTmpl.Execute(w, map[string]bool{"Error": false})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pw := r.FormValue("password")
	if bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(pw)) != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		loginTmpl.Execute(w, map[string]bool{"Error": true})
		return
	}
	setSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !isAuthed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	uploadTmpl.Execute(w, map[string]interface{}{
		"UploadDir":    cfg.UploadDir,
		"Port":         cfg.Port,
		"SessionHours": sessionHoursLeft(r),
	})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "file too large or malformed request", http.StatusBadRequest)
		return
	}
	fhs := r.MultipartForm.File["files"]
	if len(fhs) == 0 {
		http.Error(w, "no files received", http.StatusBadRequest)
		return
	}
	for _, fh := range fhs {
		src, err := fh.Open()
		if err != nil {
			http.Error(w, "cannot open upload", http.StatusInternalServerError)
			logger.Printf("ERROR open multipart file: %v", err)
			return
		}
			uploadDir, ok := safeSubpath(cfg.UploadDir, r.URL.Query().Get("path"))
		if !ok {
			src.Close()
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			src.Close()
			http.Error(w, "cannot create directory", http.StatusInternalServerError)
			return
		}
		destName := resolveFilename(uploadDir, fh.Filename)
		destPath := filepath.Join(uploadDir, destName)
		dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			src.Close()
			http.Error(w, "cannot create file", http.StatusInternalServerError)
			logger.Printf("ERROR create %s: %v", destPath, err)
			return
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			os.Remove(destPath)
			http.Error(w, "write error", http.StatusInternalServerError)
			logger.Printf("ERROR write %s: %v", destPath, err)
			return
		}
		src.Close()
		dst.Close()
		logger.Printf("upload OK: %s", destPath)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

type fileEntry struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	Modified     time.Time `json:"modified"`
	IsNote       bool      `json:"is_note"`
	IsDir        bool      `json:"is_dir"`
	Snippet      string    `json:"snippet,omitempty"`
	MatchContent bool      `json:"match_content,omitempty"`
}


func safeSubpath(base, sub string) (string, bool) {
	if sub == "" || sub == "." {
		return base, true
	}
	clean := filepath.Clean(sub)
	full := filepath.Join(base, clean)
	cleanBase := filepath.Clean(base) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(full)+string(os.PathSeparator), cleanBase) {
		return "", false
	}
	return full, true
}

func handleFiles(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	dirPath, ok := safeSubpath(cfg.UploadDir, r.URL.Query().Get("path"))
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "cannot read directory", http.StatusInternalServerError)
		logger.Printf("ERROR ReadDir %s: %v", dirPath, err)
		return
	}
	var dirs, files []fileEntry
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, fileEntry{Name: e.Name(), Modified: fi.ModTime(), IsDir: true})
			continue
		}
		entry := fileEntry{Name: e.Name(), Size: fi.Size(), Modified: fi.ModTime()}
		if strings.HasPrefix(e.Name(), "note_") && strings.HasSuffix(e.Name(), ".txt") {
			entry.IsNote = true
			if raw, err := os.ReadFile(filepath.Join(dirPath, e.Name())); err == nil {
				s := string(raw)
				if len(s) > 160 {
					s = s[:160] + "..."
				}
				entry.Snippet = s
			}
		}
		files = append(files, entry)
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	sort.Slice(files, func(i, j int) bool { return files[i].Modified.After(files[j].Modified) })
	result := append(dirs, files...)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logger.Printf("ERROR encoding file list: %v", err)
	}
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rawName := r.URL.Query().Get("name")
	fpath, ok := safeSubpath(cfg.UploadDir, rawName)
	if !ok || rawName == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	f, err := os.Open(fpath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "stat error", http.StatusInternalServerError)
		return
	}
	name := filepath.Base(fpath)
	if r.URL.Query().Get("dl") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename=%q`, name))
	}
	http.ServeContent(w, r, name, fi.ModTime(), f)
}



// handleNote saves a text note as note_<timestamp>.txt in the upload dir.
func handleNote(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || len(strings.TrimSpace(string(body))) == 0 {
		http.Error(w, "empty note", http.StatusBadRequest)
		return
	}
	name := fmt.Sprintf("note_%d.txt", time.Now().UnixMilli())
	dest := filepath.Join(cfg.UploadDir, name)
	if err := os.WriteFile(dest, body, 0644); err != nil {
		http.Error(w, "write error", http.StatusInternalServerError)
		logger.Printf("ERROR write note %s: %v", dest, err)
		return
	}
	logger.Printf("note saved: %s", dest)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rawName := r.URL.Query().Get("name")
	fpath, ok := safeSubpath(cfg.UploadDir, rawName)
	if !ok || rawName == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := os.Remove(fpath); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "cannot delete — directory may not be empty", http.StatusBadRequest)
			logger.Printf("ERROR delete %s: %v", fpath, err)
		}
		return
	}
	logger.Printf("deleted: %s", fpath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}


func handleQR(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	host := r.Host
	if host == "" {
		host = fmt.Sprintf("localhost:%d", cfg.Port)
	}
	png, err := qrcode.Encode("http://"+host+"/", qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(png)
}

func handleDisk(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var free, total uint64
	if p, err := windows.UTF16PtrFromString(cfg.UploadDir); err == nil {
		windows.GetDiskFreeSpaceEx(p, &free, &total, nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint64{"free": free, "total": total})
}

// ─── CLI Send ─────────────────────────────────────────────────────────────────
// Invoked by the Windows "Send To" shortcut.
// Accepts one or more file paths as arguments, authenticates, and uploads.

const cliCookieName = "fd_sess"

func cliLogin() error {
	fmt.Print("FileDrop password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("cannot read password: %w", err)
	}

	formBody := "password=" + urlEncode(string(pw))
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/login", cfg.Port),
		strings.NewReader(formBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		return fmt.Errorf("wrong password")
	}

	for _, sc := range resp.Header["Set-Cookie"] {
		if strings.HasPrefix(sc, cliCookieName+"=") {
			cfg.SessionCookie = strings.SplitN(
				strings.TrimPrefix(sc, cliCookieName+"="), ";", 2)[0]
			return saveConfig()
		}
	}
	return fmt.Errorf("no session cookie in login response")
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func cliUploadOne(path string, idx, total int) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	name := filepath.Base(path)
	boundary := fmt.Sprintf("fd%d", time.Now().UnixNano())
	header := "--" + boundary + "\r\n" +
		`Content-Disposition: form-data; name="files"; filename="` + name + `"` + "\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n"
	footer := "\r\n--" + boundary + "--\r\n"

	body := io.MultiReader(
		strings.NewReader(header),
		f,
		strings.NewReader(footer),
	)

	fmt.Printf("[%d/%d] %s (%.1f MB)... ", idx, total, name, float64(fi.Size())/(1<<20))

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/upload", cfg.Port), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("Cookie", cliCookieName+"="+cfg.SessionCookie)
	req.ContentLength = int64(len(header)) + fi.Size() + int64(len(footer))

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload network error: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Println("done")
		return nil
	case http.StatusUnauthorized:
		fmt.Println("session expired, re-authenticating...")
		if err := cliLogin(); err != nil {
			return err
		}
		return cliUploadOne(path, idx, total)
	default:
		return fmt.Errorf("server returned %d for %s", resp.StatusCode, name)
	}
}

func runSend(paths []string) {
	mustLoadConfig()

	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: filedrop.exe send <file> [file ...]")
		os.Exit(1)
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(os.Stderr, "not found: %s\n", p)
			os.Exit(1)
		}
	}

	if cfg.SessionCookie == "" {
		fmt.Println("First use — enter your FileDrop password.")
		if err := cliLogin(); err != nil {
			fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
			os.Exit(1)
		}
	}

	for i, p := range paths {
		if err := cliUploadOne(p, i+1, len(paths)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("\nSent to %s\n", cfg.UploadDir)
}

// resolveFilename returns a non-conflicting filename in dir.
func resolveFilename(dir, name string) string {
	name = filepath.Base(name)
	if _, err := os.Stat(filepath.Join(dir, name)); os.IsNotExist(err) {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	return fmt.Sprintf("%s_%d%s", base, time.Now().UnixMilli(), ext)
}

// ─── Search ───────────────────────────────────────────────────────────────────

func isTextFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt", ".md", ".log", ".csv", ".json", ".xml", ".html", ".htm",
		".js", ".ts", ".go", ".py", ".rs", ".kt", ".java", ".c", ".cpp",
		".h", ".css", ".sh", ".bat", ".ps1", ".yaml", ".yml", ".toml", ".ini":
		return true
	}
	return false
}

func walkSearch(dir, base, query string, results *[]fileEntry) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	q := strings.ToLower(query)
	for _, e := range entries {
		rel := e.Name()
		if base != "" {
			rel = base + "/" + e.Name()
		}
		if e.IsDir() {
			walkSearch(filepath.Join(dir, e.Name()), rel, query, results)
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		entry := fileEntry{Name: rel, Size: fi.Size(), Modified: fi.ModTime()}
		isNote := strings.HasPrefix(e.Name(), "note_") && strings.HasSuffix(e.Name(), ".txt")
		if isNote {
			entry.IsNote = true
		}
		if strings.Contains(strings.ToLower(e.Name()), q) {
			if isNote {
				if raw, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
					s := string(raw)
					if len(s) > 160 {
						s = s[:160] + "..."
					}
					entry.Snippet = s
				}
			}
			*results = append(*results, entry)
			continue
		}
		if isTextFile(e.Name()) && fi.Size() > 0 && fi.Size() < 2<<20 {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			lower := strings.ToLower(string(raw))
			idx := strings.Index(lower, q)
			if idx >= 0 {
				entry.MatchContent = true
				start := idx - 60
				if start < 0 {
					start = 0
				}
				end := idx + len(q) + 60
				if end > len(raw) {
					end = len(raw)
				}
				entry.Snippet = "..." + string(raw[start:end]) + "..."
				*results = append(*results, entry)
			}
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		os.Remove(dst)
		return err
	}
	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		return copyFile(path, target)
	})
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cfg.ExportDir == "" {
		http.Error(w, "export directory not configured", http.StatusServiceUnavailable)
		return
	}
	rawName := r.URL.Query().Get("name")
	srcPath, ok := safeSubpath(cfg.UploadDir, rawName)
	if !ok || rawName == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := os.MkdirAll(cfg.ExportDir, 0755); err != nil {
		http.Error(w, "cannot create export dir", http.StatusInternalServerError)
		return
	}
	destName := resolveFilename(cfg.ExportDir, filepath.Base(rawName))
	destPath := filepath.Join(cfg.ExportDir, destName)
	if fi.IsDir() {
		if err := copyDir(srcPath, destPath); err != nil {
			http.Error(w, "copy error", http.StatusInternalServerError)
			logger.Printf("ERROR export dir %s → %s: %v", srcPath, destPath, err)
			return
		}
	} else {
		if err := copyFile(srcPath, destPath); err != nil {
			http.Error(w, "copy error", http.StatusInternalServerError)
			logger.Printf("ERROR export file %s → %s: %v", srcPath, destPath, err)
			return
		}
	}
	logger.Printf("export: %s → %s", srcPath, destPath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if !isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	var results []fileEntry
	walkSearch(cfg.UploadDir, "", query, &results)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Modified.After(results[j].Modified)
	})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		logger.Printf("ERROR encoding search results: %v", err)
	}
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

func buildServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/favicon.png", handleFaviconPNG)
	mux.HandleFunc("/favicon.ico", handleFaviconPNG)
	mux.HandleFunc("/apple-touch-icon.png", handleAppleTouchIcon)
	mux.HandleFunc("/apple-touch-icon-precomposed.png", handleAppleTouchIcon)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/upload", handleUpload)
	mux.HandleFunc("/files", handleFiles)
	mux.HandleFunc("/file", handleFile)
	mux.HandleFunc("/note", handleNote)
	mux.HandleFunc("/delete", handleDelete)
	mux.HandleFunc("/qr.png", handleQR)
	mux.HandleFunc("/disk", handleDisk)
	mux.HandleFunc("/search", handleSearch)
	mux.HandleFunc("/export", handleExport)
	mux.HandleFunc("/", handleIndex)
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout intentionally omitted — large uploads (up to 10GB) need unbounded transfer time.
		// ReadHeaderTimeout still guards against slowloris attacks.
		MaxHeaderBytes: 1 << 20,
	}
}

// ─── Windows Service ──────────────────────────────────────────────────────────

type fileDropSvc struct{}

func (s *fileDropSvc) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	srv := buildServer()
	go func() {
		logger.Printf("server starting on :%d, upload dir: %s", cfg.Port, cfg.UploadDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("server error: %v", err)
		}
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
loop:
	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			break loop
		case svc.Interrogate:
			status <- c.CurrentStatus
		}
	}
	status <- svc.Status{State: svc.StopPending}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown error: %v", err)
	}
	logger.Println("service stopped")
	return false, 0
}

func runAsService(exePath string) {
	logPath := filepath.Join(filepath.Dir(exePath), "filedrop.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		logger = log.New(lf, "", log.LstdFlags)
	} else {
		logger = log.Default()
	}
	mustLoadConfig()
	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		logger.Fatalf("cannot create upload dir %s: %v", cfg.UploadDir, err)
	}
	if err := svc.Run(serviceName, &fileDropSvc{}); err != nil {
		logger.Fatalf("svc.Run error: %v", err)
	}
}

func installService(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()
	existing, err := m.OpenService(serviceName)
	if err == nil {
		existing.Close()
		return fmt.Errorf("service %q already exists — run uninstall first", serviceName)
	}
	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		StartType:        mgr.StartAutomatic,
		DisplayName:      serviceDispName,
		Description:      "Local-network file drop — LAN access only",
		DelayedAutoStart: true,
	})
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	s.Close()
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q not found", serviceName)
	}
	defer s.Close()
	return s.Delete()
}

// ─── Setup ────────────────────────────────────────────────────────────────────

func runSetup() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Upload directory [%s]: ", defaultUpload)
	uploadDir, _ := reader.ReadString('\n')
	uploadDir = strings.TrimSpace(uploadDir)
	if uploadDir == "" {
		uploadDir = defaultUpload
	}
	fmt.Printf("Port [%d]: ", defaultPort)
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	port := defaultPort
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			port = p
		} else if portStr != "" {
			fmt.Fprintf(os.Stderr, "invalid port %q, using %d\n", portStr, defaultPort)
		}
	}
	fmt.Print("Set password: ")
	pw1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatalf("cannot read password: %v", err)
	}
	if len(strings.TrimSpace(string(pw1))) == 0 {
		log.Fatal("password cannot be empty")
	}
	fmt.Print("Confirm password: ")
	pw2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatalf("cannot read password: %v", err)
	}
	if string(pw1) != string(pw2) {
		log.Fatal("passwords do not match")
	}
	hash, err := bcrypt.GenerateFromPassword(pw1, 12)
	if err != nil {
		log.Fatalf("bcrypt error: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("random error: %v", err)
	}
	fmt.Print("Export folder for Google Drive / cloud sync (leave blank to skip): ")
	exportDir, _ := reader.ReadString('\n')
	exportDir = strings.TrimSpace(exportDir)

	cfg = Config{
		PasswordHash: string(hash),
		Secret:       hex.EncodeToString(secret),
		UploadDir:    uploadDir,
		Port:         port,
		ExportDir:    exportDir,
	}
	if err := saveConfig(); err != nil {
		log.Fatalf("save config: %v", err)
	}
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Fatalf("create upload dir: %v", err)
	}
	fmt.Println("\nSetup complete. Next:")
	fmt.Println("  1. Open an admin terminal in this directory")
	fmt.Println("  2. filedrop.exe install")
	fmt.Println("  3. net start filedrop")
	fmt.Printf("  4. Access from any LAN device: http://<your-local-IP>:%d\n", port)
}

func printUsage() {
	fmt.Println("FileDrop — local network file drop server")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  setup      first-time configuration (creates config.json)")
	fmt.Println("  install    register as Windows service  [run as admin]")
	fmt.Println("  uninstall  remove Windows service       [run as admin]")
	fmt.Println("  serve      run interactively for testing")
	fmt.Println("  send       upload files from the command line / Send To shortcut")
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	cfgPath = filepath.Join(filepath.Dir(exe), "config.json")
	logger = log.Default()

	if len(os.Args) < 2 {
		isService, err := svc.IsWindowsService()
		if err != nil {
			log.Fatal(err)
		}
		if isService {
			runAsService(exe)
			return
		}
		printUsage()
		return
	}

	switch os.Args[1] {
	case "setup":
		runSetup()
	case "install":
		if err := installService(exe); err != nil {
			log.Fatalf("install: %v", err)
		}
		fmt.Println("Service installed.")
		fmt.Println("Run: net start filedrop")
	case "uninstall":
		if err := uninstallService(); err != nil {
			log.Fatalf("uninstall: %v", err)
		}
		fmt.Println("Service removed.")
	case "serve":
		mustLoadConfig()
		if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
			log.Fatalf("cannot create upload dir: %v", err)
		}
		srv := buildServer()
		log.Printf("serving on http://localhost:%d — upload dir: %s", cfg.Port, cfg.UploadDir)
		log.Fatal(srv.ListenAndServe())
	case "send":
		runSend(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}
