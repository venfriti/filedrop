package main

import (
	"archive/zip"
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.org/x/term"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	serviceName       = "filedrop"
	serviceDispName   = "FileDrop LAN Server"
	cookieName        = "fd_sess"
	pubCookieName     = "fd_pub"
	sessionTTL        = 180 * 24 * time.Hour // ~6 months
	maxUploadBytes    = 10 << 30             // 10 GB
	defaultPort       = 5743
	defaultUpload     = `D:\host`
	noteInlineMax     = 4000 // note text sent with a listing, for inline editing
	maxLoginFailures  = 10
	loginLockDuration = 15 * time.Minute
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
	PasswordHash        string `json:"password_hash"`
	Secret              string `json:"secret"`
	UploadDir           string `json:"upload_dir"`
	Port                int    `json:"port"`
	ExportDir           string `json:"export_dir,omitempty"`
	SessionCookie       string `json:"session_cookie,omitempty"`
	PublicPort          int    `json:"public_port,omitempty"`
	PublicPasswordHash  string `json:"public_password_hash,omitempty"`
	PublicSecret        string `json:"public_secret,omitempty"`
	LoginDisabled       bool   `json:"login_disabled,omitempty"`
	PublicLoginDisabled bool   `json:"public_login_disabled,omitempty"`
	R2AccountID         string `json:"r2_account_id,omitempty"`
	R2AccessKey         string `json:"r2_access_key,omitempty"`
	R2SecretKey         string `json:"r2_secret_key,omitempty"`
	R2Bucket            string `json:"r2_bucket,omitempty"`
	R2PublicURL         string `json:"r2_public_url,omitempty"`
	FFmpegPath          string `json:"ffmpeg_path,omitempty"`
	FFprobePath         string `json:"ffprobe_path,omitempty"`
}

// rateEntry tracks failed login attempts per IP.
type rateEntry struct {
	failures    int
	lockedUntil time.Time
}

// throttledReader wraps an io.ReadSeeker and caps read throughput.
type throttledReader struct {
	r         io.ReadSeeker
	rate      int64 // bytes per second
	start     time.Time
	totalRead int64
}

func newThrottledReader(r io.ReadSeeker, rate int64) *throttledReader {
	return &throttledReader{
		r:         r,
		rate:      rate,
		start:     time.Now(),
		totalRead: -rate, // 1-second burst credit avoids microsleeps at startup
	}
}

func (t *throttledReader) Read(p []byte) (int, error) {
	elapsed := time.Since(t.start).Seconds()
	allowed := int64(float64(t.rate)*elapsed) - t.totalRead
	if allowed <= 0 {
		waitUntil := t.start.Add(time.Duration(float64(t.totalRead+1) / float64(t.rate) * float64(time.Second)))
		wait := time.Until(waitUntil)
		if wait > 5*time.Millisecond {
			time.Sleep(wait)
		}
		allowed = 1
	}
	if int64(len(p)) > allowed {
		p = p[:allowed]
	}
	n, err := t.r.Read(p)
	t.totalRead += int64(n)
	return n, err
}

func (t *throttledReader) Seek(offset int64, whence int) (int64, error) {
	t.start = time.Now()
	t.totalRead = 0
	return t.r.Seek(offset, whence)
}

// ─── Cloudflare R2 ────────────────────────────────────────────────────────────

func newR2Client(accountID, accessKey, secretKey string) *s3.Client {
	return s3.New(s3.Options{
		Region:       "auto",
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		BaseEndpoint: awsv2.String(fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)),
		UsePathStyle: true,
	})
}

var (
	privSrv *serverCtx
	pubSrv  *serverCtx
)

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

// ─── Server context ────────────────────────────────────────────────────────────

type serverCtx struct {
	rootDir      string
	passHash     string
	secret       []byte
	cookie       string
	port         int
	exportDir    string
	footerLabel  string
	loginLabel   string
	downloadRate int64 // bytes/sec, 0 = unlimited
	r2           *s3.Client
	r2Bucket     string
	r2PubURL     string
	// publishR2 lets the private server push a file to the public bucket. It is a
	// separate field from r2 on purpose: setting r2 would switch this server into
	// R2 mode entirely, serving the bucket instead of the local disk.
	publishR2     *s3.Client
	publishBucket string
	publishURL    string
	loginDisabled atomic.Bool
	rateMu        sync.Mutex
	rateMap       map[string]*rateEntry
}

// ─── Session Auth ─────────────────────────────────────────────────────────────

func (c *serverCtx) sessionMAC(expiry string) string {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(expiry))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *serverCtx) makeSessionValue() string {
	expiry := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	return expiry + ":" + c.sessionMAC(expiry)
}

func (c *serverCtx) validSession(value string) bool {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, mac := parts[0], parts[1]
	if !hmac.Equal([]byte(mac), []byte(c.sessionMAC(expiry))) {
		return false
	}
	ts, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < ts
}

func (c *serverCtx) isAuthed(r *http.Request) bool {
	ck, err := r.Cookie(c.cookie)
	if err != nil {
		return false
	}
	return c.validSession(ck.Value)
}

func (c *serverCtx) setSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookie,
		Value:    c.makeSessionValue(),
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// ─── File handoff tokens ──────────────────────────────────────────────────────
// An external player (VLC, opened through a vlc:// deep link) fetches the file
// itself and never carries the browser's session cookie — the cookie is
// HttpOnly + SameSite=Strict precisely so it cannot leak to another app. These
// mint a short-lived token scoped to a single file so the handoff can be
// authorised without a session.

const fileTokenTTL = 12 * time.Hour

func (c *serverCtx) fileTokenMAC(path, expiry string) string {
	h := hmac.New(sha256.New, c.secret)
	h.Write([]byte(path))
	h.Write([]byte(":"))
	h.Write([]byte(expiry))
	return hex.EncodeToString(h.Sum(nil))
}

// makeFileToken deliberately outlives the handoff itself: VLC replays this same
// URL for every byte-range request while seeking, so a short TTL would break
// seeking part-way through playback rather than at the start.
func (c *serverCtx) makeFileToken(path string) string {
	expiry := strconv.FormatInt(time.Now().Add(fileTokenTTL).Unix(), 10)
	return expiry + ":" + c.fileTokenMAC(path, expiry)
}

func (c *serverCtx) validFileToken(path, value string) bool {
	if path == "" || value == "" {
		return false
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, mac := parts[0], parts[1]
	// MAC covers the path, so a leaked token unlocks one file, not the library.
	if !hmac.Equal([]byte(mac), []byte(c.fileTokenMAC(path, expiry))) {
		return false
	}
	ts, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < ts
}

func (c *serverCtx) handleFileToken(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	if _, ok := safeSubpath(c.rootDir, name); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": c.makeFileToken(name)})
}

// Go's sniffer does not recognise Matroska's EBML signature and would serve
// octet-stream, which makes players treat the stream as an opaque download
// instead of seekable video.
var videoContentTypes = map[string]string{
	".mkv":  "video/x-matroska",
	".avi":  "video/x-msvideo",
	".wmv":  "video/x-ms-wmv",
	".flv":  "video/x-flv",
	".ts":   "video/mp2t",
	".m2ts": "video/mp2t",
	".mpg":  "video/mpeg",
	".mpeg": "video/mpeg",
}

// ─── Rate limiting ────────────────────────────────────────────────────────────

func realIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return strings.TrimSpace(cf)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isHTTPS(r *http.Request) bool {
	return r.Header.Get("X-Forwarded-Proto") == "https" ||
		strings.Contains(r.Header.Get("CF-Visitor"), `"https"`)
}

func (c *serverCtx) isRateLimited(ip string) bool {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	e, ok := c.rateMap[ip]
	if !ok {
		return false
	}
	if time.Now().After(e.lockedUntil) {
		delete(c.rateMap, ip)
		return false
	}
	return true
}

func (c *serverCtx) recordLoginFailure(ip string) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	e, ok := c.rateMap[ip]
	if !ok {
		e = &rateEntry{}
		c.rateMap[ip] = e
	}
	if time.Now().After(e.lockedUntil) {
		e.failures = 0
	}
	e.failures++
	if e.failures >= maxLoginFailures {
		e.lockedUntil = time.Now().Add(loginLockDuration)
		logger.Printf("rate limit: locked %s after %d failures", ip, e.failures)
	}
}

func (c *serverCtx) resetLoginRate(ip string) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	delete(c.rateMap, ip)
}

// ─── Login toggle ─────────────────────────────────────────────────────────────

func (c *serverCtx) handleToggleLogin(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := r.URL.Query().Get("target")
	var disabled bool
	switch target {
	case "public":
		if pubSrv == nil {
			http.Error(w, "public server not configured", http.StatusServiceUnavailable)
			return
		}
		disabled = !pubSrv.loginDisabled.Load()
		pubSrv.loginDisabled.Store(disabled)
		cfg.PublicLoginDisabled = disabled
	case "private":
		disabled = !c.loginDisabled.Load()
		c.loginDisabled.Store(disabled)
		cfg.LoginDisabled = disabled
	default:
		http.Error(w, "target must be 'public' or 'private'", http.StatusBadRequest)
		return
	}
	if err := saveConfig(); err != nil {
		logger.Printf("toggle-login save error: %v", err)
	}
	logger.Printf("login toggle: target=%s disabled=%v", target, disabled)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"target": target, "disabled": disabled})
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
  <p class="label">{{.Label}}</p>
  <h1>File<span>Drop</span></h1>
  <div class="card">
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="password" autofocus autocomplete="current-password">
      <button type="submit">Unlock</button>
      {{if .Error}}{{if .Locked}}<p class="err">// too many attempts — try again later</p>{{else}}<p class="err">// incorrect password</p>{{end}}{{end}}
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
<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js"></script>
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


/* ── Scrollbars ──────────────────────────────────────────────────────────────
   Defined on html, not body: the viewport scrollbar resolves its colours
   against the root element, which cannot see the theme variables body.light
   sets on body — hence the :has() override rather than var(--rule). */
html{--sb-thumb:#3a3428;--sb-thumb-hover:#5a554e;scrollbar-width:thin;scrollbar-color:var(--sb-thumb) transparent}
html:has(body.light){--sb-thumb:#d8cfc2;--sb-thumb-hover:#8a7d6e}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
/* transparent border + padding-box clip insets the thumb without painting a
   colour, so it sits correctly on the page, menus and the modal alike */
::-webkit-scrollbar-thumb{background:var(--sb-thumb);border:2px solid transparent;background-clip:padding-box;border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:var(--sb-thumb-hover)}
::-webkit-scrollbar-corner{background:transparent}
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
.hdr-icons{display:flex;align-items:center;gap:.05rem}
.hdr-icon-btn{background:none;border:none;color:var(--muted);font-size:1.6rem;cursor:pointer;padding:.1rem .3rem;line-height:1;display:flex;align-items:center;transition:color .15s;font-family:system-ui,-apple-system,sans-serif}
.hdr-icon-btn:hover{color:var(--text)}

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
.divider-text{font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;letter-spacing:.1em;color:var(--muted);white-space:nowrap}
.breadcrumb{display:none;align-items:center;gap:.3rem;margin-bottom:.75rem;flex-wrap:wrap}
.bc-item{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;color:var(--muted);cursor:pointer;transition:color .15s}
.bc-item:hover{color:var(--text)}
.bc-root{color:var(--muted)}
.bc-current{color:var(--text);cursor:default}
.bc-sep{font-family:'IBM Plex Mono',monospace;font-size:.72rem;color:var(--faint)}
.ft-dir{background:var(--card);font-family:'IBM Plex Mono',monospace;font-size:.65rem;font-weight:500;letter-spacing:.06em;color:var(--gold);border-color:var(--gold-dim)}
.dir-item:hover .dir-name{opacity:.8}

/* file/note list */
.file-list{display:flex;flex-direction:column}

.file-item:hover{background:var(--surface)}
.file-item+.file-item{border-top:1px solid var(--faint)}

/* note item overrides — no thumb column, spans full row */
.note-item{display:grid;grid-template-columns:1fr auto auto;align-items:center;gap:1.25rem;padding:1rem 1.25rem;border-radius:5px;background:var(--note-bg);border:1px solid var(--note-border);margin:.25rem 0;transition:background .15s;position:relative}
.note-item:hover{background:var(--card)}
.note-snippet{font-family:'Libre Baskerville',Georgia,serif;font-size:.95rem;color:var(--text);line-height:1.5;word-break:break-word}
/* Collapsed to a few lines so a long note does not stretch the row. The full
   text is still in the DOM — it has to be, or editing and saving would write
   back a truncated file — this only limits how much is shown. */
.note-snippet{cursor:text;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
/* editing expands it, scrolling past a sensible height rather than growing forever */
.note-snippet.editing{display:block;-webkit-line-clamp:none;white-space:pre-wrap;min-height:1.4em;max-height:16rem;overflow:auto}
.note-item .save-btn{color:var(--gold)}
.note-item .cancel-btn{color:var(--muted)}
.note-meta{font-family:'IBM Plex Mono',monospace;font-size:.68rem;font-weight:500;color:var(--muted);margin-top:.2rem;letter-spacing:.04em}
.note-actions{display:flex;align-items:center;gap:.5rem;flex-shrink:0}

.file-thumb{width:50px;height:50px;border-radius:5px;border:1px solid var(--faint);flex-shrink:0;display:flex;align-items:center;justify-content:center;overflow:hidden}
.file-thumb img{width:100%;height:100%;object-fit:cover;display:block}
.vid-thumb{width:100%;height:100%;object-fit:cover;display:block}
/* "preparing for playback" state while ffmpeg repackages the container */
.prep{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.8rem;padding:2.5rem 1.5rem;min-width:260px}
.prep-spin{width:26px;height:26px;border:2px solid var(--faint);border-top-color:var(--gold);border-radius:50%;animation:prep-rot .8s linear infinite}
@keyframes prep-rot{to{transform:rotate(360deg)}}
.prep-msg{font-family:'IBM Plex Mono',monospace;font-size:.8rem;font-weight:500;color:var(--text);text-align:center}
.prep-sub{font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:var(--muted);text-align:center}
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
.view-btn,.dl-btn,.copy-btn,.menu-btn{background:none;border:none;padding:.25rem .15rem;cursor:pointer;font-family:'IBM Plex Mono',monospace;font-size:1.05rem;font-weight:500;letter-spacing:.05em;white-space:nowrap;transition:color .15s}
.view-btn{color:var(--muted);font-size:.82rem}.view-btn:hover{color:var(--text)}
.dl-btn{color:var(--muted)}.dl-btn:hover{color:var(--gold)}
.copy-btn{color:var(--muted)}.copy-btn:hover{color:var(--text)}
.copy-btn.copied{color:var(--copy-ok)}
.menu-btn{display:none;color:var(--muted);font-size:1.1rem;padding:.2rem .5rem;letter-spacing:0;line-height:1}
.menu-btn:hover{color:var(--text)}

.folder-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem;justify-content:flex-start}
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
/* right-click menu: same card as .row-menu, but pinned to the pointer */
.ctx-menu{position:fixed;right:auto;top:auto;z-index:120;min-width:170px}
.row-menu-item:disabled{opacity:.35;cursor:default}
.row-menu-item.danger{color:#9a5a4a}
.row-menu-item.danger:hover{background:rgba(154,90,74,.12);color:#c06050}
.ctx-sep{height:1px;background:var(--rule);margin:.25rem 0}

/* bulk delete */
.row-check{display:flex;align-items:center;justify-content:center}
.row-check input[type=checkbox]{width:15px;height:15px;accent-color:var(--gold);cursor:pointer;flex-shrink:0}
#select-trigger{display:none;color:#9a5a4a;background:none;border:none;cursor:pointer;padding:.1rem .15rem;line-height:1;margin-left:auto;transition:color .15s}
#select-trigger:hover{color:#c06050}

/* extension filter */
.ext-filter{position:relative;flex-shrink:0}
#ext-btn{display:flex;align-items:center;gap:.45rem;background:none;border:1px solid var(--faint);border-radius:4px;color:var(--muted);cursor:pointer;font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;letter-spacing:.08em;padding:.35rem .6rem;line-height:1;transition:color .15s,border-color .15s}
#ext-btn:hover{color:var(--text);border-color:#3a3530}
#ext-btn.active{color:var(--gold);border-color:var(--gold-dim)}
#ext-btn:disabled{opacity:.45;cursor:default}
#ext-btn:disabled:hover{color:var(--muted);border-color:var(--faint)}
.ext-caret{font-size:.55rem;line-height:1;opacity:.8}
.ext-menu{display:none;position:absolute;left:0;top:calc(100% + 4px);z-index:50;background:var(--card);border:1px solid var(--faint);border-radius:6px;min-width:150px;max-height:15rem;overflow-y:auto;box-shadow:0 4px 16px rgba(0,0,0,.35)}
.ext-menu.open{display:block}
.ext-item{display:flex;align-items:center;justify-content:space-between;gap:1.25rem;padding:.55rem .9rem;font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;color:var(--muted);cursor:pointer;white-space:nowrap;background:none;border:none;width:100%;text-align:left;transition:background .1s,color .1s}
.ext-item:hover{background:var(--faint);color:var(--text)}
.ext-item.sel{color:var(--gold)}
.ext-count{font-size:.68rem;opacity:.65}
/* selection toolbar: sits directly above the list rather than pinned to the
   bottom, so the actions are next to what they act on */
/* shared-folder banner: QR first, then the link to copy */
#share-banner{display:none;flex-direction:column;align-items:center;gap:.5rem;padding:1.1rem;margin-bottom:.9rem;background:var(--surface);border:1px solid var(--rule);border-radius:6px}
.share-qr{width:150px;height:150px;image-rendering:pixelated;background:#fff;padding:6px;border-radius:4px}
.share-copy{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;color:var(--gold);text-decoration:underline;cursor:pointer}
.share-copy:hover{opacity:.8}
.share-url{font-family:'IBM Plex Mono',monospace;font-size:.68rem;color:var(--muted);word-break:break-all;text-align:center}
#select-bar{display:none;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;background:var(--surface);border:1px solid var(--rule);border-radius:6px;padding:.65rem .8rem;margin-bottom:.75rem}
#select-bar.open{display:flex}
#select-bar-count{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;color:var(--gold);letter-spacing:.04em;white-space:nowrap}
#select-bar-actions{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
#select-bar-actions .folder-btn{padding:.35rem .75rem;font-size:.72rem}
.sb-div{width:1px;height:1.1rem;background:var(--rule)}
/* everything except the list and its toolbar recedes while selecting */
body.selecting header,
body.selecting .upload-section,
body.selecting .search-wrap,
body.selecting .divider,
body.selecting .breadcrumb,
body.selecting .folder-row,
body.selecting footer{opacity:.22;pointer-events:none;transition:opacity .18s}
body.selecting .file-list,body.selecting #select-bar{opacity:1}
#select-bar-count{font-family:'IBM Plex Mono',monospace;font-size:.78rem;font-weight:500;color:var(--muted);letter-spacing:.04em}
#select-bar-actions{display:flex;gap:.75rem}
/* .folder-btn had no rule at all — these buttons were falling through to the
   browser's default grey chrome, which is why they looked undesigned. */
.folder-btn{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;letter-spacing:.06em;color:var(--muted);background:none;border:1px solid var(--faint);padding:.45rem 1rem;border-radius:4px;cursor:pointer;white-space:nowrap;transition:color .15s,border-color .15s,background .15s}
.folder-btn:hover:not(:disabled){color:var(--text);border-color:var(--rule)}
.folder-btn:disabled{opacity:.4;cursor:default}
.folder-btn.danger{color:#9a5a4a;border-color:#3a2622}
.folder-btn.danger:hover:not(:disabled){color:#c06050;border-color:#9a5a4a;background:rgba(154,90,74,.08)}
.folder-btn.primary{color:var(--gold);border-color:var(--gold-dim)}
.folder-btn.primary:hover:not(:disabled){color:var(--gold);border-color:var(--gold);background:rgba(154,125,74,.1)}

/* new folder */
#newfolder-btn,#share-btn{display:flex;align-items:center;gap:.4rem;flex-shrink:0;background:none;border:1px solid var(--faint);border-radius:4px;color:var(--muted);cursor:pointer;font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;letter-spacing:.08em;padding:.35rem .6rem;line-height:1;transition:color .15s,border-color .15s}
#newfolder-btn:hover,#share-btn:hover{color:var(--gold);border-color:var(--gold-dim)}
.nf-plus{font-size:.9rem;line-height:1}

/* name prompt */

/* drag to move */
.file-item.dragging,.note-item.dragging{opacity:.4}
.file-item.drop-target,.note-item.drop-target{outline:1px dashed var(--gold);outline-offset:-2px;background:rgba(154,125,74,.08)}
.bc-item.drop-target{outline:1px dashed var(--gold);border-radius:3px;color:var(--gold)}

/* confirm dialog — above every other layer, since it gates a destructive action */
#confirm-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.78);z-index:130;align-items:center;justify-content:center;padding:1.5rem}
#confirm-modal.open{display:flex}
#confirm-box{background:var(--card);border:1px solid var(--faint);border-radius:8px;padding:1.5rem;width:100%;max-width:360px}
#confirm-title{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.12em;color:var(--muted);margin-bottom:.9rem}
#confirm-text{font-family:'Libre Baskerville',Georgia,serif;font-size:.9rem;color:var(--text);line-height:1.55;word-break:break-word}
#confirm-text b{font-family:'IBM Plex Mono',monospace;font-size:.82rem;font-weight:500;color:var(--gold)}
.confirm-name{font-family:'IBM Plex Mono',monospace;font-size:.82rem;font-weight:500;color:var(--gold);background:var(--bg);border:1px solid var(--faint);border-radius:4px;padding:.5rem .7rem;margin-top:.7rem;word-break:break-all}
#confirm-note{font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:var(--muted);margin-top:.6rem}
#confirm-actions{display:flex;justify-content:flex-end;gap:.75rem;margin-top:1.4rem}
/* move picker */
#move-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:110;align-items:center;justify-content:center;padding:1.5rem}
#move-modal.open{display:flex}
#move-box{background:var(--card);border:1px solid var(--faint);border-radius:8px;padding:1.5rem;width:100%;max-width:400px;display:flex;flex-direction:column}
#move-title{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.12em;color:var(--muted);margin-bottom:.9rem}
#move-title span{color:var(--text)}
#move-crumb{display:flex;align-items:center;flex-wrap:wrap;gap:.3rem;font-family:'IBM Plex Mono',monospace;font-size:.75rem;color:var(--muted);margin-bottom:.6rem}
.mc-item{cursor:pointer;transition:color .15s}
.mc-item:hover{color:var(--gold)}
.mc-sep{opacity:.4}
#move-list{border:1px solid var(--faint);border-radius:4px;min-height:8rem;max-height:14rem;overflow-y:auto;background:var(--bg)}
.move-row{display:block;width:100%;text-align:left;background:none;border:none;border-bottom:1px solid var(--rule);color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:.78rem;padding:.6rem .85rem;cursor:pointer;transition:background .1s,color .1s}
.move-row:last-child{border-bottom:none}
.move-row:hover:not(.disabled){background:var(--faint);color:var(--gold)}
.move-row::before{content:'\002B22';margin-right:.5rem;opacity:.5}
.move-row.disabled{opacity:.35;cursor:default}
.move-empty{font-family:'IBM Plex Mono',monospace;font-size:.75rem;color:var(--muted);padding:.9rem}
#move-actions{display:flex;justify-content:flex-end;gap:.75rem;margin-top:1.25rem}
/* locked rows: visibly inert until unlocked */
.locked-row{opacity:.42;cursor:pointer;transition:opacity .15s}
.locked-row:hover{opacity:.62}
.file-item.is-locked{opacity:.72}
.ft-lock{background:var(--card);font-size:1.1rem}
/* password dialog */
#pw-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.78);z-index:135;align-items:center;justify-content:center;padding:1.5rem}
#pw-modal.open{display:flex}
#pw-box{background:var(--card);border:1px solid var(--faint);border-radius:8px;padding:1.5rem;width:100%;max-width:340px}
#pw-title{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:.5rem}
#pw-sub{font-family:'IBM Plex Mono',monospace;font-size:.8rem;color:var(--gold);margin-bottom:1rem;word-break:break-all}
#pw-input{width:100%;padding:.7rem .9rem;background:var(--bg);border:1px solid var(--faint);border-radius:4px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:.85rem;outline:none;transition:border-color .15s}
#pw-input:focus{border-color:var(--gold-dim)}
#pw-err{font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;color:#9a5a4a;margin-top:.6rem;display:none}
#pw-actions{display:flex;justify-content:flex-end;gap:.75rem;margin-top:1.25rem}
#prompt-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:110;align-items:center;justify-content:center;padding:1.5rem}
#prompt-modal.open{display:flex}
#prompt-box{background:var(--card);border:1px solid var(--faint);border-radius:8px;padding:1.5rem;width:100%;max-width:340px}
#prompt-title{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:500;letter-spacing:.12em;color:var(--muted);margin-bottom:1rem}
#prompt-input{width:100%;padding:.7rem .9rem;background:var(--bg);border:1px solid var(--faint);border-radius:4px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:.85rem;outline:none;transition:border-color .15s}
#prompt-input:focus{border-color:var(--gold-dim)}
#prompt-input::placeholder{color:var(--muted)}
#prompt-err{font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;color:#9a5a4a;letter-spacing:.04em;margin-top:.6rem;display:none}
#prompt-actions{display:flex;justify-content:flex-end;gap:.75rem;margin-top:1.25rem}

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
  .view-btn,.dl-btn,.note-actions,.action-sep{display:none!important}
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
#modal-content pre{cursor:text}
#note-edit{width:min(70vw,640px);max-width:100%;height:min(60vh,420px);background:var(--bg);border:1px solid var(--faint);border-radius:4px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:.85rem;line-height:1.7;padding:.9rem 1rem;outline:none;resize:vertical}
#note-edit:focus{border-color:var(--gold-dim)}
#modal-save{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;letter-spacing:.06em;color:var(--gold);background:none;border:1px solid var(--gold-dim);padding:.45rem 1rem;border-radius:4px;cursor:pointer;transition:color .15s,border-color .15s}
#modal-save:hover:not(:disabled){border-color:var(--gold)}
#modal-save:disabled{opacity:.5;cursor:default}
#modal-cancel{font-family:'IBM Plex Mono',monospace;font-size:.75rem;font-weight:500;letter-spacing:.06em;color:var(--muted);background:none;border:1px solid var(--faint);padding:.45rem 1rem;border-radius:4px;cursor:pointer;transition:color .15s,border-color .15s}
#modal-cancel:hover{color:var(--text);border-color:var(--rule)}
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
      <span class="pill active">:{{.Port}}</span>
      <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">&#9728; Light</button>
    </div>
    <div class="hdr-mobile-meta" id="hdr-mobile">
      <div class="hdr-icons">
        <button class="hdr-icon-btn" id="theme-btn-m" onclick="toggleTheme()">&#9728;&#xFE0E;</button>
      </div>
    </div>
  </header>

  <div class="upload-section">
    <div class="drop-card" id="drop">
      <div class="drop-icon">&#x2193;</div>
      <p class="drop-label">Drop files or folders to upload</p>
      <p class="drop-sub">any format &nbsp;&#xB7;&nbsp; up to 10 GB &nbsp;&#xB7;&nbsp; click to browse &nbsp;&#xB7;&nbsp; <span id="folder-pick-link" style="text-decoration:underline;cursor:pointer">upload a folder</span></p>
      <input type="file" id="file-input" multiple>
      <input type="file" id="folder-input" webkitdirectory directory multiple style="display:none">
    </div>
    <div class="upload-compact" onclick="document.getElementById('file-input').click()">
      <div class="uc-icon">&#x2191;</div>
      <div class="uc-text">
        <div class="uc-title">Upload files</div>
        <div class="uc-sub">any format · up to 10 GB</div>
      </div>
      <span class="uc-chevron">&#x203A;</span>
    </div>
    <div class="upload-compact" id="folder-upload-compact" style="margin-top:.6rem" onclick="document.getElementById('folder-input').click()">
      <div class="uc-icon">&#x1F4C1;</div>
      <div class="uc-text">
        <div class="uc-title">Upload folder</div>
        <div class="uc-sub">preserves subfolder structure</div>
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

  <div class="breadcrumb" id="breadcrumb"></div>
  <div class="folder-row">
    <div class="ext-filter">
      <button id="ext-btn" onclick="toggleExtMenu(event)" title="Filter by file type" disabled><span id="ext-btn-label">All</span><span class="ext-caret">&#x25BC;</span></button>
      <div class="ext-menu" id="ext-menu"></div>
    </div>
    <button id="newfolder-btn" onclick="openNewFolder()" title="Create a folder"><span class="nf-plus">+</span>New</button>
    <button id="share-btn" onclick="startShare()" title="Create a shared folder"><span class="nf-plus">&#x21AA;</span>Share</button>
    <button id="select-trigger" onclick="enterSelectMode()" title="Select to delete"><svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="2,4 14,4"/><path d="M5 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1"/><path d="M13 4l-.8 10H3.8L3 4"/><line x1="6.5" y1="7" x2="6.5" y2="11"/><line x1="9.5" y1="7" x2="9.5" y2="11"/></svg></button>
  </div>
  <div id="share-banner" style="display:none"></div>
  <div id="select-bar">
    <span id="select-bar-count">0 selected</span>
    <div id="select-bar-actions">
      <button class="folder-btn" id="sb-copy" onclick="bulkCopy()">Copy</button>
      <button class="folder-btn" id="sb-cut" onclick="bulkCut()">Cut</button>
      <button class="folder-btn" id="sb-download" onclick="bulkDownload()">Download</button>
      {{if .CanPublish}}<button class="folder-btn" id="sb-upload" onclick="bulkUpload()">Upload</button>{{end}}
      <button class="folder-btn primary" id="sb-add" style="display:none" onclick="finishShare()">Add to shared folder</button>
      <button class="folder-btn danger" id="select-bar-delete" onclick="confirmBulkDelete()">Delete</button>
      <span class="sb-div"></span>
      <button class="folder-btn" id="sb-cancel" onclick="exitSelectMode()">Done</button>
    </div>
  </div>
  <div class="file-list" id="file-list"></div>

  <footer>
    <span class="ft-l">FileDrop &nbsp;&#xB7;&nbsp; {{.FooterLabel}}</span>
    <div id="disk-bar-wrap" style="display:none">
      <div id="disk-bar-track"><div id="disk-bar-fill" style="width:0%"></div></div>
      <span id="disk-label"></span>
    </div>
    <span class="ft-r">{{.UploadDir}}</span>
  </footer>
</div>




<div id="confirm-modal">
  <div id="confirm-box">
    <div id="confirm-title">Confirm</div>
    <div id="confirm-text"></div>
    <div id="confirm-actions">
      <button class="folder-btn" id="confirm-cancel" onclick="closeConfirm()">Cancel</button>
      <button class="folder-btn danger" id="confirm-ok">Delete</button>
    </div>
  </div>
</div>
<div id="move-modal">
  <div id="move-box">
    <div id="move-title">Move <span id="move-subject"></span> to</div>
    <div id="move-crumb"></div>
    <div id="move-list"></div>
    <div id="move-actions">
      <button class="folder-btn" onclick="closeMove()">Cancel</button>
      <button class="folder-btn primary" id="move-ok" onclick="confirmMove()">Move here</button>
    </div>
  </div>
</div>

<div id="pw-modal">
  <div id="pw-box">
    <div id="pw-title">Unlock</div>
    <div id="pw-sub"></div>
    <input id="pw-input" type="password" placeholder="password" autocomplete="off">
    <div id="pw-err"></div>
    <div id="pw-actions">
      <button class="folder-btn" onclick="closePw()">Cancel</button>
      <button class="folder-btn primary" id="pw-ok">Unlock</button>
    </div>
  </div>
</div>
<div id="prompt-modal">
  <div id="prompt-box">
    <div id="prompt-title">New folder</div>
    <input id="prompt-input" type="text" placeholder="folder name" autocomplete="off" spellcheck="false">
    <div id="prompt-err"></div>
    <div id="prompt-actions">
      <button class="folder-btn" onclick="closePrompt()">Cancel</button>
      <button class="folder-btn primary" id="prompt-ok" onclick="submitNewFolder()">Create</button>
    </div>
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
      <button id="modal-cancel" style="display:none">Cancel</button>
      <button id="modal-save" style="display:none">&#x2713; Save</button>
    </div>
  </div>
</div>

<script>
var R2_MODE = {{if .R2Mode}}true{{else}}false{{end}};
var CAN_PUBLISH = {{if .CanPublish}}true{{else}}false{{end}};
var SHARE_MODE = {{if .ShareMode}}true{{else}}false{{end}};
var SHARE_NAME = "{{.ShareName}}";
var VIDEO_TOOLS = {{if .VideoTools}}true{{else}}false{{end}};

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
var mSave    = document.getElementById('modal-save');
var mCancel  = document.getElementById('modal-cancel');
if (mSave) mSave.addEventListener("click", function(){ saveNoteEdit(); });
if (mCancel) mCancel.addEventListener("click", function(){ cancelNoteEdit(); });
var mCopy    = document.getElementById('modal-copy');
var activeFile = '';
var noteFullText = '';
var currentPath = '';
var currentFiles = [];
var selectMode = false;
var selectedPaths = new Set();
var activeMenu = null;

// ── ⋮ menu ────────────────────────────────────────────────────────────────────
// buildMenuEl is shared by the ⋮ button and the right-click menu so the two can
// never drift apart.
function buildMenuEl(actions) {
  var menu = document.createElement('div');
  menu.className = 'row-menu';
  actions.forEach(function(a) {
    if (a.sep) { menu.appendChild(document.createElement('div')).className = 'ctx-sep'; return; }
    var item = document.createElement('button');
    item.className = 'row-menu-item' + (a.danger ? ' danger' : '');
    item.textContent = a.label;
    if (a.disabled) item.disabled = true;
    else item.addEventListener('click', function(e){ e.stopPropagation(); closeMenu(); a.fn(); });
    menu.appendChild(item);
  });
  return menu;
}

function openMenu(btn, actions) {
  closeMenu();
  var menu = buildMenuEl(actions);
  btn.parentElement.appendChild(menu);
  activeMenu = menu;
}
function closeMenu() {
  if (activeMenu) { activeMenu.remove(); activeMenu = null; }
}

// Right-click anywhere that is not a row, a form field or a dialog acts on the
// folder currently being viewed. Bound to the document rather than the list so
// the shell's side padding and the space below a short list work too — that is
// what makes it possible to cut inside a subfolder, navigate up, and paste.
document.addEventListener('contextmenu', function(e){
  if (selectMode) { closeMenu(); return; }
  if (e.target.closest('.file-item,.note-item')) return;    // rows handle their own
  // leave the browser's own menu alone where it is genuinely useful; dismiss
  // ours first so the two menus never overlap
  if (e.target.closest('input,textarea,select,a,.row-menu,#modal,#prompt-modal,#confirm-modal')) { closeMenu(); return; }
  e.preventDefault();
  var acts = [
    {label:'New folder', fn:function(){ openNewFolder(); }},
    {label:'Select', fn:function(){ if (!selectMode) enterSelectMode(); }}
  ];
  if (clipPaths.length) {
    acts.push({sep:true});
    acts.push({label:clipboardLabel(), fn:function(){ pasteInto(currentPath); }});
    acts.push({label:'Clear clipboard', fn:function(){ clipClear(); msg.textContent=''; }});
  }
  openContextMenu(e.clientX, e.clientY, acts);
});
document.addEventListener('click', function(e) {
  if (activeMenu && !activeMenu.contains(e.target)) closeMenu();
  if (extMenu && extMenu.classList.contains('open') &&
      !extMenu.contains(e.target) && extBtn && !extBtn.contains(e.target)) closeExtMenu();
});
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeMenu();
});
window.addEventListener('scroll', function() { if (activeMenu) closeMenu(); }, true);

// ── Bulk delete ───────────────────────────────────────────────────────────────
function enterSelectMode() {
  selectMode = true;
  list.classList.add('selecting');
  document.body.classList.add('selecting');          // dims everything but the list
  document.getElementById('select-bar').classList.add('open');
  document.getElementById('select-trigger').style.display = 'none';
  closeMenu();
  updateSelectBar();
  renderList(currentFiles);
}

function exitSelectMode() {
  selectMode = false;
  shareStage = null;
  var ab = document.getElementById("sb-add"); if (ab) ab.style.display = "none";
  selectedPaths.clear();
  list.classList.remove('selecting');
  document.body.classList.remove('selecting');
  document.getElementById('select-bar').classList.remove('open');
  document.getElementById('select-trigger').style.display = '';
  renderList(currentFiles);
}

function toggleSelect(path, checked) {
  if (checked) { selectedPaths.add(path); } else { selectedPaths.delete(path); }
  updateSelectBar();
}

function updateSelectBar() {
  var n = selectedPaths.size;
  var sharing = shareStage === 'picking';
  var addBtn = document.getElementById('sb-add');
  if (addBtn) { addBtn.style.display = sharing ? '' : 'none'; addBtn.disabled = n === 0; }
  ['sb-copy','sb-cut','sb-download','sb-upload','select-bar-delete'].forEach(function(id){
    var b = document.getElementById(id); if (b) b.style.display = sharing ? 'none' : '';
  });
  document.getElementById('select-bar-count').textContent =
    n + ' selected';
  // every action needs at least one row ticked
  ['select-bar-delete','sb-copy','sb-cut','sb-download','sb-upload'].forEach(function(id){
    var b = document.getElementById(id);
    if (b) b.disabled = n === 0;
  });
}

// ── Bulk actions ──────────────────────────────────────────────────────────────
function selectedList() { return Array.from(selectedPaths); }

// Folders are excluded where an action cannot apply to them, and the caller is
// told rather than left wondering why nothing happened.
function selectedFilesOnly(actionName) {
  var all = selectedList(), files = [];
  for (var i = 0; i < all.length; i++) {
    var isDir = false;
    for (var j = 0; j < currentFiles.length; j++) {
      var full = currentPath ? currentPath + '/' + currentFiles[j].name : currentFiles[j].name;
      if (full === all[i]) { isDir = currentFiles[j].is_dir; break; }
    }
    if (!isDir) files.push(all[i]);
  }
  if (files.length < all.length) {
    msg.className = '';
    msg.textContent = '// ' + actionName + ': skipping ' + (all.length - files.length) + ' folder(s)';
  }
  return files;
}

function bulkCopy() {
  if (!selectedPaths.size) return;
  clipCopy(selectedList());
  exitSelectMode();
}

function bulkCut() {
  if (!selectedPaths.size) return;
  clipCut(selectedList());
  exitSelectMode();
}

// Browsers throttle rapid successive downloads, so these are spaced out.
function bulkDownload() {
  var files = selectedFilesOnly('download');
  if (!files.length) return;
  files.forEach(function(p, i){ setTimeout(function(){ dlFile(p); }, i * 600); });
  exitSelectMode();
}

function bulkUpload() {
  var files = selectedFilesOnly('upload');
  if (!files.length) return;
  var done = 0, failed = 0;
  function next(i) {
    if (i >= files.length) {
      msg.className = failed ? 'err' : 'ok';
      msg.textContent = '// uploaded ' + done + ' to the public site' + (failed ? ', ' + failed + ' failed' : '');
      return;
    }
    msg.className = '';
    msg.textContent = '// uploading ' + (i + 1) + '/' + files.length + '...';
    fetch('/publish?name=' + encodeURIComponent(files[i]), {method:'POST'})
      .then(function(r){ if (r.ok) done++; else failed++; next(i + 1); })
      .catch(function(){ failed++; next(i + 1); });
  }
  exitSelectMode();
  next(0);
}
// ── Confirm dialog ────────────────────────────────────────────────────────────
// Gates destructive actions. Cancel takes focus, not Delete, so a stray Enter
// dismisses rather than deletes.
var confirmModal  = document.getElementById('confirm-modal');
var confirmTitle  = document.getElementById('confirm-title');
var confirmText   = document.getElementById('confirm-text');
var confirmOk     = document.getElementById('confirm-ok');
var confirmCancel = document.getElementById('confirm-cancel');
var confirmFn     = null;

function showConfirm(title, html, okLabel, fn) {
  closeMenu();
  confirmTitle.textContent = title;
  confirmText.innerHTML = html;
  confirmOk.textContent = okLabel;
  confirmFn = fn;
  confirmModal.classList.add('open');
  confirmCancel.focus();
}

function closeConfirm() {
  confirmModal.classList.remove('open');
  confirmFn = null;
}

confirmOk.addEventListener('click', function(){
  var fn = confirmFn;
  closeConfirm();
  if (fn) fn();
});
confirmModal.addEventListener('click', function(e){ if (e.target === confirmModal) closeConfirm(); });
document.addEventListener('keydown', function(e){
  if (e.key === 'Escape' && confirmModal.classList.contains('open')) { e.stopPropagation(); closeConfirm(); }
});

function confirmBulkDelete() {
  if (!selectedPaths.size) return;
  var n = selectedPaths.size;
  showConfirm('Delete ' + n + ' item' + (n !== 1 ? 's' : ''),
    'Are you sure you want to delete ' + (n === 1 ? 'this item' : 'these <b>' + n + '</b> items') + '?' +
    '<div id="confirm-note">// this cannot be undone</div>',
    'OK', bulkDeleteNow);
}

function bulkDeleteNow() {
  var paths = Array.from(selectedPaths);
  var n = paths.length;
  var done = 0, failed = 0, lastStatus = 0, lastText = '';
  var snapshot = currentFiles.slice();
  removeFromListing(paths);          // vanish immediately
  exitSelectMode();
  pendingOps++;
  function next(i) {
    if (i >= paths.length) {
      pendingOps--;
      if (failed) {
        if (done === 0) currentFiles = snapshot;   // nothing went, put it all back
        rerender();
        msg.className = 'err';
        msg.textContent = '// ' + describeFailure('delete ' + failed + ' of ' + n, lastStatus, lastText);
      } else {
        msg.className = 'ok';
        msg.textContent = '// deleted ' + done;
      }
      loadFiles();
      return;
    }
    fetch('/delete?name='+encodeURIComponent(paths[i]), {method:'POST'})
      .then(function(r){
        if (r.ok) { done++; next(i+1); return; }
        failed++; lastStatus = r.status;
        return r.text().then(function(t){ lastText = t; next(i+1); });
      })
      .catch(function(){ failed++; lastStatus = 0; next(i+1); });
  }
  next(0);
}

// Every delete entry point goes through here, so the confirm cannot be bypassed.
function deleteItem(path) {
  var isDir = false;
  for (var i = 0; i < currentFiles.length; i++) {
    var full = currentPath ? currentPath + '/' + currentFiles[i].name : currentFiles[i].name;
    if (full === path) { isDir = currentFiles[i].is_dir; break; }
  }
  var what = isDir ? 'folder' : 'file';
  showConfirm(isDir ? 'Delete folder' : 'Delete file',
    'Are you sure you want to delete this ' + what + '?' +
    '<div class="confirm-name">' + esc(path.split('/').pop()) + '</div>' +
    '<div id="confirm-note">// this cannot be undone' +
    (isDir ? ' — everything inside it goes too' : '') + '</div>',
    'OK', function(){ deleteItemNow(path); });
}
function deleteItemNow(path) {
  var name = path.split('/').pop();
  optimistic('delete ' + name,
    function(){ removeFromListing([path]); },
    function(){ return fetch('/delete?name='+encodeURIComponent(path), {method:'POST'}); },
    'deleted ' + name);
}

function moveItem(src, destFolder) {
  if (insideSelf(src, destFolder) || parentOf(src) === destFolder) return;
  optimistic('move ' + src.split('/').pop(),
    function(){ removeFromListing([src]); },   // it leaves this folder
    function(){ return fetch('/move?name=' + encodeURIComponent(src) +
                             '&to=' + encodeURIComponent(destFolder), {method:'POST'}); },
    'moved to ' + (destFolder || 'root'));
}


// ── QR code ───────────────────────────────────────────────────────────────────

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
var folderInput = document.getElementById('folder-input');
var folderPickLink = document.getElementById('folder-pick-link');
// A programmatic folderInput.click() dispatches a click that bubbles up to this
// card. Without excluding the inputs themselves, that synthetic event re-opened
// the plain file picker on top of the folder picker — which is why "upload a
// folder" only ever offered files.
drop.addEventListener('click', function(e){
  if (e.target === fi || e.target === folderInput || e.target === folderPickLink) return;
  fi.click();
});
drop.addEventListener('dragover', function(e){ e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', function(e){ if(!drop.contains(e.relatedTarget)) drop.classList.remove('over'); });
drop.addEventListener('drop', function(e){
  e.preventDefault(); drop.classList.remove('over');
  var items = e.dataTransfer.items;
  if (items && items.length && items[0].webkitGetAsEntry) {
    var entries = [];
    for (var i=0; i<items.length; i++) {
      var entry = items[i].webkitGetAsEntry && items[i].webkitGetAsEntry();
      if (entry) entries.push(entry);
    }
    if (entries.length) { uploadEntries(entries); return; }
  }
  upload(e.dataTransfer.files);
});
fi.addEventListener('change', function(){ upload(fi.files); fi.value=''; });
if (folderPickLink) folderPickLink.addEventListener('click', function(e){ e.stopPropagation(); folderInput.click(); });
if (folderInput) folderInput.addEventListener('change', function(){ uploadFileListWithRelPaths(folderInput.files); folderInput.value=''; });
var folderUploadCompact = document.getElementById('folder-upload-compact');
if (folderUploadCompact) folderUploadCompact.addEventListener('click', function(e){ e.stopPropagation(); });

// Walk dropped directory entries (webkitGetAsEntry) into a flat list of {file, relPath}
function uploadEntries(entries) {
  var out = [];
  var pending = 0, started = false;
  function walk(entry, prefix) {
    pending++;
    if (entry.isFile) {
      entry.file(function(file) {
        out.push({file: file, rel: prefix + file.name});
        pending--;
        finishIfDone();
      }, function(){ pending--; finishIfDone(); });
    } else if (entry.isDirectory) {
      var reader = entry.createReader();
      var readBatch = function() {
        reader.readEntries(function(children) {
          if (!children.length) { pending--; finishIfDone(); return; }
          children.forEach(function(child) { walk(child, prefix + entry.name + '/'); });
          readBatch();
        }, function(){ pending--; finishIfDone(); });
      };
      readBatch();
    } else {
      pending--;
    }
  }
  function finishIfDone() {
    if (pending === 0 && !started) { started = true; uploadRelPaths(out); }
  }
  entries.forEach(function(e){ walk(e, ''); });
}

function uploadFileListWithRelPaths(fileList) {
  var out = [];
  for (var i=0; i<fileList.length; i++) {
    var f = fileList[i];
    out.push({file: f, rel: f.webkitRelativePath || f.name});
  }
  uploadRelPaths(out);
}

// Group files by their subdirectory (relative to current folder) and upload each group.
function uploadRelPaths(items) {
  if (!items.length) return;
  var groups = {};
  var order = [];
  items.forEach(function(it){
    var rel = it.rel.replace(/\\/g,'/');
    var slash = rel.lastIndexOf('/');
    var subdir = slash === -1 ? '' : rel.slice(0, slash);
    if (!groups[subdir]) { groups[subdir] = []; order.push(subdir); }
    groups[subdir].push(it.file);
  });
  prog.style.display='block'; bar.style.width='0'; pct.textContent='0%';
  msg.className=''; msg.textContent='';
  uploadGroups(order, groups, 0);
}

function uploadGroups(order, groups, idx) {
  if (idx >= order.length) {
    prog.style.display='none';
    msg.className='ok'; msg.textContent='// uploaded'; loadFiles();
    return;
  }
  var subdir = order[idx];
  var files = groups[subdir];
  var destPath = currentPath ? (subdir ? currentPath+'/'+subdir : currentPath) : subdir;
  if (R2_MODE) {
    uploadR2WithPath(files, 0, destPath, function(){ uploadGroups(order, groups, idx+1); });
    return;
  }
  var fd = new FormData();
  for (var i=0; i<files.length; i++) fd.append('files', files[i]);
  var url = '/upload' + (destPath ? '?path=' + encodeURIComponent(destPath) : '');
  var xhr = new XMLHttpRequest();
  xhr.upload.addEventListener('progress', function(e){
    if (e.lengthComputable){
      var p = Math.round((idx + e.loaded/e.total) / order.length * 100);
      bar.style.width=p+'%'; pct.textContent=p+'%';
    }
  });
  xhr.addEventListener('load', function(){
    if (xhr.status===200){ uploadGroups(order, groups, idx+1); }
    else { prog.style.display='none'; msg.className='err'; msg.textContent='// failed: '+xhr.responseText; }
  });
  xhr.addEventListener('error', function(){ prog.style.display='none'; msg.className='err'; msg.textContent='// network error'; });
  xhr.open('POST', url); xhr.send(fd);
}

function uploadR2WithPath(files, idx, destPath, onDone) {
  if (idx >= files.length) { onDone(); return; }
  var file = files[idx];
  var q = '?name=' + encodeURIComponent(file.name) + (destPath ? '&path=' + encodeURIComponent(destPath) : '');
  fetch('/presign' + q, {credentials:'include'})
    .then(function(r){ if (!r.ok) throw new Error('presign '+r.status); return r.json(); })
    .then(function(data){
      var xhr = new XMLHttpRequest();
      xhr.addEventListener('load', function(){
        if (xhr.status===200 || xhr.status===204){ uploadR2WithPath(files, idx+1, destPath, onDone); }
        else { prog.style.display='none'; msg.className='err'; msg.textContent='// upload failed: '+xhr.status; }
      });
      xhr.addEventListener('error', function(){ prog.style.display='none'; msg.className='err'; msg.textContent='// network error'; });
      xhr.open('PUT', data.url);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.send(file);
    })
    .catch(function(e){ prog.style.display='none'; msg.className='err'; msg.textContent='// '+e.message; });
}

// ── Upload ────────────────────────────────────────────────────────────────────
function upload(files, destPath) {
  if (!files || !files.length) return;
  var dest = (destPath === undefined || destPath === null) ? currentPath : destPath;
  prog.style.display='block'; bar.style.width='0'; pct.textContent='0%';
  msg.className=''; msg.textContent='';
  if (R2_MODE) { uploadR2(Array.from(files), 0, dest); return; }
  var fd = new FormData();
  for (var i=0; i<files.length; i++) fd.append('files', files[i]);
  var url = '/upload' + (dest ? '?path=' + encodeURIComponent(dest) : '');
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

function uploadR2(files, idx, dest) {
  if (dest === undefined || dest === null) dest = currentPath;
  if (idx >= files.length) {
    prog.style.display='none';
    msg.className='ok'; msg.textContent='// uploaded';
    loadFiles(); return;
  }
  var file = files[idx];
  var q = '?name=' + encodeURIComponent(file.name) + (dest ? '&path=' + encodeURIComponent(dest) : '');
  fetch('/presign' + q, {credentials:'include'})
    .then(function(r){ if (!r.ok) throw new Error('presign '+r.status); return r.json(); })
    .then(function(data){
      var xhr = new XMLHttpRequest();
      xhr.upload.addEventListener('progress', function(e){
        if (e.lengthComputable){
          var p = Math.round((idx + e.loaded/e.total) / files.length * 100);
          bar.style.width=p+'%'; pct.textContent=p+'%';
        }
      });
      xhr.addEventListener('load', function(){
        if (xhr.status===200 || xhr.status===204){ uploadR2(files, idx+1, dest); }
        else { prog.style.display='none'; msg.className='err'; msg.textContent='// upload failed: '+xhr.status; }
      });
      xhr.addEventListener('error', function(){ prog.style.display='none'; msg.className='err'; msg.textContent='// network error'; });
      xhr.open('PUT', data.url);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.send(file);
    })
    .catch(function(e){ prog.style.display='none'; msg.className='err'; msg.textContent='// '+e.message; });
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
  listSeq++;   // discard any listing still in flight for the old folder
  currentPath = path;
  renderShareBanner();
  extFilter = null;
  closeExtMenu();
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
    makeDropTarget(el, el.dataset.path);   // drop onto a crumb to move up a level
  });
}

// ── File list ─────────────────────────────────────────────────────────────────
// ── Listing requests ──────────────────────────────────────────────────────────
// Every listing request is numbered, and a response is applied only if it is
// still the most recent one AND was issued for the folder currently on screen.
// Without this, a slow root listing (R2 goes over the network) could land after
// you had already opened a folder and snap the view back to the root.
var listSeq = 0;
var pendingOps = 0;   // in-flight mutations: the poll must not fight them

function loadFiles() {
  var seq = ++listSeq;
  var forPath = currentPath;
  var url = '/files' + (currentPath ? '?path=' + encodeURIComponent(currentPath) : '');
  if (showLocked) url += (url.indexOf('?') === -1 ? '?' : '&') + 'locked=1';
  fetch(url).then(function(r){return r.json();}).then(function(files){
    if (seq !== listSeq || forPath !== currentPath) return;   // superseded
    currentFiles = files || [];
    lastFilesJSON = JSON.stringify(files);
    renderList(currentFiles);
  }).catch(function(){
    if (seq !== listSeq || forPath !== currentPath) return;
    list.innerHTML='<div class="empty-state">// error loading</div>';
  });
}

// ── Optimistic updates ────────────────────────────────────────────────────────
// The screen changes at once and the request is reconciled afterwards, so the
// UI does not sit still waiting on the network. If the request fails the old
// listing is put back and the reason is reported.

function pathsOf(entries) {
  return entries.map(function(f){ return currentPath ? currentPath + '/' + f.name : f.name; });
}

function removeFromListing(paths) {
  var gone = {};
  paths.forEach(function(p){ gone[p] = true; });
  currentFiles = currentFiles.filter(function(f){
    return !gone[currentPath ? currentPath + '/' + f.name : f.name];
  });
}

// Turn a failure into something that says what actually went wrong.
function describeFailure(action, status, text) {
  var t = (text || '').trim();
  if (!status)        return 'Could not ' + action + ' — no connection to the server';
  if (status === 401) return 'Could not ' + action + ' — your session expired, reload the page';
  if (status === 403) return t || ('Could not ' + action + ' — it is locked, or outside the shared folder');
  if (status === 404) return 'Could not ' + action + ' — it is no longer there';
  if (status === 405) return 'Could not ' + action + ' — that action is not allowed here';
  if (status === 409) return t || ('Could not ' + action + ' — something with that name already exists');
  if (status === 429) return 'Too many attempts — wait a moment and try again';
  if (status === 503) return t || ('Could not ' + action + ' — that feature is not available on this server');
  if (status >= 500)  return 'Could not ' + action + ' — the server had a problem';
  return t ? ('Could not ' + action + ' — ' + t) : ('Could not ' + action);
}

// apply() changes the listing straight away; run() returns the fetch promise.
function optimistic(action, apply, run, okMsg) {
  var snapshot = currentFiles.slice();
  apply();
  rerender();
  pendingOps++;
  run()
    .then(function(r){
      if (r.ok) {
        if (okMsg) { msg.className = 'ok'; msg.textContent = '// ' + okMsg; }
        return null;
      }
      return r.text().then(function(t){ throw {status: r.status, text: t}; });
    })
    .catch(function(e){
      currentFiles = snapshot;          // put it back exactly as it was
      rerender();
      msg.className = 'err';
      msg.textContent = '// ' + describeFailure(action, e && e.status, e && e.text);
    })
    .then(function(){
      pendingOps--;
      loadFiles();                      // reconcile with what the server really has
    });
}

// ── Extension filter ──────────────────────────────────────────────────────────
// extFilter === null  -> show everything
// extFilter === ''    -> show only files with no extension
// extFilter === 'mkv' -> show only .mkv
var extFilter = null;
var extBtn      = document.getElementById('ext-btn');
var extBtnLabel = document.getElementById('ext-btn-label');
var extMenu     = document.getElementById('ext-menu');

function extOf(name) {
  var slash = name.lastIndexOf('/');
  var base = slash >= 0 ? name.slice(slash + 1) : name;
  var dot = base.lastIndexOf('.');
  if (dot <= 0 || dot === base.length - 1) return '';
  return base.slice(dot + 1).toLowerCase();
}

function extLabel(ext) { return ext ? '.' + ext : 'No extension'; }

function closeExtMenu() { if (extMenu) extMenu.classList.remove('open'); }

function toggleExtMenu(e) {
  e.stopPropagation();
  closeMenu();
  extMenu.classList.toggle('open');
}

function setExtFilter(ext) {
  extFilter = ext;
  closeExtMenu();
  // selections can point at rows the filter now hides — drop them rather than
  // silently bulk-deleting something the user can no longer see
  if (selectMode) { selectedPaths.clear(); updateSelectBar(); }
  rerender();
}

// Re-render whatever view is currently on screen (folder listing or search results).
function rerender() {
  var q = searchInput && searchInput.value ? searchInput.value.trim() : '';
  if (q) renderSearchList(currentFiles, q);
  else renderList(currentFiles);
}

// Rebuild the dropdown from the UNFILTERED listing so every extension stays reachable.
function syncExtMenu(files) {
  if (!extBtn) return;
  var counts = {}, exts = [], total = 0;
  for (var i = 0; i < files.length; i++) {
    if (files[i].is_dir) continue;
    var ext = extOf(files[i].name);
    if (counts[ext] === undefined) { counts[ext] = 0; exts.push(ext); }
    counts[ext]++; total++;
  }
  exts.sort();
  // active filter no longer present in this listing (navigated away, file deleted)
  if (extFilter !== null && counts[extFilter] === undefined) extFilter = null;
  extBtn.disabled = exts.length === 0;
  extBtn.classList.toggle('active', extFilter !== null);
  extBtnLabel.textContent = extFilter !== null ? extLabel(extFilter) : 'All';
  if (exts.length === 0) { extMenu.innerHTML = ''; closeExtMenu(); return; }
  var html = '<button class="ext-item' + (extFilter === null && !showLocked ? ' sel' : '') +
             '" data-ext="*">All<span class="ext-count">' + total + '</span></button>';
  // the only place locked items are visible
  html += '<button class="ext-item' + (showLocked ? ' sel' : '') +
          '" data-ext="**">All + ·<span class="ext-count">locked</span></button>';
  for (var j = 0; j < exts.length; j++) {
    var e = exts[j];
    html += '<button class="ext-item' + (extFilter === e ? ' sel' : '') + '" data-ext="' + esc(e) + '">' +
            esc(extLabel(e)) + '<span class="ext-count">' + counts[e] + '</span></button>';
  }
  extMenu.innerHTML = html;
  var btns = extMenu.querySelectorAll('[data-ext]');
  for (var k = 0; k < btns.length; k++) {
    btns[k].addEventListener('click', function () {
      var v = this.getAttribute('data-ext');
      if (v === '**') { showLocked = true;  extFilter = null; closeExtMenu(); loadFiles(); return; }
      if (showLocked) { showLocked = false; closeExtMenu(); setExtFilter(v === '*' ? null : v); loadFiles(); return; }
      setExtFilter(v === '*' ? null : v);
    });
  }
}

// Folders are hidden while a filter is active — a .mkv filter showing folders
// would be lying about what matched.
function visibleFiles(files) {
  if (extFilter === null) return files;
  return files.filter(function (f) { return !f.is_dir && extOf(f.name) === extFilter; });
}

function countLabel(files) {
  var totalBytes = 0, fileCount = 0;
  for (var i = 0; i < files.length; i++) {
    if (!files[i].is_note && !files[i].is_dir) { totalBytes += files[i].size; fileCount++; }
  }
  var dirCount = files.filter(function (f) { return f.is_dir; }).length;
  var label = '';
  if (dirCount) label += dirCount + ' folder' + (dirCount !== 1 ? 's' : '');
  if (fileCount) label += (label ? ' · ' : '') + fileCount + ' file' + (fileCount !== 1 ? 's' : '');
  if (totalBytes) label += ' · ' + fmtSize(totalBytes);
  return label;
}

function appendRows(files) {
  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    // locked and not yet unlocked: an inert placeholder, nothing to act on
    if (f.locked && !f.unlocked) { list.appendChild(makeLockedRow(f)); continue; }
    var row = f.is_dir ? makeDirRow(f) : (f.is_note ? makeNoteRow(f) : makeFileRow(f));
    if (f.locked) row.classList.add('is-locked');   // unlocked, but still marked
    list.appendChild(row);
  }
}

// ── New folder ────────────────────────────────────────────────────────────────
var promptModal = document.getElementById('prompt-modal');
var promptInput = document.getElementById('prompt-input');
var promptErr   = document.getElementById('prompt-err');
// built without any escape sequences so the character list stays readable
var badNameChars = ':*?"<>|/' + String.fromCharCode(92);

function hasBadNameChar(s) {
  for (var i = 0; i < badNameChars.length; i++) {
    if (s.indexOf(badNameChars.charAt(i)) !== -1) return true;
  }
  return false;
}


// askText reuses the new-folder dialog for any single-line input. fn returns
// either an error string, or a promise that resolves when it has finished.
var promptSubmit = null;
function askText(title, placeholder, okLabel, fn) {
  closeMenu();
  document.getElementById('prompt-title').textContent = title;
  promptInput.placeholder = placeholder;
  promptInput.value = '';
  promptErr.style.display = 'none';
  document.getElementById('prompt-ok').textContent = okLabel;
  promptSubmit = fn;
  promptModal.classList.add('open');
  promptInput.focus();
}
function openNewFolder() {
  closeExtMenu();
  promptSubmit = null;
  document.getElementById("prompt-title").textContent = "New folder";
  document.getElementById("prompt-ok").textContent = "Create";
  promptInput.placeholder = "folder name";
  promptInput.value = '';
  promptErr.style.display = 'none';
  promptModal.classList.add('open');
  promptInput.focus();
}

function closePrompt() {
  promptModal.classList.remove('open');
  promptErr.style.display = 'none';
}

function promptError(t) {
  promptErr.textContent = '// ' + t;
  promptErr.style.display = 'block';
}

function submitNewFolder() {
  var name = promptInput.value.trim();
  if (!name) { promptError('name required'); return; }
  if (promptSubmit) {
    var r = promptSubmit(name);
    if (typeof r === "string") { promptError(r); return; }
    if (r && r.then) { r.then(function(){ closePrompt(); promptSubmit = null; })
                          .catch(function(e){ promptError(e.message || "failed"); }); }
    else { closePrompt(); promptSubmit = null; }
    return;
  }
  if (name === '.' || name === '..' || hasBadNameChar(name)) {
    promptError('cannot contain ' + badNameChars.split('').join(' '));
    return;
  }
  var url = '/mkdir?name=' + encodeURIComponent(name) +
            (currentPath ? '&path=' + encodeURIComponent(currentPath) : '');
  fetch(url, {method:'POST'})
    .then(function(r){
      if (r.ok) { closePrompt(); loadFiles(); return; }
      r.text().then(function(t){ promptError(t.trim() || 'could not create folder'); });
    })
    .catch(function(){ promptError('network error'); });
}

promptInput.addEventListener('keydown', function(e){
  if (e.key === 'Enter') { e.preventDefault(); submitNewFolder(); }
  else if (e.key === 'Escape') { e.stopPropagation(); closePrompt(); }
});
promptModal.addEventListener('click', function(e){ if (e.target === promptModal) closePrompt(); });

// ── Unplayable video handoff ──────────────────────────────────────────────────
// iOS WebKit has no Matroska demuxer, so .mkv can never play inline there and
// downloading a multi-GB file to a phone is useless. VLC registers a vlc://
// scheme that streams a URL straight into the app — but VLC fetches that URL
// itself and never carries this page's session cookie (it is HttpOnly and
// SameSite=Strict precisely so it cannot reach another app), so the link needs
// a file-scoped token minted just for the handoff.
var externalPlayerExts = ['mkv','avi','wmv','flv','ts','m2ts','mpg','mpeg'];

function isIOS() {
  // iPadOS reports itself as MacIntel, hence the touch-point check
  return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
         (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

function handOffToPlayer(path) {
  msg.className = '';
  msg.textContent = '// opening ' + path.split('/').pop() + ' in your video app...';
  fetch('/file-token?name=' + encodeURIComponent(path))
    .then(function(r){ if (!r.ok) throw new Error('token'); return r.json(); })
    .then(function(d){
      // absolute — VLC has no base URL to resolve against
      var u = location.origin + '/file?name=' + encodeURIComponent(path) +
              '&tok=' + encodeURIComponent(d.token);
      window.location.href = 'vlc://' + u;
    })
    .catch(function(){
      msg.className = 'err';
      msg.textContent = '// could not open in a video app — install VLC, or download the file';
    });
}

function renderList(files) {
  files = files || [];
  syncExtMenu(files);
  var shown = visibleFiles(files);
  list.innerHTML = '';
  if (!shown.length) {
    if (extFilter !== null) {
      divT.textContent = extFilter ? 'No ' + extLabel(extFilter) + ' files here'
                                   : 'No files without an extension here';
      list.innerHTML = '<div class="empty-state">// nothing matches this filter</div>';
    } else {
      divT.textContent = currentPath ? 'Empty folder' : 'Empty';
      list.innerHTML = '<div class="empty-state">// nothing here yet</div>';
    }
    return;
  }
  divT.textContent = countLabel(shown) || 'Empty';
  appendRows(shown);
}

function renderSearchList(files, q) {
  files = files || [];
  syncExtMenu(files);
  var shown = visibleFiles(files);
  list.innerHTML = '';
  if (!shown.length) {
    divT.textContent = 'No results for "' + q + '"';
    list.innerHTML = '<div class="empty-state">// nothing matched</div>';
    return;
  }
  divT.textContent = shown.length + ' result' + (shown.length !== 1 ? 's' : '') + ' for "' + q + '"';
  appendRows(shown);
}

// ── Move: drag-and-drop + picker ──────────────────────────────────────────────
// dragSrcPath is set only while an internal row is being dragged; a drop with it
// null means files arrived from the desktop and should be uploaded instead.
var dragSrcPath = null;

function parentOf(p) {
  var i = p.lastIndexOf('/');
  return i === -1 ? '' : p.slice(0, i);
}

// True if dest is the item itself or somewhere inside it — moving a folder into
// its own subtree would detach it. The server enforces this too.
function insideSelf(src, dest) {
  return dest === src || dest.indexOf(src + '/') === 0;
}

function makeDraggable(el, itemPath) {
  el.draggable = true;
  el.addEventListener('dragstart', function(e){
    if (selectMode) { e.preventDefault(); return; }
    dragSrcPath = itemPath;
    e.dataTransfer.effectAllowed = 'move';
    try { e.dataTransfer.setData('text/plain', itemPath); } catch(err){}
    el.classList.add('dragging');
  });
  el.addEventListener('dragend', function(){
    dragSrcPath = null;
    el.classList.remove('dragging');
    var t = document.querySelectorAll('.drop-target');
    for (var i = 0; i < t.length; i++) t[i].classList.remove('drop-target');
  });
}

// Folder rows and breadcrumb crumbs take both kinds of drop: an internal row
// (move it here) and desktop files (upload straight into this folder).
function makeDropTarget(el, folderPath) {
  el.addEventListener('dragover', function(e){
    if (dragSrcPath !== null &&
        (insideSelf(dragSrcPath, folderPath) || parentOf(dragSrcPath) === folderPath)) return;
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = dragSrcPath !== null ? 'move' : 'copy';
    el.classList.add('drop-target');
  });
  el.addEventListener('dragleave', function(e){
    if (!el.contains(e.relatedTarget)) el.classList.remove('drop-target');
  });
  el.addEventListener('drop', function(e){
    e.preventDefault();
    e.stopPropagation();
    el.classList.remove('drop-target');
    if (dragSrcPath !== null) {
      var src = dragSrcPath;
      dragSrcPath = null;
      moveItem(src, folderPath);
      return;
    }
    if (e.dataTransfer.files && e.dataTransfer.files.length) upload(e.dataTransfer.files, folderPath);
  });
}


// ── Right-click context menu ──────────────────────────────────────────────────
// openMenu() anchors to a button; this positions at the pointer instead, and
// flips back inside the viewport when opened near an edge.
function openContextMenu(x, y, actions) {
  closeMenu();
  closeExtMenu();
  var menu = buildMenuEl(actions);
  menu.classList.add('ctx-menu');
  document.body.appendChild(menu);
  var w = menu.offsetWidth, h = menu.offsetHeight;
  if (x + w > window.innerWidth - 8) x = Math.max(8, window.innerWidth - w - 8);
  if (y + h > window.innerHeight - 8) y = Math.max(8, window.innerHeight - h - 8);
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  activeMenu = menu;
}

// ── Clipboard (copy / cut / paste) ────────────────────────────────────────────
// Holds an array so a multi-selection can be copied or cut as one unit.
var clipPaths = [];
var clipMode  = null; // 'copy' | 'cut'

function clipCopy(paths) { clipPaths = [].concat(paths); clipMode = 'copy'; flashClip('copied'); }
function clipCut(paths)  { clipPaths = [].concat(paths); clipMode = 'cut';  flashClip('cut'); }

function clipClear() { clipPaths = []; clipMode = null; }

function clipName() {
  if (clipPaths.length === 1) return clipPaths[0].split('/').pop();
  return clipPaths.length + ' items';
}

function flashClip(what) {
  msg.className = '';
  msg.textContent = '// ' + clipName() + ' ' + what + ' — right-click where you want it and choose paste';
}

function clipboardLabel() {
  if (!clipPaths.length) return '';
  return (clipMode === 'cut' ? 'Paste (move) ' : 'Paste ') + clipName();
}

// Paste lands every clipboard entry into destFolder: a cut moves, a copy duplicates.
function pasteInto(destFolder) {
  if (!clipPaths.length) return;
  var srcs = clipPaths.slice(), mode = clipMode;
  for (var i = 0; i < srcs.length; i++) {
    if (insideSelf(srcs[i], destFolder)) {
      msg.className = 'err';
      msg.textContent = '// cannot paste a folder into itself';
      return;
    }
  }
  var endpoint = mode === 'cut' ? '/move' : '/copy';
  var verb = mode === 'cut' ? 'move' : 'copy';
  var snapshot = currentFiles.slice();
  // A cut leaves this folder straight away; a copy adds something we cannot name
  // in advance, so that one just reconciles when the request lands.
  if (mode === 'cut') { removeFromListing(srcs); rerender(); }
  else { msg.className = ''; msg.textContent = '// copying ' + srcs.length + '...'; }
  pendingOps++;
  var done = 0, failed = 0, lastStatus = 0, lastText = '';
  function next(i) {
    if (i >= srcs.length) {
      pendingOps--;
      if (mode === 'cut' && !failed) clipClear();
      if (failed) {
        if (mode === 'cut' && done === 0) { currentFiles = snapshot; rerender(); }
        msg.className = 'err';
        msg.textContent = '// ' + describeFailure(verb + ' ' + failed + ' of ' + srcs.length, lastStatus, lastText);
      } else {
        msg.className = 'ok';
        msg.textContent = '// ' + (mode === 'cut' ? 'moved ' : 'copied ') + done + ' to ' + (destFolder || 'root');
      }
      loadFiles();
      return;
    }
    fetch(endpoint + '?name=' + encodeURIComponent(srcs[i]) + '&to=' + encodeURIComponent(destFolder), {method:'POST'})
      .then(function(r){
        if (r.ok) { done++; next(i+1); return; }
        failed++; lastStatus = r.status;
        return r.text().then(function(t){ lastText = t; next(i+1); });
      })
      .catch(function(){ failed++; lastStatus = 0; next(i+1); });
  }
  next(0);
}

// ── Upload to the public site ─────────────────────────────────────────────────
// Pushes a local file into the R2 bucket the public server serves, so it becomes
// reachable at the public URL.
function publishFile(p) {
  msg.className = '';
  msg.textContent = '// uploading ' + p.split('/').pop() + ' to the public site...';
  fetch('/publish?name=' + encodeURIComponent(p), {method:'POST'})
    .then(function(r){
      if (!r.ok) return r.text().then(function(t){ throw new Error(t.trim() || ('HTTP ' + r.status)); });
      return r.json();
    })
    .then(function(d){
      msg.className = 'ok';
      msg.textContent = '// uploaded — ' + d.url;
      copyText(d.url, null, '');
    })
    .catch(function(e){ msg.className='err'; msg.textContent='// upload: ' + e.message; });
}

// ── Per-row menus ─────────────────────────────────────────────────────────────
// Menu order follows the usual desktop convention: the primary action first,
// then clipboard, then transfer, then selection, with the destructive action
// alone at the bottom behind a separator so it is never a slip away.

// A locked item only reaches a menu once it has been unlocked for this session,
// so the choice is between locking a plain item and removing an existing lock.
function addLockAction(a, p) {
  var st = lockStateOf(p);
  if (st && st.locked) a.push({label:'Remove lock', fn:function(){ removeLockItem(p); }});
  else a.push({label:'Lock', fn:function(){ lockItem(p); }});
}
function fileMenuActions(p, kind) {
  var a = [{label:'Open', fn:function(){ kind === 'note' ? openNotePreview(p) : openPreview(p); }}];
  if (SHARE_MODE) { a.push({sep:true}); a.push({label:'Download', fn:function(){ dlFile(p); }}); return a; }
  a.push({sep:true});
  a.push({label:'Select', fn:function(){ selectOnly(p); }});
  a.push({label:'Copy',   fn:function(){ clipCopy([p]); }});
  a.push({label:'Cut',    fn:function(){ clipCut([p]); }});
  // Pointless at the root, where there is no level above to move to — cut and
  // paste covers moving downwards from there.
  if (currentPath) a.push({label:'Move to...', fn:function(){ openMovePicker(p); }});
  a.push({sep:true});
  a.push({label:'Download', fn:function(){ dlFile(p); }});
  if (CAN_PUBLISH) a.push({label:'Upload', fn:function(){ publishFile(p); }});
  a.push({sep:true});
  addLockAction(a, p);
  a.push({label:'Delete', danger:true, fn:function(){ deleteItem(p); }});
  return a;
}

function dirMenuActions(p) {
  var a = [{label:'Open', fn:function(){ navigateTo(p); }}];
  if (SHARE_MODE) return a;
  a.push({sep:true});
  a.push({label:'Select', fn:function(){ selectOnly(p); }});
  a.push({label:'Copy',   fn:function(){ clipCopy([p]); }});
  a.push({label:'Cut',    fn:function(){ clipCut([p]); }});
  if (currentPath) a.push({label:'Move to...', fn:function(){ openMovePicker(p); }});
  if (clipPaths.length) a.push({label:clipboardLabel(), fn:function(){ pasteInto(p); }});
  if (!R2_MODE) {
    a.push({sep:true});
    a.push({label:'Download', fn:function(){ dlFolder(p); }});
  }
  a.push({sep:true});
  addLockAction(a, p);
  a.push({label:'Delete', danger:true, fn:function(){ deleteItem(p); }});
  return a;
}

function selectOnly(p) {
  if (!selectMode) enterSelectMode();
  selectedPaths.add(p);
  updateSelectBar();
  renderList(currentFiles);
}

function attachContextMenu(el, build) {
  el.addEventListener('contextmenu', function(e){
    if (selectMode) return;
    e.preventDefault();
    e.stopPropagation();
    openContextMenu(e.clientX, e.clientY, build());
  });
}

// ── Move picker (works on touch, where dragging rows does not) ────────────────
var moveModal   = document.getElementById('move-modal');
var moveSubject = document.getElementById('move-subject');
var moveCrumb   = document.getElementById('move-crumb');
var moveList    = document.getElementById('move-list');
var moveOk      = document.getElementById('move-ok');
var movingPath  = null;
var moveDest    = '';

function openMovePicker(itemPath) {
  closeMenu();
  movingPath = itemPath;
  moveDest = parentOf(itemPath);
  moveSubject.textContent = itemPath.split('/').pop();
  moveModal.classList.add('open');
  renderMoveList();
}

function closeMove() {
  moveModal.classList.remove('open');
  movingPath = null;
}

function renderMoveList() {
  var parts = moveDest ? moveDest.split('/') : [];
  var crumb = '<span class="mc-item" data-dest="">root</span>';
  var cum = '';
  for (var i = 0; i < parts.length; i++) {
    cum += (cum ? '/' : '') + parts[i];
    crumb += '<span class="mc-sep">/</span><span class="mc-item" data-dest="' + esc(cum) + '">' + esc(parts[i]) + '</span>';
  }
  moveCrumb.innerHTML = crumb;
  var crumbs = moveCrumb.querySelectorAll('[data-dest]');
  for (var c = 0; c < crumbs.length; c++) {
    crumbs[c].addEventListener('click', function(){ moveDest = this.getAttribute('data-dest'); renderMoveList(); });
  }
  // cannot land somewhere it already is, nor inside itself
  var blocked = insideSelf(movingPath, moveDest) || parentOf(movingPath) === moveDest;
  moveOk.disabled = blocked;
  moveOk.textContent = blocked ? (insideSelf(movingPath, moveDest) ? 'Inside itself' : 'Already here') : 'Move here';
  moveList.innerHTML = '<div class="move-empty">loading...</div>';
  fetch('/files' + (moveDest ? '?path=' + encodeURIComponent(moveDest) : ''))
    .then(function(r){ return r.json(); })
    .then(function(files){
      var dirs = (files || []).filter(function(f){ return f.is_dir; });
      var html = '';
      for (var i = 0; i < dirs.length; i++) {
        var full = moveDest ? moveDest + '/' + dirs[i].name : dirs[i].name;
        var self = insideSelf(movingPath, full);
        html += '<button class="move-row' + (self ? ' disabled' : '') + '" data-into="' + esc(full) + '"' +
                (self ? ' disabled' : '') + '>' + esc(dirs[i].name.split('/').pop()) + '</button>';
      }
      moveList.innerHTML = html || '<div class="move-empty">// no subfolders here</div>';
      var rows = moveList.querySelectorAll('[data-into]');
      for (var k = 0; k < rows.length; k++) {
        rows[k].addEventListener('click', function(){ moveDest = this.getAttribute('data-into'); renderMoveList(); });
      }
    })
    .catch(function(){ moveList.innerHTML = '<div class="move-empty">// could not load folders</div>'; });
}

function confirmMove() {
  if (!movingPath) return;
  var src = movingPath, dest = moveDest;
  closeMove();
  moveItem(src, dest);
}

moveModal.addEventListener('click', function(e){ if (e.target === moveModal) closeMove(); });
// ── Locked items ──────────────────────────────────────────────────────────────
// showLocked drives the "All + ·" view. Locked items are hidden from the normal
// listing by the server; in this view they come back as inert placeholders.
var showLocked = false;

var pwModal  = document.getElementById('pw-modal');
var pwTitle  = document.getElementById('pw-title');
var pwSub    = document.getElementById('pw-sub');
var pwInput  = document.getElementById('pw-input');
var pwErr    = document.getElementById('pw-err');
var pwOk     = document.getElementById('pw-ok');
var pwSubmit = null;

function askPassword(title, sub, okLabel, fn) {
  closeMenu();
  pwTitle.textContent = title;
  pwSub.textContent = sub;
  pwOk.textContent = okLabel;
  pwInput.value = '';
  pwErr.style.display = 'none';
  pwSubmit = fn;
  pwModal.classList.add('open');
  pwInput.focus();
}

function closePw() {
  pwModal.classList.remove('open');
  pwSubmit = null;
}

function pwError(t) {
  pwErr.textContent = '// ' + t;
  pwErr.style.display = 'block';
  pwInput.focus();
  pwInput.select();
}

function submitPw() {
  if (!pwSubmit) return;
  var v = pwInput.value;
  if (!v) { pwError('password required'); return; }
  pwSubmit(v);
}

pwOk.addEventListener('click', submitPw);
pwInput.addEventListener('keydown', function(e){
  if (e.key === 'Enter') { e.preventDefault(); submitPw(); }
  else if (e.key === 'Escape') { e.stopPropagation(); closePw(); }
});
pwModal.addEventListener('click', function(e){ if (e.target === pwModal) closePw(); });

// what the server told us about this path in the current listing
function lockStateOf(path) {
  for (var i = 0; i < currentFiles.length; i++) {
    var full = currentPath ? currentPath + '/' + currentFiles[i].name : currentFiles[i].name;
    if (full === path) return currentFiles[i];
  }
  return null;
}

function lockItem(p) {
  askPassword('Lock', p.split('/').pop(), 'Lock', function(pw){
    fetch('/lock?name=' + encodeURIComponent(p), {method:'POST', body:pw})
      .then(function(r){
        if (r.ok) { closePw(); msg.className='ok'; msg.textContent='// locked ' + p.split('/').pop(); loadFiles(); return; }
        r.text().then(function(t){ pwError(t.trim() || 'could not lock'); });
      })
      .catch(function(){ pwError('network error'); });
  });
}

function unlockItem(p) {
  askPassword('Unlock', p.split('/').pop(), 'Unlock', function(pw){
    fetch('/unlock?name=' + encodeURIComponent(p), {method:'POST', body:pw})
      .then(function(r){
        if (r.ok) {
          return r.json().then(function(d){
            closePw();
            msg.className = 'ok';
            msg.textContent = '// unlocked for ' + d.hours + 'h on this device';
            loadFiles();
          });
        }
        r.text().then(function(t){ pwError(t.trim() || 'incorrect password'); });
      })
      .catch(function(){ pwError('network error'); });
  });
}

function removeLockItem(p) {
  askPassword('Remove lock', p.split('/').pop(), 'Remove', function(pw){
    fetch('/remove-lock?name=' + encodeURIComponent(p), {method:'POST', body:pw})
      .then(function(r){
        if (r.ok) { closePw(); msg.className='ok'; msg.textContent='// lock removed'; loadFiles(); return; }
        r.text().then(function(t){ pwError(t.trim() || 'incorrect password'); });
      })
      .catch(function(){ pwError('network error'); });
  });
}

// A still-locked entry: greyed, and inert apart from the click that asks for the
// password. No menu, no drag, no selection — there is nothing to act on yet.
function makeLockedRow(f) {
  var el = document.createElement('div');
  el.className = 'file-item locked-row';
  var p = currentPath ? currentPath + '/' + f.name : f.name;
  el.innerHTML =
    '<div class="file-thumb ft-lock">&#x1F512;</div>' +
    '<div class="file-info-col">' +
      '<div class="file-name">' + esc(f.name.split('/').pop()) + '</div>' +
      '<div class="file-type-date">' + (f.is_dir ? 'Locked folder' : 'Locked') + ' &#xB7; click to unlock</div>' +
    '</div>' +
    '<div class="file-actions"></div>';
  el.addEventListener('click', function(){ unlockItem(p); });
  return el;
}
// ── Sharing ───────────────────────────────────────────────────────────────────
// Share builds a folder from a selection: name it, tick the files, and they are
// copied in. The folder then carries a link that opens it as someone else's root
// without a password.
var shareStage = null;   // null | 'picking'
var shareTarget = '';

function startShare() {
  closeExtMenu();
  askText('New shared folder', 'folder name', 'Next', function(name){
    var bad = name === '.' || name === '..' || hasBadNameChar(name);
    if (bad) return 'cannot contain ' + badNameChars.split('').join(' ');
    var dest = currentPath ? currentPath + '/' + name : name;
    return fetch('/mkdir?name=' + encodeURIComponent(name) +
                 (currentPath ? '&path=' + encodeURIComponent(currentPath) : ''), {method:'POST'})
      .then(function(r){
        if (!r.ok) return r.text().then(function(t){ throw new Error(t.trim() || 'could not create folder'); });
        shareTarget = dest;
        shareStage = 'picking';
        if (!selectMode) enterSelectMode();
        updateSelectBar();
        msg.className = '';
        msg.textContent = '// tick the files to put in "' + name + '", then press Add';
        return null;
      });
  });
}

// Copy the ticked files in, then mint the link and open the folder.
function finishShare() {
  var picked = Array.from(selectedPaths);
  var dest = shareTarget;
  shareStage = null;
  exitSelectMode();
  msg.className = '';
  msg.textContent = '// building shared folder...';
  var i = 0, failed = 0;
  function next() {
    if (i >= picked.length) {
      fetch('/share?name=' + encodeURIComponent(dest), {method:'POST'})
        .then(function(r){
          if (!r.ok) return r.text().then(function(t){ throw new Error(t.trim() || 'could not create link'); });
          return r.json();
        })
        .then(function(d){
          msg.className = failed ? 'err' : 'ok';
          msg.textContent = failed ? '// shared, but ' + failed + ' file(s) could not be copied'
                                   : '// shared ' + dest.split('/').pop();
          navigateTo(dest);
        })
        .catch(function(e){ msg.className='err'; msg.textContent='// ' + e.message; loadFiles(); });
      return;
    }
    fetch('/copy?name=' + encodeURIComponent(picked[i]) + '&to=' + encodeURIComponent(dest), {method:'POST'})
      .then(function(r){ if (!r.ok) failed++; i++; next(); })
      .catch(function(){ failed++; i++; next(); });
  }
  next();
}

function cancelShare() {
  shareStage = null;
  exitSelectMode();
  msg.textContent = '';
}

// Banner shown at the top of a shared folder: the QR first, then the link.
function renderShareBanner() {
  var wrap = document.getElementById('share-banner');
  if (!wrap) return;
  // a visitor already is inside the share; the banner is for the owner
  if (SHARE_MODE || !currentPath) { wrap.style.display = 'none'; return; }
  fetch('/share-info?name=' + encodeURIComponent(currentPath))
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      if (!d || !d.url) { wrap.style.display = 'none'; return; }
      wrap.style.display = 'flex';
      wrap.innerHTML =
        '<img class="share-qr" src="/qr.png?data=' + encodeURIComponent(d.url) + '" alt="QR code">' +
        '<a class="share-copy" href="#">copy link</a>' +
        '<div class="share-url">' + esc(d.url) + '</div>';
      wrap.querySelector('.share-copy').addEventListener('click', function(e){
        e.preventDefault();
        copyText(d.url, null, '');
        msg.className = 'ok';
        msg.textContent = '// link copied';
      });
    })
    .catch(function(){ wrap.style.display = 'none'; });
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
      '<div class="file-type-date">Folder'+(fmtDate(f.modified)?' &#xB7; '+fmtDate(f.modified):'')+(parentDir?' &#xB7; <span style="opacity:.6">'+esc(parentDir)+'</span>':'')+'</div>'+
    '</div>'+
    '<div class="file-actions">'+
      '<button class="view-btn" title="Open">\u25B7 <span class="btn-lbl">open</span></button>'+
      (!R2_MODE ? '<div class="action-sep"></div><button class="dl-btn" title="Download as zip">\u2193 <span class="btn-lbl">dl</span></button>' : '')+
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
    var dirDlBtn = el.querySelector('.dl-btn');
    if (dirDlBtn) dirDlBtn.addEventListener('click', (function(p){ return function(e){ e.stopPropagation(); dlFolder(p); }; })(dirPath));
    el.querySelector('.menu-btn').addEventListener('click', (function(p){ return function(e){
      e.stopPropagation();
      openMenu(e.currentTarget, dirMenuActions(p));
    }; })(dirPath));
  }
  makeDraggable(el, dirPath);
  attachContextMenu(el, function(){ return dirMenuActions(dirPath); });
  makeDropTarget(el, dirPath);   // folders receive drops: move here, or upload here
  return el;
}

// ── Inline note editing ───────────────────────────────────────────────────────
// Clicking a note's text edits it in place rather than opening a modal. The
// element is made editable on mousedown — before the browser places the caret —
// so the caret lands exactly where the click was, as it would in any editor.
var inlineEditing = null;   // the .note-snippet currently being edited

function noteRowButtons(row, editing) {
  var copy = row.querySelector('.copy-btn');
  var view = row.querySelector('.view-btn');
  if (!copy || !view) return;
  if (editing) {
    copy.innerHTML = '✓ <span class="btn-lbl">save</span>';
    copy.title = 'Save';
    view.innerHTML = '✕ <span class="btn-lbl">cancel</span>';
    view.title = 'Cancel';
    copy.classList.add('save-btn');
    view.classList.add('cancel-btn');
  } else {
    copy.innerHTML = '⎘ <span class="btn-lbl">copy</span>';
    copy.title = 'Copy text';
    view.innerHTML = '▷ <span class="btn-lbl">view</span>';
    view.title = 'Preview';
    copy.classList.remove('save-btn');
    view.classList.remove('cancel-btn');
  }
}

function endInlineEdit(save) {
  var el = inlineEditing;
  if (!el) return;
  // A note whose body is still loading must not be saved: writing the partial
  // text back would truncate the file.
  if (save && el.dataset.pending === "1") {
    msg.className = "err";
    msg.textContent = "// still loading this note — not saved";
    save = false;
  }
  var row = el.closest('.note-item');
  var p = el.dataset.path;
  var original = el.dataset.original;
  var text = el.innerText;
  inlineEditing = null;
  el.contentEditable = 'false';
  el.classList.remove('editing');
  noteRowButtons(row, false);

  if (!save) { el.innerText = original; return; }
  if (text === original) return;               // nothing changed
  fetch('/save-text?name=' + encodeURIComponent(p), {method:'POST', body:text})
    .then(function(r){
      if (!r.ok) return r.text().then(function(t){ throw {status:r.status, text:t}; });
      el.dataset.original = text;
      msg.className = 'ok';
      msg.textContent = '// saved';
    })
    .catch(function(e){
      el.innerText = original;                 // put the old text back
      msg.className = 'err';
      msg.textContent = '// ' + describeFailure('save the note', e && e.status, e && e.text);
    });
}

function startInlineEdit(el, p, truncated) {
  if (inlineEditing === el) return;
  if (inlineEditing) endInlineEdit(true);      // committing one starts the next
  inlineEditing = el;
  el.dataset.path = p;
  el.dataset.original = el.innerText;
  el.contentEditable = 'plaintext-only';
  if (el.contentEditable !== 'plaintext-only') el.contentEditable = 'true';  // Firefox
  el.classList.add('editing');
  noteRowButtons(el.closest('.note-item'), true);

  // A long note only arrives partially in the listing, so fetch the rest before
  // it can be edited — otherwise saving would truncate the file.
  if (truncated) {
    el.dataset.pending = "1";
    fetch("/file?name=" + encodeURIComponent(p))
      .then(function(r){ return r.text(); })
      .then(function(full){
        if (inlineEditing !== el) return;
        el.innerText = full;
        el.dataset.original = full;
        el.dataset.pending = "0";
        var r2 = document.createRange();
        r2.selectNodeContents(el);
        r2.collapse(false);
        var s = window.getSelection();
        s.removeAllRanges();
        s.addRange(r2);
      });
  }

  el.addEventListener('keydown', function(e){
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); endInlineEdit(false); }
    else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); endInlineEdit(true); }
  });
  el.addEventListener('blur', function(){
    // clicking save/cancel handles itself; losing focus elsewhere commits
    setTimeout(function(){ if (inlineEditing === el) endInlineEdit(true); }, 120);
  });
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
    var snip = el.querySelector('.note-snippet');
    var copyBtn = el.querySelector('.copy-btn');
    var viewBtn = el.querySelector('.view-btn');

    // mousedown, not click: the element must already be editable when the
    // browser positions the caret, so it lands where the pointer is.
    snip.addEventListener('mousedown', function(e){
      if (inlineEditing === snip) return;      // already editing, let the caret move
      if (e.button !== 0) return;
      startInlineEdit(snip, notePath, !!f.truncated);
    });

    copyBtn.addEventListener('click', (function(p,btn){
      return function(e){
        e.stopPropagation();
        if (inlineEditing === snip) { endInlineEdit(true); return; }   // acting as Save
        fetch('/file?name='+encodeURIComponent(p)).then(function(r){return r.text();}).then(function(text){
          copyText(text, btn, '⎘');
        });
      };
    })(notePath, copyBtn));

    viewBtn.addEventListener('click', function(e){
      e.stopPropagation();
      if (inlineEditing === snip) { endInlineEdit(false); return; }    // acting as Cancel
      openNotePreview(notePath);
    });

    el.querySelector('.menu-btn').addEventListener('click', (function(p){ return function(e){
      e.stopPropagation();
      openMenu(e.currentTarget, fileMenuActions(p, 'note'));
    }; })(notePath));
  }
  makeDraggable(el, notePath);
  attachContextMenu(el, function(){ return fileMenuActions(notePath, 'note'); });
  return el;
}

function makeFileRow(f) {
  var displayName = f.name.split('/').pop();
  var ext = displayName.includes('.') ? displayName.split('.').pop().toLowerCase() : '';
  var base = ext ? displayName.slice(0,displayName.length-ext.length-1) : displayName;
  var kind = previewKind(ext);
  // .mkv and friends have no previewKind, but they are playable once repackaged
  // (or handed to a video app on iOS), so they must be openable too.
  var canOpen = !!kind || externalPlayerExts.indexOf(ext) !== -1;
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
      (canOpen ? '<button class="view-btn" title="Preview">&#x25B7; <span class="btn-lbl">view</span></button><div class="action-sep"></div>' : '')+
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
    if (!canOpen) el.querySelector('.file-info-col').style.cursor = 'default';
    el.addEventListener('click', (function(p,ok){ return function(e){
      if (e.target.closest('button,input,label')) return;
      if (ok) openPreview(p);
    }; })(filePath, canOpen));
    if (canOpen) el.querySelector('.view-btn').addEventListener('click',(function(p){return function(e){ e.stopPropagation(); openPreview(p); };})(filePath));
    el.querySelector('.dl-btn').addEventListener('click',(function(p){return function(e){ e.stopPropagation(); dlFile(p); };})(filePath));
    el.querySelector('.menu-btn').addEventListener('click', (function(p){ return function(e){
      e.stopPropagation();
      openMenu(e.currentTarget, fileMenuActions(p, 'file'));
    }; })(filePath));
  }
  makeDraggable(el, filePath);
  attachContextMenu(el, function(){ return fileMenuActions(filePath, 'file'); });
  return el;
}

// ── Preview ───────────────────────────────────────────────────────────────────
// Notes open read-only and become editable on click, with the caret placed at
// the end of the text. The footer swaps to Save / Cancel while editing.
var noteEditing = false;

function openNotePreview(path) {
  fetch('/file?name='+encodeURIComponent(path)).then(function(r){return r.text();}).then(function(text){
    noteFullText = text;
    activeFile = path;
    noteEditing = false;
    mName.textContent = path.split('/').pop();
    renderNoteRead();
    modal.classList.add('open');
    document.body.style.overflow='hidden';
  });
}

function renderNoteRead() {
  noteEditing = false;
  mContent.innerHTML = '<pre id="note-view" title="Click to edit">'+esc(noteFullText)+'</pre>';
  document.getElementById('note-view').addEventListener('click', startNoteEdit);
  mDl.style.display = 'none';
  mCopy.style.display = '';
  mCopy.textContent = '⎘ Copy text';
  mCopy.onclick = function(){ copyText(noteFullText, mCopy, '⎘ Copy text'); };
  mSave.style.display = 'none';
  mCancel.style.display = 'none';
}

function startNoteEdit() {
  noteEditing = true;
  mContent.innerHTML = '<textarea id="note-edit" spellcheck="false"></textarea>';
  var ta = document.getElementById('note-edit');
  ta.value = noteFullText;
  mCopy.style.display = 'none';
  mDl.style.display = 'none';
  mSave.style.display = '';
  mCancel.style.display = '';
  ta.focus();
  // caret at the very end, and scrolled there
  ta.setSelectionRange(ta.value.length, ta.value.length);
  ta.scrollTop = ta.scrollHeight;
  ta.addEventListener('keydown', function(e){
    if (e.key === 'Escape') { e.stopPropagation(); cancelNoteEdit(); }
    // Ctrl/Cmd+S saves, as in any editor
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); saveNoteEdit(); }
  });
}

function cancelNoteEdit() {
  renderNoteRead();
}

function saveNoteEdit() {
  var ta = document.getElementById('note-edit');
  if (!ta) return;
  var text = ta.value;
  var path = activeFile;
  mSave.disabled = true;
  mSave.textContent = 'Saving...';
  fetch('/save-text?name='+encodeURIComponent(path), {method:'POST', body:text})
    .then(function(r){
      mSave.disabled = false;
      mSave.textContent = '✓ Save';
      if (!r.ok) { return r.text().then(function(t){ throw new Error(t.trim() || 'save failed'); }); }
      noteFullText = text;
      renderNoteRead();
      msg.className = 'ok';
      msg.textContent = '// saved ' + path.split('/').pop();
      loadFiles();
    })
    .catch(function(e){
      mSave.disabled = false;
      mSave.textContent = '✓ Save';
      msg.className = 'err';
      msg.textContent = '// save: ' + e.message;
    });
}

// Containers the browser cannot demux. With ffmpeg present these are remuxed to
// MP4 on demand (stream-copy, no re-encode) and played inline; otherwise they
// fall back to the external player on iOS or a plain download.
function openPreview(path) {
  var ext = path.includes('.') ? path.split('.').pop().toLowerCase() : '';
  var kind = previewKind(ext);
  if (externalPlayerExts.indexOf(ext) !== -1) {
    if (VIDEO_TOOLS) { playViaRemux(path); return; }
    if (isIOS()) { handOffToPlayer(path); return; }
    dlFile(path);
    return;
  }
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

// Ask the server to repackage the file, poll until it is ready, then play it.
// Conversion is a stream copy, so it runs at disk speed rather than encode speed.
var remuxPoll = null;
// hls.js plays the transcoded stream everywhere except Safari, which has native
// HLS and is handed the playlist directly.
var hlsInstance = null;

function playHLS(masterURL, videoEl) {
  if (hlsInstance) { hlsInstance.destroy(); hlsInstance = null; }
  if (typeof Hls !== 'undefined' && Hls.isSupported()) {
    hlsInstance = new Hls({maxBufferLength: 30, maxMaxBufferLength: 120, enableWorker: true});
    hlsInstance.loadSource(masterURL);
    hlsInstance.attachMedia(videoEl);
    hlsInstance.on(Hls.Events.MANIFEST_PARSED, function(){ videoEl.play(); });
  } else if (videoEl.canPlayType('application/vnd.apple.mpegurl')) {
    videoEl.src = masterURL;
    videoEl.play();
  }
}

function stopHLS() {
  if (hlsInstance) { hlsInstance.destroy(); hlsInstance = null; }
}

function playViaRemux(path) {
  var startedAt = Date.now();
  var slowShown = false;
  activeFile = path;
  mName.textContent = path.split('/').pop();
  mDl.style.display = '';
  mCopy.style.display = 'none';
  mDl.onclick = function(){ dlFile(activeFile); };
  mContent.innerHTML = '<div class="prep"><div class="prep-spin"></div>' +
    '<div class="prep-msg">Repackaging for playback...</div></div>';
  modal.classList.add('open');
  document.body.style.overflow = 'hidden';

  function fail(m) {
    if (remuxPoll) { clearInterval(remuxPoll); remuxPoll = null; }
    mContent.innerHTML = '<div class="prep"><div class="prep-msg">' + esc(m) + '</div>' +
      '<div class="prep-sub">// use Download, or open it in a video app</div></div>';
  }
  function play(d) {
    if (remuxPoll) { clearInterval(remuxPoll); remuxPoll = null; }
    if (activeFile !== path) return;   // modal moved on while we waited
    if (d.mode === 'hls' && d.url) {
      mContent.innerHTML = '<video id="hls-video" controls></video>';
      playHLS(d.url, document.getElementById('hls-video'));
      return;
    }
    mContent.innerHTML = '<video src="/stream?name=' + encodeURIComponent(path) + '" controls autoplay></video>';
  }
  function ask() {
    fetch('/remux?name=' + encodeURIComponent(path), {method:'POST'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        if (d.state === 'ready') play(d);
        else if (d.state === 'error') fail(d.message || 'cannot play this video');
        else if (!slowShown && Date.now() - startedAt > 6000) {
          // A re-encode takes minutes rather than seconds, so change the wording
          // once. Rendering the whole block keeps this idempotent — the previous
          // version appended a line on every poll.
          slowShown = true;
          mContent.innerHTML = '<div class="prep"><div class="prep-spin"></div>' +
            '<div class="prep-msg">Converting for playback...</div>' +
            '<div class="prep-sub">// this format needs re-encoding, it can take a few minutes</div></div>';
        }
      })
      .catch(function(){ fail('conversion request failed'); });
  }
  ask();
  remuxPoll = setInterval(function(){
    if (!modal.classList.contains('open')) { clearInterval(remuxPoll); remuxPoll = null; return; }
    ask();
  }, 2000);
}

function closeModal() {
  stopHLS();
  if (remuxPoll) { clearInterval(remuxPoll); remuxPoll = null; }
  modal.classList.remove('open');
  mContent.innerHTML='';
  activeFile=''; noteFullText='';
  document.body.style.overflow='';
}

function dlFile(path){ window.location.href='/file?name='+encodeURIComponent(path)+'&dl=1'; }
function dlFolder(path){ window.location.href='/download-folder?name='+encodeURIComponent(path); }

modal.addEventListener('click',function(e){ if(e.target===modal) closeModal(); });
document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeModal(); });

// ── Helpers ───────────────────────────────────────────────────────────────────
// Extensions ffmpeg can pull a still frame from. The server generates on first
// request and caches, so a broken/absent thumbnail just falls back to the label.
var thumbExts = ['mkv','mp4','webm','mov','m4v','avi','wmv','flv','ts','m2ts','mpg','mpeg'];

function thumb(name,ext,path){
  if (['jpg','jpeg','png','gif','webp','svg'].indexOf(ext)!==-1)
    return '<img src="/file?name='+encodeURIComponent(path)+'" alt="" loading="lazy">';
  if (VIDEO_TOOLS && thumbExts.indexOf(ext)!==-1)
    return '<img class="vid-thumb" src="/thumb?name='+encodeURIComponent(path)+'" alt="" loading="lazy"'+
           ' onerror="this.parentNode.classList.add(\'ft-vid\');this.remove();">';
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
  if (!iso) return '';
  var t=new Date(iso);
  // R2 has no timestamp for a folder prefix; the zero value must not render as 1/1/1
  if (isNaN(t) || t.getFullYear() < 1971) return '';
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
      renderSearchList(currentFiles, q);
    })
    .catch(function(){ list.innerHTML='<div class="empty-state">// search error</div>'; });
}


// A share visitor may only look: hide everything that writes, so the UI matches
// what the server will actually allow.
if (SHARE_MODE) {
  document.body.classList.add('share-view');
  var up = document.querySelector('.upload-section');
  if (up) up.style.display = 'none';
  var st = document.getElementById('select-trigger');
  if (st) st.style.display = 'none';
  var nf = document.getElementById('newfolder-btn');
  if (nf) nf.style.display = 'none';
  var sb = document.getElementById("share-btn");
  if (sb) sb.style.display = "none";
  var nfield = document.querySelector('.note-field');
  if (nfield) nfield.style.display = 'none';
}
loadFiles();
loadDisk();
var lastFilesJSON = '';
setInterval(function(){
  if (searchInput.value.trim() || selectMode || pendingOps) return;
  var seq = ++listSeq;
  var forPath = currentPath;
  var url = '/files' + (currentPath ? '?path=' + encodeURIComponent(currentPath) : '');
  if (showLocked) url += (url.indexOf('?') === -1 ? '?' : '&') + 'locked=1';
  fetch(url).then(function(r){ return r.json(); }).then(function(files){
    if (seq !== listSeq || forPath !== currentPath) return;   // superseded
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

// ─── Shared folders ───────────────────────────────────────────────────────────
// A share is a random token that grants read-only access to exactly one folder,
// which becomes that visitor's root. The token is the credential, so it is
// generated with crypto/rand and is the only thing standing between a stranger
// and those files — hence read-only, and hence scoped to the one folder.
//
// A normal logged-in session is unaffected: shared folders are ordinary folders
// that also happen to have a token, and they appear in the root listing as usual.

const shareCookieName = "fd_share"

type shareEntry struct {
	Path    string    `json:"path"`
	Created time.Time `json:"created"`
}

var (
	sharesMu sync.RWMutex
	shares   = map[string]shareEntry{} // token -> folder
)

func sharesPath() string { return filepath.Join(filepath.Dir(cfgPath), "shares.json") }

func loadShares() {
	data, err := os.ReadFile(sharesPath())
	if err != nil {
		return
	}
	sharesMu.Lock()
	defer sharesMu.Unlock()
	if err := json.Unmarshal(data, &shares); err != nil {
		logger.Printf("shares.json: %v", err)
		shares = map[string]shareEntry{}
	}
}

func saveShares() error {
	sharesMu.RLock()
	data, err := json.MarshalIndent(shares, "", "  ")
	sharesMu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(sharesPath(), data, 0600)
}

// shareTokenFor returns the existing token for a folder, so re-sharing the same
// folder keeps the link stable rather than invalidating the one already sent.
func shareTokenFor(rel string) string {
	key := normLock(rel)
	sharesMu.RLock()
	defer sharesMu.RUnlock()
	for tok, s := range shares {
		if normLock(s.Path) == key {
			return tok
		}
	}
	return ""
}

func shareForToken(tok string) (shareEntry, bool) {
	sharesMu.RLock()
	defer sharesMu.RUnlock()
	s, ok := shares[tok]
	return s, ok
}

// shareRoot resolves the folder a share cookie is confined to.
func (c *serverCtx) shareRoot(r *http.Request) (string, string, bool) {
	ck, err := r.Cookie(shareCookieName)
	if err != nil {
		return "", "", false
	}
	s, ok := shareForToken(ck.Value)
	if !ok {
		return "", "", false
	}
	full, ok := safeSubpath(c.rootDir, s.Path)
	if !ok {
		return "", "", false
	}
	if fi, err := os.Stat(full); err != nil || !fi.IsDir() {
		return "", "", false
	}
	return full, s.Path, true
}

// rootFor is the read-access gate. A real session sees the whole tree; a share
// visitor sees only their folder, which becomes their root.
func (c *serverCtx) rootFor(r *http.Request) (string, bool) {
	if c.isAuthed(r) {
		return c.rootDir, true
	}
	if c.r2 == nil {
		if root, _, ok := c.shareRoot(r); ok {
			return root, true
		}
	}
	return "", false
}

func (c *serverCtx) isShareVisitor(r *http.Request) bool {
	if c.isAuthed(r) {
		return false
	}
	_, _, ok := c.shareRoot(r)
	return ok
}

// handleShare mints (or returns) the token for a folder.
func (c *serverCtx) handleShare(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.r2 != nil {
		http.Error(w, "sharing is not available on this server", http.StatusNotFound)
		return
	}
	name := r.URL.Query().Get("name")
	full, ok := safeSubpath(c.rootDir, name)
	if !ok || name == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(full)
	if err != nil || !fi.IsDir() {
		http.Error(w, "only a folder can be shared", http.StatusBadRequest)
		return
	}
	tok := shareTokenFor(name)
	if tok == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			http.Error(w, "could not create link", http.StatusInternalServerError)
			return
		}
		tok = hex.EncodeToString(buf)
		sharesMu.Lock()
		shares[tok] = shareEntry{Path: name, Created: time.Now()}
		sharesMu.Unlock()
		if err := saveShares(); err != nil {
			logger.Printf("saveShares: %v", err)
		}
		logger.Printf("shared: %s -> /s/%s", name, tok)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tok,
		"url":   shareURL(r, tok),
	})
}

// shareURL builds an absolute link, since it is meant to be sent to someone else.
func shareURL(r *http.Request, tok string) string {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/s/" + tok
}

// handleShareEntry is what a share link hits: it sets the scoped cookie and
// hands the visitor the normal UI, rooted at the shared folder.
func (c *serverCtx) handleShareEntry(w http.ResponseWriter, r *http.Request) {
	tok := strings.Trim(strings.TrimPrefix(r.URL.Path, "/s/"), "/")
	if _, ok := shareForToken(tok); !ok {
		http.Error(w, "this link is no longer valid", http.StatusNotFound)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     shareCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * 24 * time.Hour).Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}


// handleShareInfo reports whether a folder is shared, for the owner's banner.
func (c *serverCtx) handleShareInfo(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := r.URL.Query().Get("name")
	tok := shareTokenFor(name)
	if tok == "" {
		http.Error(w, "not shared", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tok, "url": shareURL(r, tok)})
}
// handleUnshare revokes a link.
func (c *serverCtx) handleUnshare(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	tok := shareTokenFor(name)
	if tok == "" {
		http.Error(w, "not shared", http.StatusNotFound)
		return
	}
	sharesMu.Lock()
	delete(shares, tok)
	sharesMu.Unlock()
	if err := saveShares(); err != nil {
		logger.Printf("saveShares: %v", err)
	}
	logger.Printf("unshared: %s", name)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}
// ─── Locked files ─────────────────────────────────────────────────────────────
// A lock hides an item from the normal listing until its password is entered.
// The password is stored as a bcrypt hash in locks.json beside config.json; the
// file itself is NOT encrypted, so anyone with access to the disk or a backup
// can still read it. This is concealment in the UI, not protection at rest.
//
// An unlock is scoped to one browser session and lasts 24h, held in memory —
// restarting the service therefore re-locks everything, which is the safe
// direction to fail in.

const unlockTTL = 24 * time.Hour

type lockEntry struct {
	Hash    string    `json:"hash"`
	Created time.Time `json:"created"`
}

var (
	locksMu sync.RWMutex
	locks   = map[string]lockEntry{}

	unlockMu sync.Mutex
	unlocks  = map[string]map[string]time.Time{} // session cookie value -> path -> expiry
)

func locksPath() string { return filepath.Join(filepath.Dir(cfgPath), "locks.json") }

func loadLocks() {
	data, err := os.ReadFile(locksPath())
	if err != nil {
		return
	}
	locksMu.Lock()
	defer locksMu.Unlock()
	if err := json.Unmarshal(data, &locks); err != nil {
		logger.Printf("locks.json: %v", err)
		locks = map[string]lockEntry{}
	}
}

func saveLocks() error {
	locksMu.RLock()
	data, err := json.MarshalIndent(locks, "", "  ")
	locksMu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(locksPath(), data, 0600)
}

// normLock puts a path into the single form used as a lock key.
func normLock(p string) string {
	return strings.Trim(strings.ToLower(filepath.ToSlash(strings.TrimSpace(p))), "/")
}

// lockedAncestor returns the locked path guarding rel — rel itself, or the
// nearest locked folder above it. Without the ancestor walk, a locked folder
// could be stepped into simply by asking for a path inside it.
func lockedAncestor(rel string) string {
	key := normLock(rel)
	if key == "" {
		return ""
	}
	locksMu.RLock()
	defer locksMu.RUnlock()
	for {
		if _, ok := locks[key]; ok {
			return key
		}
		i := strings.LastIndex(key, "/")
		if i < 0 {
			return ""
		}
		key = key[:i]
	}
}

func sessionKey(c *serverCtx, r *http.Request) string {
	ck, err := r.Cookie(c.cookie)
	if err != nil {
		return ""
	}
	return ck.Value
}

func isUnlocked(sess, lockKey string) bool {
	if sess == "" || lockKey == "" {
		return false
	}
	unlockMu.Lock()
	defer unlockMu.Unlock()
	m := unlocks[sess]
	if m == nil {
		return false
	}
	exp, ok := m[lockKey]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(m, lockKey)
		return false
	}
	return true
}

func grantUnlock(sess, lockKey string) {
	unlockMu.Lock()
	defer unlockMu.Unlock()
	if unlocks[sess] == nil {
		unlocks[sess] = map[string]time.Time{}
	}
	unlocks[sess][lockKey] = time.Now().Add(unlockTTL)
}

// blockedByLock reports whether this request may not touch rel. Every content
// and mutation handler consults it, otherwise hiding the row would be cosmetic
// and the file would still be fetchable by URL.
func (c *serverCtx) blockedByLock(r *http.Request, rel string) bool {
	if c.r2 != nil {
		return false // locking is a private-server feature
	}
	// A share visitor addresses paths relative to their own folder, so map back
	// to the real tree before checking locks — otherwise a locked file inside a
	// shared folder would not match any lock key and would leak.
	if _, sharePath, ok := c.shareRoot(r); ok && !c.isAuthed(r) {
		rel = strings.Trim(sharePath, "/") + "/" + strings.Trim(rel, "/")
	}
	key := lockedAncestor(rel)
	if key == "" {
		return false
	}
	return !isUnlocked(sessionKey(c, r), key)
}

func readPassword(r *http.Request) string {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	return strings.TrimSpace(string(body))
}

func (c *serverCtx) lockPrecheck(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	if c.r2 != nil {
		http.Error(w, "locking is not available on this server", http.StatusNotFound)
		return "", false
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return "", false
	}
	if _, ok := safeSubpath(c.rootDir, name); !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return "", false
	}
	return name, true
}

func (c *serverCtx) handleLock(w http.ResponseWriter, r *http.Request) {
	name, ok := c.lockPrecheck(w, r)
	if !ok {
		return
	}
	key := normLock(name)
	locksMu.RLock()
	_, exists := locks[key]
	locksMu.RUnlock()
	if exists {
		http.Error(w, "this item is already locked", http.StatusConflict)
		return
	}
	pw := readPassword(r)
	if len(pw) < 4 {
		http.Error(w, "password must be at least 4 characters", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "could not lock", http.StatusInternalServerError)
		return
	}
	locksMu.Lock()
	locks[key] = lockEntry{Hash: string(hash), Created: time.Now()}
	locksMu.Unlock()
	if err := saveLocks(); err != nil {
		logger.Printf("saveLocks: %v", err)
	}
	// the person who just set it should not have to immediately type it back
	grantUnlock(sessionKey(c, r), key)
	logger.Printf("locked: %s", key)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// verifyLock checks the supplied password against the stored hash.
func verifyLock(key, pw string) bool {
	locksMu.RLock()
	e, ok := locks[key]
	locksMu.RUnlock()
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(e.Hash), []byte(pw)) == nil
}

func (c *serverCtx) handleUnlock(w http.ResponseWriter, r *http.Request) {
	name, ok := c.lockPrecheck(w, r)
	if !ok {
		return
	}
	key := normLock(name)
	ip := realIP(r)
	if c.isRateLimited(ip) {
		http.Error(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	if !verifyLock(key, readPassword(r)) {
		c.recordLoginFailure(ip)
		http.Error(w, "incorrect password", http.StatusUnauthorized)
		return
	}
	c.resetLoginRate(ip)
	grantUnlock(sessionKey(c, r), key)
	logger.Printf("unlocked for session: %s", key)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"hours": int(unlockTTL.Hours())})
}

// handleRemoveLock is the permanent unlock: the entry is deleted and the item
// goes back to being an ordinary file.
func (c *serverCtx) handleRemoveLock(w http.ResponseWriter, r *http.Request) {
	name, ok := c.lockPrecheck(w, r)
	if !ok {
		return
	}
	key := normLock(name)
	ip := realIP(r)
	if c.isRateLimited(ip) {
		http.Error(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	if !verifyLock(key, readPassword(r)) {
		c.recordLoginFailure(ip)
		http.Error(w, "incorrect password", http.StatusUnauthorized)
		return
	}
	c.resetLoginRate(ip)
	locksMu.Lock()
	delete(locks, key)
	locksMu.Unlock()
	if err := saveLocks(); err != nil {
		logger.Printf("saveLocks: %v", err)
	}
	logger.Printf("lock removed: %s", key)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// relockOnRename keeps a lock attached to its item when it is moved or renamed.
func relockOnRename(oldRel, newRel string) {
	oldKey, newKey := normLock(oldRel), normLock(newRel)
	locksMu.Lock()
	defer locksMu.Unlock()
	if e, ok := locks[oldKey]; ok {
		delete(locks, oldKey)
		locks[newKey] = e
		go saveLocks()
	}
}

// dropLock forgets a lock whose item no longer exists.
func dropLock(rel string) {
	key := normLock(rel)
	locksMu.Lock()
	_, ok := locks[key]
	if ok {
		delete(locks, key)
	}
	locksMu.Unlock()
	if ok {
		go saveLocks()
	}
}
// ─── Media tools (ffmpeg) ─────────────────────────────────────────────────────
// A browser cannot demux Matroska, but an .mkv holding H.264 video is already
// playable — only the container is wrong. So the fix is to remux (stream-copy)
// into a faststart MP4 rather than re-encode: fast, and lossless. Sources in a
// codec the browser cannot decode at all (HEVC, AV1) would need a real
// transcode, far too slow for a file-drop box, so those are reported back and
// left to the download / external-player path.

var (
	ffmpegPath  string
	ffprobePath string
	videoTools  bool
)

// resolveMediaTools finds ffmpeg/ffprobe once at startup. The service runs as
// LocalSystem, whose PATH does not include a per-user WinGet install, so an
// explicit config path is honoured first and common install roots are swept
// before giving up.
func resolveMediaTools() {
	find := func(configured, name string) string {
		if configured != "" {
			if _, err := os.Stat(configured); err == nil {
				return configured
			}
			logger.Printf("media: configured %s not found at %s", name, configured)
		}
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
		home, _ := os.UserHomeDir()
		roots := []string{
			filepath.Join(home, "AppData", "Local", "Microsoft", "WinGet", "Packages"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "WinGet", "Links"),
			filepath.Join("C:", "ffmpeg", "bin"),
			filepath.Join("C:", "Program Files", "ffmpeg", "bin"),
		}
		for _, root := range roots {
			var hit string
			filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
				if err != nil || hit != "" {
					return nil
				}
				if !fi.IsDir() && strings.EqualFold(fi.Name(), name+".exe") {
					hit = p
				}
				return nil
			})
			if hit != "" {
				return hit
			}
		}
		return ""
	}
	ffmpegPath = find(cfg.FFmpegPath, "ffmpeg")
	ffprobePath = find(cfg.FFprobePath, "ffprobe")
	videoTools = ffmpegPath != "" && ffprobePath != ""
	if videoTools {
		logger.Printf("media tools: ffmpeg=%s", ffmpegPath)
	} else {
		logger.Printf("media tools: unavailable — thumbnails and mkv playback disabled")
	}
}

func mediaCacheDir(kind string) string {
	dir := filepath.Join(filepath.Dir(cfgPath), "media_cache", kind)
	os.MkdirAll(dir, 0755)
	return dir
}

// removeMediaCache drops the thumbnail, remux, and HLS output tied to this
// exact file revision, so deleting the source doesn't leave orphaned cache
// data behind until the next weekly prune.
func removeMediaCache(path string, fi os.FileInfo) {
	key := cacheKey(path, fi)
	os.Remove(filepath.Join(mediaCacheDir("thumbs"), key+".jpg"))
	os.Remove(filepath.Join(mediaCacheDir("remux"), key+".mp4"))
	os.RemoveAll(filepath.Join(mediaCacheDir("hls"), key))
}

// cacheKey ties an entry to this exact file revision, so replacing a file with
// a different one of the same name cannot serve a stale thumbnail or video.
func cacheKey(path string, fi os.FileInfo) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", strings.ToLower(path), fi.ModTime().UnixNano(), fi.Size())))
	return hex.EncodeToString(h[:])
}

type videoMeta struct {
	VideoCodec string
	AudioCodec string
	Height     int
	Duration   int
}

func probeVideo(path string) (videoMeta, error) {
	var m videoMeta
	out, err := exec.Command(ffprobePath, "-v", "error", "-print_format", "json",
		"-show_streams", "-show_format", path).Output()
	if err != nil {
		return m, err
	}
	var res struct {
		Streams []struct {
			CodecType string `json:"codec_type"`
			CodecName string `json:"codec_name"`
			Height    int    `json:"height"`
		} `json:"streams"`
		Format struct {
			Duration string `json:"duration"`
		} `json:"format"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return m, err
	}
	for _, s := range res.Streams {
		if s.CodecType == "video" && m.VideoCodec == "" {
			m.VideoCodec = s.CodecName
			m.Height = s.Height
		}
		if s.CodecType == "audio" && m.AudioCodec == "" {
			m.AudioCodec = s.CodecName
		}
	}
	if f, err := strconv.ParseFloat(res.Format.Duration, 64); err == nil {
		m.Duration = int(f)
	}
	return m, nil
}

// browserVideoCodecs are decodable by every current browser once inside MP4, so
// they can be stream-copied. HEVC and AV1 are deliberately absent.
var browserVideoCodecs = map[string]bool{"h264": true}

func extractThumbnail(inPath, outPath string, durationSec int) error {
	seek := "00:00:05"
	if durationSec > 0 && durationSec < 10 {
		seek = "00:00:00"
	}
	return exec.Command(ffmpegPath, "-y", "-ss", seek, "-i", inPath,
		"-frames:v", "1", "-q:v", "4", "-vf", "scale=200:-1", outPath).Run()
}

func (c *serverCtx) handleThumb(w http.ResponseWriter, r *http.Request) {
	root, allowed := c.rootFor(r)
	if !allowed {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !videoTools || c.r2 != nil {
		http.Error(w, "not available", http.StatusNotFound)
		return
	}
	src, ok := safeSubpath(root, r.URL.Query().Get("name"))
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, r.URL.Query().Get("name")) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(src)
	if err != nil || fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	out := filepath.Join(mediaCacheDir("thumbs"), cacheKey(src, fi)+".jpg")
	if _, err := os.Stat(out); err != nil {
		meta, _ := probeVideo(src)
		if err := extractThumbnail(src, out, meta.Duration); err != nil {
			http.Error(w, "no thumbnail", http.StatusNotFound)
			return
		}
	}
	w.Header().Set("Cache-Control", "private, max-age=86400")
	http.ServeFile(w, r, out)
}

// ─── HLS transcode ────────────────────────────────────────────────────────────
// H.264 sources only need the container swapping (see the remux path above).
// HEVC and AV1 cannot be decoded by browsers at all, so they need a real
// re-encode. This mirrors what stream-videos does: encode to H.264 and serve it
// as HLS, played back with hls.js. It is genuinely slow — minutes, not seconds —
// so it happens on demand rather than on upload, and the UI polls for it.

// nvencAvailable is probed once at startup. The encoder being listed does not
// mean the GPU is actually reachable (notably under a service session), so this
// runs a throwaway encode to find out.
var nvencAvailable bool

func probeNvenc() bool {
	if ffmpegPath == "" {
		return false
	}
	cmd := exec.Command(ffmpegPath, "-hide_banner", "-nostdin",
		"-f", "lavfi", "-i", "testsrc=duration=1:size=256x256:rate=5",
		"-c:v", "h264_nvenc", "-f", "null", "-")
	return cmd.Run() == nil
}

type rendition struct {
	name    string
	height  int
	crf     string
	audioBR string
}

var allRenditions = []rendition{
	{"1080p", 1080, "23", "192k"},
	{"720p", 720, "25", "128k"},
	{"480p", 480, "27", "96k"},
	{"360p", 360, "28", "64k"},
}

// pickRendition returns the single rendition to encode. stream-videos ladders
// up to three for adaptive bitrate; here one viewer pulls one stream on demand,
// so a second and third encode would multiply the wait for no benefit.
func pickRendition(srcHeight int) rendition {
	for _, r := range allRenditions {
		if srcHeight >= r.height {
			return r
		}
	}
	return allRenditions[len(allRenditions)-1]
}

func buildHLSCommand(inPath, hlsDir string, r rendition, useNvenc bool) *exec.Cmd {
	args := []string{"-y", "-nostdin"}
	if useNvenc {
		// the GPU decodes HEVC/AV1 too, which roughly doubles throughput on 4K
		args = append(args, "-hwaccel", "cuda")
	}
	args = append(args, "-i", inPath)
	// Map one explicit video and audio stream: multi-language releases can
	// otherwise match several streams at once and blow up resource usage.
	args = append(args, "-map", "0:v:0", "-vf", fmt.Sprintf("scale=-2:%d,format=yuv420p", r.height))
	if useNvenc {
		args = append(args, "-c:v", "h264_nvenc", "-preset", "p5",
			"-rc", "vbr", "-cq", r.crf, "-b:v", "0",
			"-g", "60", "-keyint_min", "60")
	} else {
		args = append(args, "-c:v", "libx264", "-preset", "veryfast", "-crf", r.crf,
			"-g", "60", "-keyint_min", "60", "-sc_threshold", "0")
	}
	args = append(args,
		"-map", "0:a:0?",
		"-c:a", "aac", "-b:a", r.audioBR, "-ac", "2",
		"-f", "hls", "-hls_time", "10", "-hls_playlist_type", "vod",
		"-hls_flags", "independent_segments", "-hls_segment_type", "mpegts",
		"-hls_segment_filename", filepath.Join(hlsDir, r.name+"_seg%03d.ts"),
		"-master_pl_name", "master.m3u8",
		"-var_stream_map", "v:0,a:0,name:"+r.name,
		filepath.Join(hlsDir, "%v.m3u8"),
	)
	return exec.Command(ffmpegPath, args...)
}

// handleHLS serves the generated playlist and segments. The URL carries the
// cache key rather than a path, so it exposes no filesystem layout, and the
// key is only ever handed out by /remux to an authenticated caller.
func (c *serverCtx) handleHLS(w http.ResponseWriter, r *http.Request) {
	_, allowed := c.rootFor(r)
	if !allowed {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/hls/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	key, file := parts[0], parts[1]
	// key is our own hex digest and file is a generated name: reject anything
	// that is not one of those shapes rather than trusting the URL.
	if !isHexKey(key) || strings.ContainsAny(file, `/\:`) || strings.Contains(file, "..") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	full := filepath.Join(mediaCacheDir("hls"), key, file)
	if strings.HasSuffix(file, ".m3u8") {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	} else if strings.HasSuffix(file, ".ts") {
		w.Header().Set("Content-Type", "video/mp2t")
	}
	http.ServeFile(w, r, full)
}

func isHexKey(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, ch := range s {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}
// ─── Remux to MP4 ─────────────────────────────────────────────────────────────

type remuxJob struct {
	state string // "running" | "ready" | "error"
	msg   string
	mode  string // "mp4" (remuxed) | "hls" (re-encoded)
	when  time.Time
}

var (
	remuxMu   sync.Mutex
	remuxJobs = map[string]*remuxJob{}
)

func setRemux(key, state, msg string) {
	remuxMu.Lock()
	defer remuxMu.Unlock()
	if j, ok := remuxJobs[key]; ok {
		j.state, j.msg, j.when = state, msg, time.Now()
	}
}

func setRemuxMode(key, state, msg, mode string) {
	remuxMu.Lock()
	defer remuxMu.Unlock()
	if j, ok := remuxJobs[key]; ok {
		j.state, j.msg, j.mode, j.when = state, msg, mode, time.Now()
	}
}

func (c *serverCtx) handleRemux(w http.ResponseWriter, r *http.Request) {
	root, allowed := c.rootFor(r)
	if !allowed {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	reply := func(state, msg string) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"state": state, "message": msg})
	}
	// reply2 also tells the client how to play it: a remuxed MP4 goes straight
	// into the video element, an HLS transcode needs hls.js and a playlist URL.
	reply2 := func(state, msg, mode, key string) {
		out := map[string]string{"state": state, "message": msg, "mode": mode}
		if mode == "hls" {
			out["url"] = "/hls/" + key + "/master.m3u8"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	}
	if !videoTools || c.r2 != nil {
		reply("error", "video conversion is not available on this server")
		return
	}
	name := r.URL.Query().Get("name")
	src, ok := safeSubpath(root, name)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, name) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(src)
	if err != nil || fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	key := cacheKey(src, fi)
	out := filepath.Join(mediaCacheDir("remux"), key+".mp4")

	remuxMu.Lock()
	// already converted, either way round
	if _, err := os.Stat(out); err == nil {
		remuxJobs[key] = &remuxJob{state: "ready", mode: "mp4"}
		remuxMu.Unlock()
		reply2("ready", "", "mp4", key)
		return
	}
	if _, err := os.Stat(filepath.Join(mediaCacheDir("hls"), key, "master.m3u8")); err == nil {
		remuxJobs[key] = &remuxJob{state: "ready", mode: "hls"}
		remuxMu.Unlock()
		reply2("ready", "", "hls", key)
		return
	}
	// A failed job stays failed for a short while, otherwise every poll would
	// silently start a fresh attempt and the client would never see the error.
	if j, ok := remuxJobs[key]; ok && (j.state != "error" || time.Since(j.when) < 30*time.Second) {
		state, m, mode := j.state, j.msg, j.mode
		remuxMu.Unlock()
		reply2(state, m, mode, key)
		return
	}
	remuxJobs[key] = &remuxJob{state: "running", when: time.Now()}
	remuxMu.Unlock()

	go func() {
		meta, err := probeVideo(src)
		if err != nil {
			setRemux(key, "error", "could not read this video")
			return
		}

		// H.264: the container is the only problem, so stream-copy it into MP4.
		if browserVideoCodecs[meta.VideoCodec] {
			aCodec := "copy"
			if meta.AudioCodec != "aac" {
				aCodec = "aac"
			}
			args := []string{"-y", "-nostdin", "-i", src, "-map", "0:v:0", "-map", "0:a:0?",
				"-c:v", "copy", "-c:a", aCodec}
			if aCodec == "aac" {
				args = append(args, "-b:a", "192k", "-ac", "2")
			}
			// write under a temp name so a half-finished file is never served
			tmp := out + ".part"
			// -f mp4 is required because the temp name ends in .part, from which
			// ffmpeg could not otherwise infer the container.
			args = append(args, "-movflags", "+faststart", "-f", "mp4", tmp)
			if err := exec.Command(ffmpegPath, args...).Run(); err != nil {
				os.Remove(tmp)
				setRemux(key, "error", "conversion failed")
				logger.Printf("remux %s: %v", src, err)
				return
			}
			if err := os.Rename(tmp, out); err != nil {
				os.Remove(tmp)
				setRemux(key, "error", "conversion failed")
				return
			}
			setRemuxMode(key, "ready", "", "mp4")
			logger.Printf("remuxed for playback: %s", src)
			return
		}

		// Anything else (HEVC, AV1, VC-1 …) has to be re-encoded to H.264 and
		// served as HLS. Encode into a temp directory and swap it in, so a
		// partially written playlist is never served.
		r := pickRendition(meta.Height)
		finalDir := filepath.Join(mediaCacheDir("hls"), key)
		tmpDir := finalDir + ".part"
		os.RemoveAll(tmpDir)
		if err := os.MkdirAll(tmpDir, 0755); err != nil {
			setRemux(key, "error", "conversion failed")
			return
		}
		logger.Printf("hls transcode start: %s [%s %dp -> %s, nvenc=%v]",
			src, meta.VideoCodec, meta.Height, r.name, nvencAvailable)
		cmd := buildHLSCommand(src, tmpDir, r, nvencAvailable)
		if err := cmd.Run(); err != nil {
			// The GPU path can fail on a machine where the encoder loads but the
			// session cannot reach the card; fall back to the CPU once.
			if nvencAvailable {
				logger.Printf("hls nvenc failed for %s (%v) — retrying on CPU", src, err)
				os.RemoveAll(tmpDir)
				os.MkdirAll(tmpDir, 0755)
				err = buildHLSCommand(src, tmpDir, r, false).Run()
			}
			if err != nil {
				os.RemoveAll(tmpDir)
				setRemux(key, "error", "could not convert this video")
				logger.Printf("hls transcode %s: %v", src, err)
				return
			}
		}
		os.RemoveAll(finalDir)
		if err := os.Rename(tmpDir, finalDir); err != nil {
			os.RemoveAll(tmpDir)
			setRemux(key, "error", "conversion failed")
			return
		}
		setRemuxMode(key, "ready", "", "hls")
		logger.Printf("hls transcode done: %s", src)
	}()
	reply2("running", "", "", key)
}

// handleStream serves the remuxed MP4. ServeContent provides range support,
// which the video element needs in order to seek.
func (c *serverCtx) handleStream(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	root, allowed := c.rootFor(r)
	if !allowed && !c.validFileToken(name, r.URL.Query().Get("tok")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if root == "" {
		root = c.rootDir
	}
	if c.blockedByLock(r, name) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	src, ok := safeSubpath(root, name)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(src)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(filepath.Join(mediaCacheDir("remux"), cacheKey(src, fi)+".mp4"))
	if err != nil {
		http.Error(w, "not converted yet", http.StatusNotFound)
		return
	}
	defer f.Close()
	ofi, err := f.Stat()
	if err != nil {
		http.Error(w, "stat error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "video/mp4")
	http.ServeContent(w, r, filepath.Base(src)+".mp4", ofi.ModTime(), f)
}

// pruneMediaCache drops entries untouched for a week. A remuxed file is roughly
// the size of its source, so the cache cannot be left to grow forever.
func pruneMediaCache() {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, kind := range []string{"thumbs", "remux"} {
		dir := mediaCacheDir(kind)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			fi, err := e.Info()
			if err == nil && fi.ModTime().Before(cutoff) {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
}

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

func (c *serverCtx) handleLogin(w http.ResponseWriter, r *http.Request) {
	if c.loginDisabled.Load() {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		loginTmpl.Execute(w, map[string]interface{}{"Error": false, "Locked": false, "Label": c.loginLabel})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := realIP(r)
	if c.isRateLimited(ip) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		loginTmpl.Execute(w, map[string]interface{}{"Error": true, "Locked": true, "Label": c.loginLabel})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pw := r.FormValue("password")
	if bcrypt.CompareHashAndPassword([]byte(c.passHash), []byte(pw)) != nil {
		c.recordLoginFailure(ip)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		loginTmpl.Execute(w, map[string]interface{}{"Error": true, "Locked": false, "Label": c.loginLabel})
		return
	}
	c.resetLoginRate(ip)
	c.setSessionCookie(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (c *serverCtx) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	shareName, shareLink := "", ""
	if !c.isAuthed(r) {
		// A share visitor gets the same UI, rooted at their folder and stripped
		// of everything they are not allowed to do.
		if _, sharePath, ok := c.shareRoot(r); ok {
			shareName = path.Base(strings.Trim(filepath.ToSlash(sharePath), "/"))
			if tok := shareTokenFor(sharePath); tok != "" {
				shareLink = shareURL(r, tok)
			}
		} else {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	uploadTmpl.Execute(w, map[string]interface{}{
		"UploadDir":   c.rootDir,
		"Port":        c.port,
		"FooterLabel": c.footerLabel,
		"R2Mode":      c.r2 != nil,
		"CanPublish":  c.publishR2 != nil && shareName == "",
		"VideoTools":  videoTools && c.r2 == nil,
		"ShareMode":   shareName != "",
		"ShareName":   shareName,
		"ShareLink":   shareLink,
	})
}

func (c *serverCtx) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
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
	// R2-backed server: stream directly to R2, never touch local disk
	if c.r2 != nil {
		prefix := r.URL.Query().Get("path")
		if prefix != "" {
			prefix = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(prefix)), "/") + "/"
		}
		for _, fh := range fhs {
			src, err := fh.Open()
			if err != nil {
				http.Error(w, "cannot open upload", http.StatusInternalServerError)
				return
			}
			r2Key := prefix + filepath.Base(fh.Filename)
			_, err = c.r2.PutObject(context.Background(), &s3.PutObjectInput{
				Bucket:        awsv2.String(c.r2Bucket),
				Key:           awsv2.String(r2Key),
				Body:          src,
				ContentLength: awsv2.Int64(fh.Size),
			})
			src.Close()
			if err != nil {
				logger.Printf("R2 upload %s: %v", r2Key, err)
				http.Error(w, "upload failed", http.StatusInternalServerError)
				return
			}
			logger.Printf("R2 upload OK: %s", r2Key)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}
	for _, fh := range fhs {
		src, err := fh.Open()
		if err != nil {
			http.Error(w, "cannot open upload", http.StatusInternalServerError)
			logger.Printf("ERROR open multipart file: %v", err)
			return
		}
		uploadDir, ok := safeSubpath(c.rootDir, r.URL.Query().Get("path"))
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
		tmpPath := destPath + ".fdtmp"
		dst, err := os.Create(tmpPath)
		if err != nil {
			src.Close()
			http.Error(w, "cannot create file", http.StatusInternalServerError)
			logger.Printf("ERROR create %s: %v", tmpPath, err)
			return
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			dst.Close()
			os.Remove(tmpPath)
			http.Error(w, "write error", http.StatusInternalServerError)
			logger.Printf("ERROR write %s: %v", tmpPath, err)
			return
		}
		dst.Close()
		src.Close()
		if err := os.Rename(tmpPath, destPath); err != nil {
			os.Remove(tmpPath)
			http.Error(w, "cannot finalise file", http.StatusInternalServerError)
			logger.Printf("ERROR rename %s: %v", tmpPath, err)
			return
		}
		logger.Printf("upload OK: %s", destPath)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func (c *serverCtx) handlePresign(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if c.r2 == nil {
		http.Error(w, "not available", http.StatusNotFound)
		return
	}
	name := filepath.Base(r.URL.Query().Get("name"))
	if name == "" || name == "." {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	prefix := r.URL.Query().Get("path")
	if prefix != "" {
		prefix = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(prefix)), "/") + "/"
	}
	r2Key := prefix + name
	pc := s3.NewPresignClient(c.r2)
	result, err := pc.PresignPutObject(context.Background(), &s3.PutObjectInput{
		Bucket:      awsv2.String(c.r2Bucket),
		Key:         awsv2.String(r2Key),
		ContentType: awsv2.String("application/octet-stream"),
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		logger.Printf("presign error: %v", err)
		http.Error(w, "presign failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": result.URL})
}

type fileEntry struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	Modified     time.Time `json:"modified"`
	IsNote       bool      `json:"is_note"`
	IsDir        bool      `json:"is_dir"`
	Snippet      string    `json:"snippet,omitempty"`
	MatchContent bool      `json:"match_content,omitempty"`
	Locked       bool      `json:"locked,omitempty"`
	Unlocked     bool      `json:"unlocked,omitempty"`
	Truncated    bool      `json:"truncated,omitempty"`
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

// applyLocks decides what a listing is allowed to show.
//
//   - not locked                 -> shown as normal
//   - locked, not unlocked       -> omitted, unless ?locked=1 (the "All + ·"
//     view), where it appears as an inert, greyed placeholder
//   - locked, unlocked this session -> shown everywhere, still flagged so the UI
//     can grey it and sort it first
//
// Locked entries are hoisted to the front in either case.
func applyLocks(c *serverCtx, r *http.Request, in []fileEntry) []fileEntry {
	if c.r2 != nil {
		return in // locking is a private-server feature
	}
	locksMu.RLock()
	any := len(locks)
	locksMu.RUnlock()
	if any == 0 {
		return in
	}
	showLocked := r.URL.Query().Get("locked") == "1"
	sess := sessionKey(c, r)
	base := strings.Trim(filepath.ToSlash(r.URL.Query().Get("path")), "/")
	if _, sharePath, ok := c.shareRoot(r); ok && !c.isAuthed(r) {
		base = strings.Trim(strings.Trim(sharePath, "/")+"/"+base, "/")
	}

	var locked, plain []fileEntry
	for _, e := range in {
		rel := e.Name
		if base != "" {
			rel = base + "/" + e.Name
		}
		key := lockedAncestor(rel)
		if key == "" {
			plain = append(plain, e)
			continue
		}
		e.Locked = true
		e.Unlocked = isUnlocked(sess, key)
		if e.Unlocked {
			locked = append(locked, e)
			continue
		}
		if showLocked {
			// A placeholder only: size and preview details are withheld so the
			// listing itself leaks nothing about a still-locked item.
			locked = append(locked, fileEntry{
				Name:   e.Name,
				IsDir:  e.IsDir,
				Locked: true,
			})
		}
	}
	return append(locked, plain...)
}
func (c *serverCtx) handleFiles(w http.ResponseWriter, r *http.Request) {
	root, allowed := c.rootFor(r)
	if !allowed {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if c.r2 != nil {
		prefix := r.URL.Query().Get("path")
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		out, err := c.r2.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
			Bucket:    awsv2.String(c.r2Bucket),
			Prefix:    awsv2.String(prefix),
			Delimiter: awsv2.String("/"),
		})
		if err != nil {
			http.Error(w, "cannot list files", http.StatusInternalServerError)
			logger.Printf("R2 list: %v", err)
			return
		}
		var result []fileEntry
		for _, cp := range out.CommonPrefixes {
			name := strings.TrimSuffix(strings.TrimPrefix(awsv2.ToString(cp.Prefix), prefix), "/")
			result = append(result, fileEntry{Name: name, IsDir: true})
		}
		for _, obj := range out.Contents {
			fullKey := awsv2.ToString(obj.Key)
			key := strings.TrimPrefix(fullKey, prefix)
			if key == "" {
				continue
			}
			entry := fileEntry{
				Name:     key,
				Size:     awsv2.ToInt64(obj.Size),
				Modified: awsv2.ToTime(obj.LastModified),
			}
			if strings.HasPrefix(key, "note_") && strings.HasSuffix(key, ".txt") {
				entry.IsNote = true
				if nr, err := c.r2.GetObject(context.Background(), &s3.GetObjectInput{
					Bucket: awsv2.String(c.r2Bucket),
					Key:    awsv2.String(fullKey),
					Range:  awsv2.String("bytes=0-159"),
				}); err == nil {
					raw, _ := io.ReadAll(nr.Body)
					nr.Body.Close()
					s := string(raw)
					if awsv2.ToInt64(obj.Size) > 160 {
						s += "..."
					}
					entry.Snippet = s
				}
			}
			result = append(result, entry)
		}
		// R2 gives no timestamp for a prefix, so a folder's Modified is the zero
		// value. Sorting everything by date therefore sank folders to the bottom
		// and rendered them as 1/1/1. Order them the way the local listing does:
		// folders first by name, then files newest-first.
		var r2dirs, r2files []fileEntry
		for _, e := range result {
			if e.IsDir {
				r2dirs = append(r2dirs, e)
			} else {
				r2files = append(r2files, e)
			}
		}
		sort.Slice(r2dirs, func(i, j int) bool { return r2dirs[i].Name < r2dirs[j].Name })
		sort.Slice(r2files, func(i, j int) bool { return r2files[i].Modified.After(r2files[j].Modified) })
		result = append(r2dirs, r2files...)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}
	dirPath, ok := safeSubpath(root, r.URL.Query().Get("path"))
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
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
		if strings.HasSuffix(e.Name(), ".fdtmp") {
			continue
		}
		entry := fileEntry{Name: e.Name(), Size: fi.Size(), Modified: fi.ModTime()}
		if strings.HasPrefix(e.Name(), "note_") && strings.HasSuffix(e.Name(), ".txt") {
			entry.IsNote = true
			if raw, err := os.ReadFile(filepath.Join(dirPath, e.Name())); err == nil {
				// Send enough for the row to be edited in place. Notes are short in
				// practice, so this is usually the whole thing; Truncated tells the
				// client when it must fetch the rest before editing.
				s := string(raw)
				if len(s) > noteInlineMax {
					s = s[:noteInlineMax]
					entry.Truncated = true
				}
				entry.Snippet = s
			}
		}
		files = append(files, entry)
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	sort.Slice(files, func(i, j int) bool { return files[i].Modified.After(files[j].Modified) })
	result := applyLocks(c, r, append(dirs, files...))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logger.Printf("ERROR encoding file list: %v", err)
	}
}

func (c *serverCtx) handleFile(w http.ResponseWriter, r *http.Request) {
	rawName := r.URL.Query().Get("name")
	if rawName == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// A vlc:// handoff gives this URL to a separate app that holds no session
	// cookie, so a token scoped to this exact file stands in for one.
	root, allowed := c.rootFor(r)
	if !allowed && !c.validFileToken(rawName, r.URL.Query().Get("tok")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if root == "" {
		root = c.rootDir
	}
	if c.blockedByLock(r, rawName) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	if c.r2 != nil {
		// Notes must be proxied — JS fetch() is blocked by CORS on cross-origin redirects
		if strings.HasPrefix(filepath.Base(rawName), "note_") && strings.HasSuffix(rawName, ".txt") {
			out, err := c.r2.GetObject(context.Background(), &s3.GetObjectInput{
				Bucket: awsv2.String(c.r2Bucket),
				Key:    awsv2.String(rawName),
			})
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			defer out.Body.Close()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.Copy(w, out.Body)
			return
		}
		// All other files: redirect to R2 CDN
		url := strings.TrimRight(c.r2PubURL, "/") + "/" + rawName
		http.Redirect(w, r, url, http.StatusFound)
		return
	}
	fpath, ok := safeSubpath(root, rawName)
	if !ok {
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
	var rs io.ReadSeeker = f
	if c.downloadRate > 0 {
		rs = newThrottledReader(f, c.downloadRate)
	}
	// ServeContent only sniffs when the type is not already set.
	if ct, ok := videoContentTypes[strings.ToLower(filepath.Ext(name))]; ok {
		w.Header().Set("Content-Type", ct)
	}
	http.ServeContent(w, r, name, fi.ModTime(), rs)
}

func (c *serverCtx) handleDownloadFolder(w http.ResponseWriter, r *http.Request) {
	root, allowed := c.rootFor(r)
	if !allowed {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if c.r2 != nil {
		http.Error(w, "not available", http.StatusNotFound)
		return
	}
	rawName := r.URL.Query().Get("name")
	dirPath, ok := safeSubpath(root, rawName)
	if !ok || rawName == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, rawName) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(dirPath)
	if err != nil || !fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	zipName := filepath.Base(dirPath) + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, zipName))

	var dst io.Writer = w
	var throttle *throttledReader
	if c.downloadRate > 0 {
		throttle = newThrottledReader(nil, c.downloadRate)
	}

	zw := zip.NewWriter(dst)
	defer zw.Close()

	err = filepath.Walk(dirPath, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dirPath, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".fdtmp") {
			return nil
		}
		zipRel := filepath.ToSlash(rel)
		if info.IsDir() {
			_, err := zw.Create(zipRel + "/")
			return err
		}
		fh, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		fh.Name = zipRel
		fh.Method = zip.Deflate
		zEntry, err := zw.CreateHeader(fh)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		var src io.Reader = f
		if throttle != nil {
			throttle.r = f
			throttle.start = time.Now()
			throttle.totalRead = -throttle.rate
			src = throttle
		}
		_, err = io.Copy(zEntry, src)
		return err
	})
	if err != nil {
		logger.Printf("ERROR zip %s: %v", dirPath, err)
	}
}

func (c *serverCtx) handleNote(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
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
	if c.r2 != nil {
		_, err = c.r2.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket:        awsv2.String(c.r2Bucket),
			Key:           awsv2.String(name),
			Body:          strings.NewReader(string(body)),
			ContentLength: awsv2.Int64(int64(len(body))),
			ContentType:   awsv2.String("text/plain; charset=utf-8"),
		})
		if err != nil {
			http.Error(w, "write error", http.StatusInternalServerError)
			logger.Printf("R2 note %s: %v", name, err)
			return
		}
		logger.Printf("R2 note saved: %s", name)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}
	dest := filepath.Join(c.rootDir, name)
	if err := os.WriteFile(dest, body, 0644); err != nil {
		http.Error(w, "write error", http.StatusInternalServerError)
		logger.Printf("ERROR write note %s: %v", dest, err)
		return
	}
	logger.Printf("note saved: %s", dest)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// r2Prefix normalises a folder path into an object-key prefix ("" for root,
// otherwise "some/folder/").
func r2Prefix(p string) string {
	p = strings.Trim(strings.TrimSpace(filepath.ToSlash(p)), "/")
	if p == "" {
		return ""
	}
	return p + "/"
}

// moveInR2 relocates one key, or a whole prefix when src names a folder. Object
// storage has no rename, so every object is copied then deleted.
// transferInR2 copies one key, or a whole prefix when srcKey names a folder.
// keepSource distinguishes a copy from a move: object storage has no rename, so
// a move is a copy followed by a delete either way.
func (c *serverCtx) transferInR2(srcKey, destPrefix string, keepSource bool) error {
	copyOne := func(from, to string) error {
		if from == to {
			return nil
		}
		// CopySource: EscapedPath keeps the "/" separators intact while escaping
		// spaces and other specials. url.PathEscape would turn every "/" into
		// %2F and point at a key that does not exist.
		_, err := c.r2.CopyObject(context.Background(), &s3.CopyObjectInput{
			Bucket:     awsv2.String(c.r2Bucket),
			Key:        awsv2.String(to),
			CopySource: awsv2.String((&url.URL{Path: c.r2Bucket + "/" + from}).EscapedPath()),
		})
		if err != nil || keepSource {
			return err
		}
		_, err = c.r2.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: awsv2.String(c.r2Bucket),
			Key:    awsv2.String(from),
		})
		return err
	}
	// A folder is a prefix: transfer every object beneath it, preserving
	// structure. ListObjectsV2 caps at 1000 keys per call, so this must
	// paginate — without it a folder of >1000 objects would transfer partially
	// and silently strand the remainder.
	folderPrefix := strings.TrimSuffix(srcKey, "/") + "/"
	base := path.Base(strings.TrimSuffix(srcKey, "/"))
	var token *string
	n := 0
	for {
		out, err := c.r2.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
			Bucket:            awsv2.String(c.r2Bucket),
			Prefix:            awsv2.String(folderPrefix),
			ContinuationToken: token,
		})
		if err != nil {
			return err
		}
		for _, obj := range out.Contents {
			k := awsv2.ToString(obj.Key)
			if err := copyOne(k, destPrefix+base+"/"+strings.TrimPrefix(k, folderPrefix)); err != nil {
				return err
			}
			n++
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		token = out.NextContinuationToken
	}
	if n > 0 {
		return nil
	}
	// Not a prefix, so it is a single object.
	return copyOne(srcKey, destPrefix+path.Base(srcKey))
}

func (c *serverCtx) handleMove(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "nothing to move", http.StatusBadRequest)
		return
	}
	to := r.URL.Query().Get("to") // "" means the root folder

	if c.r2 != nil {
		srcKey := strings.Trim(filepath.ToSlash(name), "/")
		destPrefix := r2Prefix(to)
		// Refuse to move a folder inside itself or one of its own descendants.
		if destPrefix == r2Prefix(srcKey) || strings.HasPrefix(destPrefix, strings.TrimSuffix(srcKey, "/")+"/") {
			http.Error(w, "cannot move a folder into itself", http.StatusBadRequest)
			return
		}
		if err := c.transferInR2(srcKey, destPrefix, false); err != nil {
			logger.Printf("R2 move %s -> %s: %v", srcKey, destPrefix, err)
			http.Error(w, "move failed", http.StatusInternalServerError)
			return
		}
		logger.Printf("R2 moved: %s -> %s", srcKey, destPrefix)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}

	srcPath, ok := safeSubpath(c.rootDir, name)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, name) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	destDir, ok := safeSubpath(c.rootDir, to)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	dfi, err := os.Stat(destDir)
	if err != nil || !dfi.IsDir() {
		http.Error(w, "destination folder not found", http.StatusNotFound)
		return
	}
	srcClean, destClean := filepath.Clean(srcPath), filepath.Clean(destDir)
	if fi.IsDir() {
		// Moving a folder into itself or a descendant would detach the subtree.
		if destClean == srcClean ||
			strings.HasPrefix(destClean+string(os.PathSeparator), srcClean+string(os.PathSeparator)) {
			http.Error(w, "cannot move a folder into itself", http.StatusBadRequest)
			return
		}
	}
	if filepath.Dir(srcClean) == destClean {
		// already there — treat as success so the UI does not need a special case
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}
	destName := resolveFilename(destDir, filepath.Base(srcPath))
	destPath := filepath.Join(destDir, destName)
	if err := os.Rename(srcPath, destPath); err != nil {
		logger.Printf("ERROR move %s -> %s: %v", srcPath, destPath, err)
		http.Error(w, "could not move", http.StatusInternalServerError)
		return
	}
	// keep any lock attached to the item it belongs to
	relockOnRename(name, strings.Trim(filepath.ToSlash(to), "/")+"/"+destName)
	logger.Printf("moved: %s -> %s", srcPath, destPath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func (c *serverCtx) handleCopy(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "nothing to copy", http.StatusBadRequest)
		return
	}
	to := r.URL.Query().Get("to")

	if c.r2 != nil {
		srcKey := strings.Trim(filepath.ToSlash(name), "/")
		destPrefix := r2Prefix(to)
		if destPrefix == r2Prefix(srcKey) || strings.HasPrefix(destPrefix, strings.TrimSuffix(srcKey, "/")+"/") {
			http.Error(w, "cannot copy a folder into itself", http.StatusBadRequest)
			return
		}
		if err := c.transferInR2(srcKey, destPrefix, true); err != nil {
			logger.Printf("R2 copy %s -> %s: %v", srcKey, destPrefix, err)
			http.Error(w, "copy failed", http.StatusInternalServerError)
			return
		}
		logger.Printf("R2 copied: %s -> %s", srcKey, destPrefix)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}

	srcPath, ok := safeSubpath(c.rootDir, name)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, name) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	destDir, ok := safeSubpath(c.rootDir, to)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	dfi, err := os.Stat(destDir)
	if err != nil || !dfi.IsDir() {
		http.Error(w, "destination folder not found", http.StatusNotFound)
		return
	}
	srcClean, destClean := filepath.Clean(srcPath), filepath.Clean(destDir)
	if fi.IsDir() {
		// Copying a folder into its own subtree would recurse forever.
		if destClean == srcClean ||
			strings.HasPrefix(destClean+string(os.PathSeparator), srcClean+string(os.PathSeparator)) {
			http.Error(w, "cannot copy a folder into itself", http.StatusBadRequest)
			return
		}
	}
	destName := resolveFilename(destDir, filepath.Base(srcPath))
	destPath := filepath.Join(destDir, destName)
	if fi.IsDir() {
		err = copyDir(srcPath, destPath)
	} else {
		err = copyFile(srcPath, destPath)
	}
	if err != nil {
		logger.Printf("ERROR copy %s -> %s: %v", srcPath, destPath, err)
		http.Error(w, "could not copy", http.StatusInternalServerError)
		return
	}
	logger.Printf("copied: %s -> %s", srcPath, destPath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// handlePublish pushes a local file into the public R2 bucket so it becomes
// available at the public URL. This is the private server's "Upload" action.
func (c *serverCtx) handlePublish(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.publishR2 == nil {
		http.Error(w, "public storage is not configured", http.StatusServiceUnavailable)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "nothing to upload", http.StatusBadRequest)
		return
	}
	srcPath, ok := safeSubpath(c.rootDir, name)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, name) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if fi.IsDir() {
		http.Error(w, "only files can be uploaded, not folders", http.StatusBadRequest)
		return
	}
	key := filepath.Base(srcPath)
	// Never clobber something already published under this name.
	for i := 1; ; i++ {
		_, err := c.publishR2.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: awsv2.String(c.publishBucket),
			Key:    awsv2.String(key),
		})
		if err != nil {
			break // does not exist — this name is free
		}
		ext := path.Ext(filepath.Base(srcPath))
		stem := strings.TrimSuffix(filepath.Base(srcPath), ext)
		key = fmt.Sprintf("%s_%d%s", stem, i, ext)
	}
	f, err := os.Open(srcPath)
	if err != nil {
		http.Error(w, "cannot read file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	_, err = c.publishR2.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:        awsv2.String(c.publishBucket),
		Key:           awsv2.String(key),
		Body:          f,
		ContentLength: awsv2.Int64(fi.Size()),
	})
	if err != nil {
		logger.Printf("publish %s: %v", key, err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	pubURL := strings.TrimRight(c.publishURL, "/") + "/" + (&url.URL{Path: key}).EscapedPath()
	logger.Printf("published: %s -> %s", srcPath, key)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"key": key, "url": pubURL})
}

func (c *serverCtx) handleMkdir(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "folder name required", http.StatusBadRequest)
		return
	}
	// One folder, not a path — reject anything that could climb out or nest.
	if name == "." || name == ".." || strings.ContainsAny(name, `\/:*?"<>|`) {
		http.Error(w, "invalid folder name", http.StatusBadRequest)
		return
	}
	parent := r.URL.Query().Get("path")
	if c.r2 != nil {
		prefix := ""
		if parent != "" {
			prefix = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(parent)), "/") + "/"
		}
		// R2 has no directories. A zero-byte object whose key ends in "/" is what
		// makes a delimiter listing report an otherwise empty folder.
		key := prefix + name + "/"
		_, err := c.r2.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket:        awsv2.String(c.r2Bucket),
			Key:           awsv2.String(key),
			Body:          strings.NewReader(""),
			ContentLength: awsv2.Int64(0),
		})
		if err != nil {
			logger.Printf("R2 mkdir %s: %v", key, err)
			http.Error(w, "could not create folder", http.StatusInternalServerError)
			return
		}
		logger.Printf("R2 folder created: %s", key)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}
	parentPath, ok := safeSubpath(c.rootDir, parent)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	dest := filepath.Join(parentPath, name)
	if _, err := os.Stat(dest); err == nil {
		http.Error(w, "a file or folder with that name already exists", http.StatusConflict)
		return
	}
	if err := os.Mkdir(dest, 0755); err != nil {
		logger.Printf("ERROR mkdir %s: %v", dest, err)
		http.Error(w, "could not create folder", http.StatusInternalServerError)
		return
	}
	logger.Printf("folder created: %s", dest)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func (c *serverCtx) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rawName := r.URL.Query().Get("name")
	fpath, ok := safeSubpath(c.rootDir, rawName)
	if !ok || rawName == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, rawName) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	if c.r2 != nil {
		// A folder is only a key prefix here, so deleting one means deleting
		// every object beneath it — paginated, since a listing caps at 1000.
		prefix := strings.TrimSuffix(rawName, "/") + "/"
		var token *string
		found := 0
		for {
			out, err := c.r2.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
				Bucket:            awsv2.String(c.r2Bucket),
				Prefix:            awsv2.String(prefix),
				ContinuationToken: token,
			})
			if err != nil {
				logger.Printf("R2 delete list %s: %v", prefix, err)
				break
			}
			for _, obj := range out.Contents {
				k := awsv2.ToString(obj.Key)
				if _, err := c.r2.DeleteObject(context.Background(), &s3.DeleteObjectInput{
					Bucket: awsv2.String(c.r2Bucket),
					Key:    awsv2.String(k),
				}); err != nil {
					logger.Printf("R2 delete %s: %v", k, err)
					http.Error(w, "delete failed", http.StatusInternalServerError)
					return
				}
				found++
			}
			if out.IsTruncated == nil || !*out.IsTruncated {
				break
			}
			token = out.NextContinuationToken
		}
		// Also remove the key itself: either the plain object, or the zero-byte
		// marker that represents an empty folder.
		if _, err := c.r2.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: awsv2.String(c.r2Bucket),
			Key:    awsv2.String(rawName),
		}); err != nil && found == 0 {
			logger.Printf("R2 delete %s: %v", rawName, err)
			http.Error(w, "delete failed", http.StatusInternalServerError)
			return
		}
		logger.Printf("R2 deleted: %s (%d nested)", rawName, found)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}
	fi, err := os.Stat(fpath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Snapshot which files will disappear before removing them, so their media
	// cache entries (keyed by path+modtime+size) can be cleaned up afterward.
	type cacheTarget struct {
		path string
		fi   os.FileInfo
	}
	var cacheTargets []cacheTarget
	if fi.IsDir() {
		filepath.Walk(fpath, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				cacheTargets = append(cacheTargets, cacheTarget{p, info})
			}
			return nil
		})
	} else {
		cacheTargets = append(cacheTargets, cacheTarget{fpath, fi})
	}
	// RemoveAll for a directory: a folder with contents used to fail with
	// "directory not empty", which made populated folders undeletable. The UI
	// warns that the contents go too.
	if fi.IsDir() {
		err = os.RemoveAll(fpath)
	} else {
		err = os.Remove(fpath)
	}
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "could not delete — a file inside may be open in another program", http.StatusBadRequest)
			logger.Printf("ERROR delete %s: %v", fpath, err)
		}
		return
	}
	for _, t := range cacheTargets {
		removeMediaCache(t.path, t.fi)
	}
	dropLock(rawName)
	logger.Printf("deleted: %s", fpath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// handleSaveText overwrites an existing text file in place, for the editable
// note/text view. Restricted to text-ish files so this cannot be used to
// clobber arbitrary binaries.
func (c *serverCtx) handleSaveText(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	if !isTextFile(name) {
		http.Error(w, "only text files can be edited", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if c.r2 != nil {
		_, err = c.r2.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket:        awsv2.String(c.r2Bucket),
			Key:           awsv2.String(name),
			Body:          strings.NewReader(string(body)),
			ContentLength: awsv2.Int64(int64(len(body))),
			ContentType:   awsv2.String("text/plain; charset=utf-8"),
		})
		if err != nil {
			logger.Printf("R2 save %s: %v", name, err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}
		logger.Printf("R2 saved: %s", name)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}
	fpath, ok := safeSubpath(c.rootDir, name)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c.blockedByLock(r, name) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(fpath)
	if err != nil || fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// write beside the original and swap, so an interrupted save cannot leave
	// the file truncated
	tmp := fpath + ".fdsave"
	if err := os.WriteFile(tmp, body, 0644); err != nil {
		os.Remove(tmp)
		logger.Printf("ERROR save %s: %v", fpath, err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, fpath); err != nil {
		os.Remove(tmp)
		logger.Printf("ERROR save rename %s: %v", fpath, err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	logger.Printf("saved: %s", fpath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func (c *serverCtx) handleQR(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	host := r.Host
	if host == "" {
		host = fmt.Sprintf("localhost:%d", c.port)
	}
	// ?data= encodes an arbitrary link (a share URL); otherwise this server's own
	// address. Restricted to our own scheme+host so it cannot be used to mint a
	// QR pointing anywhere on the internet.
	target := "http://" + host + "/"
	if d := r.URL.Query().Get("data"); d != "" {
		if u, err := url.Parse(d); err == nil && u.Host == host && (u.Scheme == "http" || u.Scheme == "https") {
			target = d
		}
	}
	png, err := qrcode.Encode(target, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "qr error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(png)
}

func (c *serverCtx) handleDisk(w http.ResponseWriter, r *http.Request) {
	// host capacity is the owner's business, not a share visitor's
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	root := c.rootDir
	var free, total uint64
	if p, err := windows.UTF16PtrFromString(root); err == nil {
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

// fillNoteBody puts a note's real text on the entry. Search results render as
// the same editable rows as a listing, so they must carry the actual note —
// not a 160-character preview, and not a match excerpt. Either would be written
// back over the file the moment someone edited a note they found by searching.
func fillNoteBody(entry *fileEntry, fullPath string) {
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return
	}
	s := string(raw)
	if len(s) > noteInlineMax {
		s = s[:noteInlineMax]
		entry.Truncated = true
	}
	entry.Snippet = s
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
				fillNoteBody(&entry, filepath.Join(dir, e.Name()))
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
				// a note row is editable, so it must hold the note itself
				if isNote {
					fillNoteBody(&entry, filepath.Join(dir, e.Name()))
				}
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

func (c *serverCtx) handleExport(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.exportDir == "" {
		http.Error(w, "export directory not configured", http.StatusServiceUnavailable)
		return
	}
	rawName := r.URL.Query().Get("name")
	srcPath, ok := safeSubpath(c.rootDir, rawName)
	if !ok || rawName == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := os.MkdirAll(c.exportDir, 0755); err != nil {
		http.Error(w, "cannot create export dir", http.StatusInternalServerError)
		return
	}
	destName := resolveFilename(c.exportDir, filepath.Base(rawName))
	destPath := filepath.Join(c.exportDir, destName)
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

func (c *serverCtx) handleSearch(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	if c.r2 != nil {
		out, err := c.r2.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
			Bucket: awsv2.String(c.r2Bucket),
		})
		if err != nil {
			http.Error(w, "search failed", http.StatusInternalServerError)
			return
		}
		ql := strings.ToLower(query)
		var results []fileEntry
		for _, obj := range out.Contents {
			key := awsv2.ToString(obj.Key)
			if strings.Contains(strings.ToLower(key), ql) {
				results = append(results, fileEntry{
					Name:     key,
					Size:     awsv2.ToInt64(obj.Size),
					Modified: awsv2.ToTime(obj.LastModified),
					IsNote:   strings.HasPrefix(key, "note_") && strings.HasSuffix(key, ".txt"),
					// No body is fetched here — one request per hit would be far too
					// many. Truncated makes the client load the real text before it
					// allows editing, so an empty snippet can never be saved over a note.
					Truncated: strings.HasPrefix(key, "note_") && strings.HasSuffix(key, ".txt"),
				})
			}
		}
		sort.Slice(results, func(i, j int) bool { return results[i].Modified.After(results[j].Modified) })
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
		return
	}
	var results []fileEntry
	walkSearch(c.rootDir, "", query, &results)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Modified.After(results[j].Modified)
	})
	// Search walks the whole tree, so it must drop locked hits itself —
	// otherwise a lock could be defeated simply by searching for the name.
	// Search names carry their full relative path already.
	sess := sessionKey(c, r)
	kept := results[:0]
	for _, e := range results {
		key := lockedAncestor(e.Name)
		if key == "" {
			kept = append(kept, e)
			continue
		}
		if isUnlocked(sess, key) {
			e.Locked, e.Unlocked = true, true
			kept = append(kept, e)
		}
	}
	results = kept
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		logger.Printf("ERROR encoding search results: %v", err)
	}
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

func newServerCtxFromCfg() *serverCtx {
	secret, _ := hex.DecodeString(cfg.Secret)
	c := &serverCtx{
		rootDir:     cfg.UploadDir,
		passHash:    cfg.PasswordHash,
		secret:      secret,
		cookie:      cookieName,
		port:        cfg.Port,
		exportDir:   cfg.ExportDir,
		footerLabel: "LAN only",
		loginLabel:  "Local Network · Private",
		rateMap:     make(map[string]*rateEntry),
	}
	// Publish target for the "Upload" action. Assigned to publishR2, never to r2:
	// r2 would put this server itself into R2 mode.
	if cfg.R2AccountID != "" && cfg.R2AccessKey != "" && cfg.R2SecretKey != "" {
		c.publishR2 = newR2Client(cfg.R2AccountID, cfg.R2AccessKey, cfg.R2SecretKey)
		c.publishBucket = cfg.R2Bucket
		c.publishURL = cfg.R2PublicURL
	}
	c.loginDisabled.Store(cfg.LoginDisabled)
	return c
}

func buildServer() *http.Server {
	c := newServerCtxFromCfg()
	privSrv = c
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/favicon.png", handleFaviconPNG)
	mux.HandleFunc("/favicon.ico", handleFaviconPNG)
	mux.HandleFunc("/apple-touch-icon.png", handleAppleTouchIcon)
	mux.HandleFunc("/apple-touch-icon-precomposed.png", handleAppleTouchIcon)
	mux.HandleFunc("/login", c.handleLogin)
	mux.HandleFunc("/upload", c.handleUpload)
	mux.HandleFunc("/files", c.handleFiles)
	mux.HandleFunc("/file", c.handleFile)
	mux.HandleFunc("/download-folder", c.handleDownloadFolder)
	mux.HandleFunc("/note", c.handleNote)
	mux.HandleFunc("/delete", c.handleDelete)
	mux.HandleFunc("/mkdir", c.handleMkdir)
	mux.HandleFunc("/save-text", c.handleSaveText)
	mux.HandleFunc("/share", c.handleShare)
	mux.HandleFunc("/unshare", c.handleUnshare)
	mux.HandleFunc("/share-info", c.handleShareInfo)
	mux.HandleFunc("/s/", c.handleShareEntry)
	mux.HandleFunc("/lock", c.handleLock)
	mux.HandleFunc("/unlock", c.handleUnlock)
	mux.HandleFunc("/remove-lock", c.handleRemoveLock)
	mux.HandleFunc("/move", c.handleMove)
	mux.HandleFunc("/copy", c.handleCopy)
	mux.HandleFunc("/file-token", c.handleFileToken)
	mux.HandleFunc("/qr.png", c.handleQR)
	mux.HandleFunc("/disk", c.handleDisk)
	mux.HandleFunc("/search", c.handleSearch)
	mux.HandleFunc("/export", c.handleExport)
	mux.HandleFunc("/publish", c.handlePublish)
	mux.HandleFunc("/thumb", c.handleThumb)
	mux.HandleFunc("/remux", c.handleRemux)
	mux.HandleFunc("/stream", c.handleStream)
	mux.HandleFunc("/hls/", c.handleHLS)
	mux.HandleFunc("/toggle-login", c.handleToggleLogin)
	mux.HandleFunc("/", c.handleIndex)
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func buildPublicServer() *http.Server {
	if cfg.PublicPort == 0 || cfg.PublicPasswordHash == "" || cfg.ExportDir == "" {
		return nil
	}
	secret, _ := hex.DecodeString(cfg.PublicSecret)
	c := &serverCtx{
		rootDir:     cfg.ExportDir,
		passHash:    cfg.PublicPasswordHash,
		secret:      secret,
		cookie:      pubCookieName,
		port:        cfg.PublicPort,
		exportDir:   "",
		footerLabel:  "Shared",
		loginLabel:   "Shared · Public",
		downloadRate: 100 * 1024 * 1024,
		r2Bucket:     cfg.R2Bucket,
		r2PubURL:     cfg.R2PublicURL,
		rateMap:      make(map[string]*rateEntry),
	}
	if cfg.R2AccountID != "" && cfg.R2AccessKey != "" && cfg.R2SecretKey != "" {
		c.r2 = newR2Client(cfg.R2AccountID, cfg.R2AccessKey, cfg.R2SecretKey)
		logger.Printf("R2 storage enabled: bucket=%s", cfg.R2Bucket)
	}
	c.loginDisabled.Store(cfg.PublicLoginDisabled)
	pubSrv = c
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/favicon.png", handleFaviconPNG)
	mux.HandleFunc("/favicon.ico", handleFaviconPNG)
	mux.HandleFunc("/apple-touch-icon.png", handleAppleTouchIcon)
	mux.HandleFunc("/apple-touch-icon-precomposed.png", handleAppleTouchIcon)
	mux.HandleFunc("/login", c.handleLogin)
	mux.HandleFunc("/upload", c.handleUpload)
	mux.HandleFunc("/presign", c.handlePresign)
	mux.HandleFunc("/files", c.handleFiles)
	mux.HandleFunc("/file", c.handleFile)
	mux.HandleFunc("/note", c.handleNote)
	mux.HandleFunc("/delete", c.handleDelete)
	mux.HandleFunc("/mkdir", c.handleMkdir)
	mux.HandleFunc("/save-text", c.handleSaveText)
	mux.HandleFunc("/move", c.handleMove)
	mux.HandleFunc("/copy", c.handleCopy)
	mux.HandleFunc("/file-token", c.handleFileToken)
	mux.HandleFunc("/qr.png", c.handleQR)
	mux.HandleFunc("/disk", c.handleDisk)
	mux.HandleFunc("/search", c.handleSearch)
	mux.HandleFunc("/", c.handleIndex)
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.PublicPort),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
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
	pub := buildPublicServer()
	if pub != nil {
		go func() {
			logger.Printf("public server starting on :%d, export dir: %s", cfg.PublicPort, cfg.ExportDir)
			if err := pub.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Printf("public server error: %v", err)
			}
		}()
	}
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
	srv.Shutdown(ctx)
	if pub != nil {
		pub.Shutdown(ctx)
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
	loadLocks()
	loadShares()
	resolveMediaTools()
	nvencAvailable = probeNvenc()
	go pruneMediaCache()
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
	fmt.Print("Shared export folder — also used as the public server root (leave blank to skip): ")
	exportDir, _ := reader.ReadString('\n')
	exportDir = strings.TrimSpace(exportDir)

	var pubPort int
	var pubHash, pubSecretHex string
	if exportDir != "" {
		fmt.Print("Public sharing port (leave blank to disable): ")
		pubPortStr, _ := reader.ReadString('\n')
		pubPortStr = strings.TrimSpace(pubPortStr)
		if pubPortStr != "" {
			if p, err := strconv.Atoi(pubPortStr); err == nil && p > 0 && p < 65536 {
				pubPort = p
			} else {
				fmt.Fprintf(os.Stderr, "invalid port %q, public server disabled\n", pubPortStr)
			}
		}
		if pubPort > 0 {
			fmt.Print("Public sharing password: ")
			pubPw1, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				log.Fatalf("cannot read password: %v", err)
			}
			if len(strings.TrimSpace(string(pubPw1))) == 0 {
				log.Fatal("public password cannot be empty")
			}
			fmt.Print("Confirm public password: ")
			pubPw2, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				log.Fatalf("cannot read password: %v", err)
			}
			if string(pubPw1) != string(pubPw2) {
				log.Fatal("passwords do not match")
			}
			h, err := bcrypt.GenerateFromPassword(pubPw1, 12)
			if err != nil {
				log.Fatalf("bcrypt error: %v", err)
			}
			pubHash = string(h)
			pubSec := make([]byte, 32)
			if _, err := rand.Read(pubSec); err != nil {
				log.Fatalf("random error: %v", err)
			}
			pubSecretHex = hex.EncodeToString(pubSec)
		}
	}

	cfg = Config{
		PasswordHash:       string(hash),
		Secret:             hex.EncodeToString(secret),
		UploadDir:          uploadDir,
		Port:               port,
		ExportDir:          exportDir,
		PublicPort:         pubPort,
		PublicPasswordHash: pubHash,
		PublicSecret:       pubSecretHex,
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
	fmt.Printf("  4. Private server: http://<your-local-IP>:%d\n", port)
	if pubPort > 0 {
		fmt.Printf("  5. Public server:  http://localhost:%d  (expose via Cloudflare Tunnel)\n", pubPort)
	}
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
		loadLocks()
		loadShares()
		resolveMediaTools()
		nvencAvailable = probeNvenc()
		go pruneMediaCache()
		pub := buildPublicServer()
		if pub != nil {
			go func() {
				log.Printf("public server on http://localhost:%d — export dir: %s", cfg.PublicPort, cfg.ExportDir)
				if err := pub.ListenAndServe(); err != nil {
					log.Printf("public server: %v", err)
				}
			}()
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