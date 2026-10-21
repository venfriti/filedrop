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
	CacheDir            string `json:"cache_dir,omitempty"`
	CachePruneDays      int    `json:"cache_prune_days,omitempty"`
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
	private      bool // the LAN server; the public one lacks pins, settings and locks
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
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<script>
(function(){
  var s = {};
  try { s = JSON.parse(localStorage.getItem('fd_settings') || '{}'); } catch(e){}
  var t = s.theme || (function(){ try { return localStorage.getItem('fd_theme'); } catch(e){ return null; } })() || 'dark';
  if (t === 'system') t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  if (t === 'light') document.documentElement.className = 'light';
})();
</script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#2d2d2d;--card:#353535;--side:#232323;--text:#d7d7d7;--head:#fff;--muted:#9a9a9a;--accent:#7383ff;--fill:#3f4fe0;--danger:#ff7d61;--shadow:0 4px 12px rgba(0,0,0,.4),0 24px 56px rgba(0,0,0,.45);--line:rgba(255,255,255,.08)}
:root.light{--bg:#f5f5f6;--card:#fff;--side:#f5f5f6;--text:#1f1f22;--head:#000;--muted:#6e6e73;--accent:#2f3fd6;--fill:#2f3fd6;--danger:#d9480f;--shadow:0 4px 12px rgba(0,0,0,.06),0 24px 56px rgba(0,0,0,.1);--line:rgba(0,0,0,.08)}
body{background:var(--bg);color:var(--text);font:14px/1.45 'Plus Jakarta Sans',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;-webkit-font-smoothing:antialiased}
.card{width:100%;max-width:360px;background:var(--card);border-radius:20px;box-shadow:var(--shadow);padding:28px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:22px}
.mark{width:34px;height:34px;border-radius:10px;background:var(--fill);color:#fff;display:flex;align-items:center;justify-content:center}
.name{font-size:18px;font-weight:700;color:var(--head)}
.label{font-size:12px;font-weight:600;color:var(--muted);margin-top:1px}
input[type=password]{width:100%;height:44px;padding:0 14px;background:var(--side);border:none;border-radius:12px;color:var(--text);font:inherit;font-size:14px;outline:none;box-shadow:inset 0 0 0 1px var(--line)}
input[type=password]:focus{box-shadow:inset 0 0 0 2px var(--accent)}
input[type=password]::placeholder{color:var(--muted)}
button{width:100%;height:44px;margin-top:12px;background:var(--fill);color:#fff;border:none;border-radius:12px;font:inherit;font-size:14px;font-weight:600;cursor:pointer;transition:filter .15s}
button:hover{filter:brightness(1.1)}
.err{margin-top:12px;font-size:13px;color:var(--danger)}
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="mark"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v12"/><path d="M6.5 11l5.5 5.5 5.5-5.5"/><path d="M5 20h14"/></svg></div>
    <div><div class="name">FileDrop</div><div class="label">{{.Label}}</div></div>
  </div>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Password" aria-label="Password" autofocus autocomplete="current-password">
    <button type="submit">Sign in</button>
    {{if .Error}}{{if .Locked}}<p class="err">Too many attempts. Try again later.</p>{{else}}<p class="err">Incorrect password.</p>{{end}}{{end}}
  </form>
</div>
</body>
</html>`))

var uploadTmpl = template.Must(template.New("upload").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>FileDrop</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="icon" href="/favicon.png" type="image/png"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<script>
// Applied before first paint so a light-theme user never sees a dark flash.
(function(){
  var s = {};
  try { s = JSON.parse(localStorage.getItem('fd_settings') || '{}'); } catch(e){}
  if (!s.theme) { try { if (localStorage.getItem('fd_theme') === 'light') s.theme = 'light'; } catch(e){} }
  var t = s.theme || 'dark';
  if (t === 'system') t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  var c = document.documentElement.classList;
  if (t === 'light') c.add('pre-light');
})();
</script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

/* ── Palette ─────────────────────────────────────────────────────────────────
   *0 variables are the untinted base; the live variables derive from them so the
   "tinted backgrounds" setting can mix the accent in without duplicating every
   theme. Dark follows Poly Haven's greys; light is a formal white. */
:root{
  --bg0:#2d2d2d;--side0:#232323;--raised0:#414141;--hover0:#363636;--card0:#353535;
  --text:#d7d7d7;--head:#ffffff;--muted0:#9a9a9a;--line:rgba(255,255,255,.07);
  --shadow:0 1px 2px rgba(0,0,0,.35),0 6px 18px rgba(0,0,0,.22);
  --shadow-lg:0 4px 12px rgba(0,0,0,.4),0 24px 56px rgba(0,0,0,.45);
  --btn-shadow:0 1px 2px rgba(0,0,0,.45);
  --danger:#ff7d61;--ok:#4ade80;--scrim:rgba(0,0,0,.55);
  --c-folder:#f5b14c;--c-image:#2dd4bf;--c-video:#a78bfa;--c-audio:#f472b6;--c-pdf:#f87171;--c-doc:#94a3b8;--c-note:#4ade80;--c-archive:#fb923c;--c-code:#a3b1c6;
  --tile-a:16%;--soft-a:16%;
  --accent:#7383ff;--accent-fill:#3f4fe0;
}
:root.pre-light,body.light{
  --bg0:#ffffff;--side0:#f5f5f6;--raised0:#e6e6e8;--hover0:#f3f3f5;--card0:#ffffff;
  --text:#1f1f22;--head:#000000;--muted0:#6e6e73;--line:rgba(0,0,0,.07);
  --shadow:0 1px 3px rgba(0,0,0,.07),0 6px 16px rgba(0,0,0,.05);
  --shadow-lg:0 4px 12px rgba(0,0,0,.08),0 24px 56px rgba(0,0,0,.16);
  --btn-shadow:0 1px 2px rgba(0,0,0,.12);
  --danger:#d9480f;--ok:#15803d;--scrim:rgba(20,20,30,.32);
  --c-folder:#d97706;--c-image:#0d9488;--c-video:#7c3aed;--c-audio:#db2777;--c-pdf:#dc2626;--c-doc:#475569;--c-note:#16a34a;--c-archive:#ea580c;--c-code:#64748b;
  --tile-a:11%;--soft-a:10%;
  --accent:#2f3fd6;--accent-fill:#2f3fd6;
}
body[data-accent=cobalt]{--accent:#5c84ff;--accent-fill:#2a5aff}
body.light[data-accent=cobalt]{--accent:#1f4fff;--accent-fill:#1f4fff}
body[data-accent=steel]{--accent:#7fa6d4;--accent-fill:#3d6a9e}
body.light[data-accent=steel]{--accent:#3d6a9e;--accent-fill:#3d6a9e}
body[data-accent=original]{--accent:#4c8dff;--accent-fill:#2f6fea}
body.light[data-accent=original]{--accent:#2563eb;--accent-fill:#2563eb}
body{--bg:var(--bg0);--side:var(--side0);--raised:var(--raised0);--hover:var(--hover0);--card:var(--card0);--muted:var(--muted0)}
body.tint{
  --bg:color-mix(in srgb,var(--bg0),var(--accent) 5%);--side:color-mix(in srgb,var(--side0),var(--accent) 5%);
  --raised:color-mix(in srgb,var(--raised0),var(--accent) 7%);--hover:color-mix(in srgb,var(--hover0),var(--accent) 6%);
  --card:color-mix(in srgb,var(--card0),var(--accent) 6%);--muted:color-mix(in srgb,var(--muted0),var(--accent) 10%)}
body.light.tint{--bg:var(--bg0);--card:var(--card0);
  --side:color-mix(in srgb,var(--side0),var(--accent) 3.5%);--raised:color-mix(in srgb,var(--raised0),var(--accent) 5%);
  --hover:color-mix(in srgb,var(--hover0),var(--accent) 3.5%)}
body{--soft:color-mix(in srgb,var(--accent) var(--soft-a),transparent)}

html{scrollbar-width:thin;scrollbar-color:rgba(128,128,128,.35) transparent}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(128,128,128,.35);border:2px solid transparent;background-clip:padding-box;border-radius:6px}
html,body{height:100%}
body{background:var(--bg);color:var(--text);font:14px/1.45 'Plus Jakarta Sans',system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}
button,input,textarea,select{font:inherit;color:inherit}
button{cursor:pointer}
svg{flex-shrink:0}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.hidden{display:none!important}

/* ── Shell ──────────────────────────────────────────────────────────────────── */
.app{display:flex;height:100vh;height:100dvh;overflow:hidden}
.sidebar{width:272px;flex-shrink:0;background:var(--side);box-shadow:1px 0 0 var(--line);display:flex;flex-direction:column;gap:18px;padding:18px 14px 14px;min-height:0;z-index:40;transition:background .2s}
.main{flex:1;min-width:0;overflow-y:auto;display:flex;flex-direction:column;position:relative}
#scrim{display:none;position:fixed;inset:0;background:var(--scrim);z-index:35}

.brand{display:flex;align-items:center;gap:10px;padding:0 6px}
.brand-mark{width:30px;height:30px;border-radius:9px;background:var(--accent-fill);color:#fff;display:flex;align-items:center;justify-content:center}
.brand-name{font-size:16px;font-weight:700;color:var(--head);letter-spacing:-.01em}

/* ── Buttons ────────────────────────────────────────────────────────────────── */
.btn,.folder-btn{height:36px;border:none;border-radius:10px;background:var(--side);color:var(--head);font-size:13px;font-weight:600;padding:0 14px;display:inline-flex;align-items:center;justify-content:center;gap:7px;white-space:nowrap;transition:background .15s,filter .15s,transform .1s}
.btn:hover:not(:disabled),.folder-btn:hover:not(:disabled){background:var(--raised)}
.btn:active:not(:disabled),.folder-btn:active:not(:disabled){transform:scale(.97)}
.btn svg,.folder-btn svg{width:16px;height:16px}
.btn.icon{width:36px;padding:0}
.btn.ghost{background:transparent}
.btn.ghost:hover{background:var(--hover)}
.btn.primary,.folder-btn.primary{background:var(--accent-fill);color:#fff;box-shadow:0 1px 2px rgba(0,0,0,.15)}
.btn.primary:hover:not(:disabled),.folder-btn.primary:hover:not(:disabled){background:var(--accent-fill);filter:brightness(1.1)}
.folder-btn.danger{background:color-mix(in srgb,var(--danger) 14%,transparent);color:var(--danger)}
.folder-btn.danger:hover:not(:disabled){background:color-mix(in srgb,var(--danger) 22%,transparent)}
.btn:disabled,.folder-btn:disabled{opacity:.45;cursor:default}
.btn.active{background:var(--soft);color:var(--accent)}

.side-actions{display:flex;flex-direction:column;gap:8px}
.upload-split{display:flex;gap:6px}
.upload-split .btn.primary{flex:1;height:40px;font-size:14px;border-radius:11px}
.sidebar .btn:not(.primary){background:var(--raised)}
.sidebar .btn:not(.primary):hover{background:color-mix(in srgb,var(--raised),var(--head) 6%)}
.upload-split .btn.icon{width:40px;height:40px;border-radius:11px}

/* ── Sidebar sections ───────────────────────────────────────────────────────── */
.side-section{display:flex;flex-direction:column;gap:2px;min-height:0}
.side-title{font-size:11.5px;font-weight:600;color:var(--muted);padding:0 8px 6px;letter-spacing:.02em}
.side-row,.tree-row{height:32px;border-radius:8px;display:flex;align-items:center;gap:8px;padding:0 8px;color:var(--text);font-weight:500;font-size:13.5px;cursor:pointer;user-select:none;transition:background .12s}
.side-row:hover,.tree-row:hover{background:var(--hover)}
.side-row .nm,.tree-row .nm{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.side-row svg,.tree-row .ico svg{width:17px;height:17px}
.tree-wrap{flex:1;min-height:0;overflow-y:auto;margin:0 -4px;padding:0 4px}
.tree-row{gap:4px;padding-right:8px}
.tree-row.active{background:var(--soft);color:var(--accent);font-weight:600}
.tree-row.drop-target{box-shadow:inset 0 0 0 2px var(--accent)}
.tree-chev{width:20px;height:20px;border:none;background:none;color:var(--muted);display:flex;align-items:center;justify-content:center;border-radius:5px;flex-shrink:0}
.tree-chev:hover{background:var(--raised)}
.tree-chev svg{width:13px;height:13px;transition:transform .15s}
.tree-chev.open svg{transform:rotate(90deg)}
.tree-chev.leaf{visibility:hidden}
.tree-row .ico{color:var(--c-folder);display:flex;margin-right:4px}
.side-empty{font-size:12.5px;color:var(--muted);padding:2px 8px}
.side-foot{display:flex;flex-direction:column;gap:8px;padding:10px 8px 0}
#disk-bar-track{height:5px;border-radius:3px;background:var(--raised);overflow:hidden}
#disk-bar-fill{height:100%;border-radius:3px;background:var(--accent);transition:width .3s}
.disk-meta{display:flex;flex-direction:column;gap:2px;font-size:12px;color:var(--muted)}
.disk-meta span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ── Top bar ────────────────────────────────────────────────────────────────── */
.topbar{position:sticky;top:0;z-index:20;height:64px;flex-shrink:0;display:flex;align-items:center;gap:16px;padding:0 24px 0 28px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(10px)}
#menu-toggle{display:none}
.breadcrumb{display:flex;align-items:center;gap:4px;font-size:13.5px;min-width:0;flex:1 1 0;overflow:hidden}
.bc-item{color:var(--muted);font-weight:500;cursor:pointer;padding:3px 6px;border-radius:6px;white-space:nowrap;transition:background .12s,color .12s}
.bc-item:hover{background:var(--hover);color:var(--text)}
.bc-current{color:var(--head);font-weight:600;cursor:default;overflow:hidden;text-overflow:ellipsis}
.bc-current:hover{background:none;color:var(--head)}
.bc-sep{color:var(--muted);display:flex}
.bc-sep svg{width:14px;height:14px}
.bc-item.drop-target{box-shadow:inset 0 0 0 2px var(--accent);color:var(--accent)}
.cmd{position:relative;width:460px;max-width:42vw;height:38px;border-radius:11px;background:var(--side);display:flex;align-items:center;gap:10px;padding:0 8px 0 14px;flex-shrink:1}
.cmd>svg{width:16px;height:16px;color:var(--muted)}
#search-input{flex:1;min-width:0;border:none;outline:none;background:transparent;font-size:13.5px}
#search-input::placeholder{color:var(--muted)}
#search-input::-webkit-search-cancel-button{display:none}
#search-clear{border:none;background:none;color:var(--muted);width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center}
#search-clear:hover{background:var(--raised);color:var(--text)}
.kbd{font-size:11.5px;font-weight:600;color:var(--muted);background:var(--bg);border-radius:6px;padding:3px 7px;box-shadow:var(--btn-shadow);white-space:nowrap}
#search-close{display:none}
.top-actions{display:flex;align-items:center;gap:4px;flex:1 1 0;justify-content:flex-end}
.top-actions .btn svg{width:18px;height:18px}
#cmd-menu{display:none;position:absolute;left:0;right:0;top:calc(100% + 6px);background:var(--card);border-radius:12px;box-shadow:var(--shadow-lg);padding:6px;z-index:60}
#cmd-menu.open{display:block}
.cmd-head{font-size:11.5px;font-weight:600;color:var(--muted);padding:6px 10px 4px}
.cmd-item{width:100%;display:flex;align-items:center;gap:10px;border:none;background:none;border-radius:8px;padding:8px 10px;text-align:left;font-size:13.5px;font-weight:500;color:var(--text)}
.cmd-item svg{width:16px;height:16px;color:var(--muted)}
.cmd-item.on,.cmd-item:hover{background:var(--hover);color:var(--head)}
.cmd-item.on svg{color:var(--accent)}
.cmd-item .hint{margin-left:auto;font-size:12px;color:var(--muted)}

/* ── Folder header ──────────────────────────────────────────────────────────── */
.content{flex:1;display:flex;flex-direction:column;padding:6px 32px 32px;min-width:0}
.folder-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;padding:8px 0 18px;flex-wrap:wrap}
#folder-title{font-size:28px;font-weight:700;color:var(--head);letter-spacing:-.02em;line-height:1.2;word-break:break-word}
.folder-meta{font-size:13px;color:var(--muted);margin-top:4px}
.folder-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.seg{display:flex;gap:2px;padding:3px;border-radius:11px;background:var(--side)}
.seg button{height:30px;min-width:34px;border:none;border-radius:8px;background:transparent;color:var(--muted);display:flex;align-items:center;justify-content:center;gap:6px;padding:0 8px;font-size:13px;font-weight:600;transition:background .15s,color .15s}
.seg button svg{width:16px;height:16px}
.seg button.on{background:var(--card);color:var(--head);box-shadow:var(--btn-shadow)}
body.light .seg button.on{background:#fff}
.ext-filter{position:relative}
.ext-caret{width:12px;height:12px;opacity:.7}
#ext-btn.active{background:var(--soft);color:var(--accent)}
.ext-menu{display:none;position:absolute;left:0;top:calc(100% + 6px);z-index:50;background:var(--card);border-radius:12px;min-width:180px;max-height:18rem;overflow-y:auto;box-shadow:var(--shadow-lg);padding:6px}
.ext-menu.open{display:block}
.ext-item{display:flex;align-items:center;justify-content:space-between;gap:1.25rem;width:100%;border:none;background:none;border-radius:8px;padding:8px 10px;font-size:13px;font-weight:500;color:var(--text);text-align:left}
.ext-item:hover{background:var(--hover)}
.ext-item.sel{color:var(--accent);font-weight:600}
.ext-count{font-size:12px;color:var(--muted)}

/* ── Pinned strip (phone) ───────────────────────────────────────────────────── */
.pin-strip{display:none;gap:8px;overflow-x:auto;padding:0 0 14px;scrollbar-width:none}
.pin-strip::-webkit-scrollbar{display:none}
.pin-chip{display:flex;align-items:center;gap:8px;height:38px;padding:0 14px 0 10px;border-radius:12px;background:var(--side);border:none;font-size:13px;font-weight:600;color:var(--head);white-space:nowrap;flex-shrink:0}
.pin-chip svg{width:17px;height:17px}

/* ── Share banner & selection bar ───────────────────────────────────────────── */
#share-banner{display:none;align-items:center;gap:18px;padding:16px;margin-bottom:18px;background:var(--side);border-radius:14px}
.share-qr{width:112px;height:112px;image-rendering:pixelated;background:#fff;padding:6px;border-radius:10px;flex-shrink:0}
.share-info{display:flex;flex-direction:column;gap:8px;min-width:0}
.share-title{font-size:14px;font-weight:700;color:var(--head)}
.share-url{font-size:12.5px;color:var(--muted);word-break:break-all}
.share-links{display:flex;gap:8px;flex-wrap:wrap}
#select-bar{display:none;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;background:var(--soft);border-radius:14px;padding:10px 12px 10px 16px;margin-bottom:14px;position:sticky;top:72px;z-index:15;backdrop-filter:blur(10px)}
#select-bar.open{display:flex}
#select-bar-count{font-size:13.5px;font-weight:700;color:var(--accent)}
#select-bar-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
#select-bar .folder-btn:not(.primary):not(.danger){background:var(--card)}
.sb-div{width:1px;height:20px;background:var(--line)}

/* ── File list ──────────────────────────────────────────────────────────────── */
.list-head{display:flex;align-items:center;gap:14px;padding:0 12px 8px;font-size:12px;font-weight:600;color:var(--muted)}
.list-head .lh-name{flex:1}
.file-list{display:flex;flex-direction:column;margin:0 -12px}
.file-item,.note-item{display:flex;align-items:center;gap:14px;padding:9px 12px;border-radius:12px;position:relative;transition:background .12s,transform .15s,box-shadow .15s}
.file-item:hover,.note-item:hover{background:var(--hover)}
.k-folder{--k:var(--c-folder)}.k-image{--k:var(--c-image)}.k-video{--k:var(--c-video)}.k-audio{--k:var(--c-audio)}.k-pdf{--k:var(--c-pdf)}.k-doc{--k:var(--c-doc)}.k-note{--k:var(--c-note)}.k-archive{--k:var(--c-archive)}.k-code{--k:var(--c-code)}.k-lock{--k:var(--muted)}
.ft-tile{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0;position:relative;background:color-mix(in srgb,var(--k) var(--tile-a),transparent);color:var(--k)}
.ft-tile svg{width:20px;height:20px}
.ft-tile img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:block}
.ft-play{position:absolute;width:22px;height:22px;border-radius:11px;background:rgba(0,0,0,.55);color:#fff;display:none;align-items:center;justify-content:center}
.ft-play svg{width:10px;height:10px}
.file-info-col,.note-body{flex:1;min-width:0;cursor:pointer}
.file-name{font-size:14px;font-weight:600;color:var(--head);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.file-name-ext{color:var(--muted);font-weight:500}
body.hide-ext .file-name-ext{display:none}
.pin-ico{display:inline-flex;vertical-align:-1px;margin-left:6px;color:var(--accent)}
.pin-ico svg{width:12px;height:12px}
.file-type-date,.note-meta{font-size:12.5px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.meta-grid{display:none}
.col-size{width:96px;text-align:right;font-size:13px;color:var(--muted);flex-shrink:0}
.col-date{width:132px;padding-left:24px;font-size:13px;color:var(--muted);flex-shrink:0;white-space:nowrap}
.file-actions{width:112px;flex-shrink:0;display:flex;justify-content:flex-end;gap:3px;opacity:0;transition:opacity .12s;position:relative}
.file-item:hover .file-actions,.note-item:hover .file-actions,.file-actions:focus-within,.file-actions.menu-open{opacity:1}
.act{width:32px;height:32px;border:none;border-radius:8px;background:var(--bg);box-shadow:var(--btn-shadow);color:var(--text);display:inline-flex;align-items:center;justify-content:center;transition:color .12s,background .12s}
.act svg{width:16px;height:16px}
.act:hover{color:var(--accent)}
.act.copied{color:var(--ok)}
.act.save-btn{color:var(--ok)}
.search-snippet{font-size:12px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.note-snippet{font-size:14px;font-weight:500;color:var(--head);line-height:1.45;word-break:break-word;cursor:text;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.note-snippet.editing{display:block;-webkit-line-clamp:none;white-space:pre-wrap;min-height:1.4em;max-height:16rem;overflow:auto;outline:none;background:var(--bg);border-radius:8px;padding:6px 8px;margin:-6px -8px;box-shadow:inset 0 0 0 2px var(--accent)}
.note-item.editing-row .file-actions{opacity:1}
.row-check{display:flex;align-items:center;justify-content:center;flex-shrink:0}
.row-check input{width:18px;height:18px;accent-color:var(--accent);cursor:pointer}
.locked-row{opacity:.55;cursor:pointer}
.locked-row:hover{opacity:.8}
.file-item.is-locked .file-name::after{content:'';display:inline-block;width:7px;height:7px;border-radius:4px;background:var(--muted);margin-left:8px;vertical-align:2px}
.file-item.dragging,.note-item.dragging{opacity:.4}
.file-item.drop-target,.note-item.drop-target{box-shadow:inset 0 0 0 2px var(--accent);background:var(--soft)}
.empty-state{padding:56px 16px;text-align:center;color:var(--muted);font-size:14px}
.empty-state b{display:block;font-size:16px;color:var(--head);margin-bottom:4px}
.drop-hint{margin-top:auto;padding:28px 0 6px;display:flex;justify-content:center;align-items:center;gap:8px;font-size:12.5px;color:var(--muted)}
.drop-hint svg{width:15px;height:15px}
body.compact .file-item,body.compact .note-item{padding-top:5px;padding-bottom:5px}
body.compact .ft-tile{width:32px;height:32px;border-radius:8px}
body.compact .ft-tile svg{width:17px;height:17px}

/* grid view */
.file-list.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(184px,1fr));gap:16px;margin:0}
.file-list.grid .file-item,.file-list.grid .note-item{flex-direction:column;align-items:stretch;gap:10px;padding:8px;border-radius:14px;background:var(--card);box-shadow:var(--shadow)}
.file-list.grid .file-item:hover,.file-list.grid .note-item:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg)}
.file-list.grid .ft-tile{width:auto;height:128px;border-radius:10px}
.file-list.grid .ft-tile svg{width:40px;height:40px}
.file-list.grid .ft-play{display:flex;width:34px;height:34px;border-radius:17px}
.file-list.grid .ft-play svg{width:14px;height:14px}
.file-list.grid .file-info-col,.file-list.grid .note-body{padding:0 4px 4px}
.file-list.grid .col-size,.file-list.grid .col-date,.file-list.grid .meta-list{display:none}
.file-list.grid .meta-grid{display:inline}
.file-list.grid .file-actions{position:absolute;top:14px;right:14px;width:auto}
.file-list.grid .row-check{position:absolute;top:14px;left:14px;z-index:2;background:var(--card);border-radius:6px;padding:3px}
.file-list.grid .note-snippet{font-size:13.5px}
body.compact .file-list.grid{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}
body.compact .file-list.grid .ft-tile{height:100px}

/* ── Menus ──────────────────────────────────────────────────────────────────── */
.row-menu{position:absolute;right:0;top:calc(100% + 4px);z-index:50;background:var(--card);border-radius:12px;min-width:180px;box-shadow:var(--shadow-lg);padding:6px}
.ctx-menu{position:fixed;right:auto;top:auto;z-index:120}
.row-menu-item{display:flex;align-items:center;width:100%;border:none;background:none;border-radius:8px;padding:8px 10px;font-size:13px;font-weight:500;color:var(--text);text-align:left;white-space:nowrap}
.row-menu-item:hover{background:var(--hover);color:var(--head)}
.row-menu-item:disabled{opacity:.4;cursor:default}
.row-menu-item.danger{color:var(--danger)}
.row-menu-item.danger:hover{background:color-mix(in srgb,var(--danger) 12%,transparent);color:var(--danger)}
.ctx-sep{height:1px;background:var(--line);margin:5px 6px}

/* ── Drop overlay & toasts ──────────────────────────────────────────────────── */
#drop-overlay{display:none;position:fixed;inset:12px;z-index:140;border-radius:20px;border:2px dashed var(--accent);background:color-mix(in srgb,var(--accent) 10%,transparent);pointer-events:none;align-items:center;justify-content:center}
body.dragging-files #drop-overlay{display:flex}
.drop-card{background:var(--card);border-radius:16px;box-shadow:var(--shadow-lg);padding:18px 22px;display:flex;align-items:center;gap:12px;font-size:15px;font-weight:600;color:var(--head)}
.drop-card svg{width:22px;height:22px;color:var(--accent)}
#toast-stack{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:150;display:flex;flex-direction:column;align-items:center;gap:8px;pointer-events:none;width:min(440px,calc(100vw - 32px))}
#progress-wrap{display:none;width:100%;background:var(--card);border-radius:14px;box-shadow:var(--shadow-lg);padding:12px 14px;pointer-events:auto}
.prog-row{display:flex;justify-content:space-between;font-size:13px;font-weight:600;color:var(--head);margin-bottom:8px}
#pct{color:var(--muted);font-weight:500}
#bar-track{height:6px;border-radius:3px;background:var(--raised);overflow:hidden}
#bar{height:100%;width:0;background:var(--accent);border-radius:3px;transition:width .1s linear}
#msg{max-width:100%;background:var(--card);color:var(--head);border-radius:12px;box-shadow:var(--shadow-lg);padding:10px 14px;font-size:13px;font-weight:500;opacity:0;transform:translateY(8px);transition:opacity .2s,transform .2s;pointer-events:auto;word-break:break-word;text-align:center}
#msg.show{opacity:1;transform:none}
#msg.ok{box-shadow:var(--shadow-lg),inset 3px 0 0 var(--ok)}
#msg.err{box-shadow:var(--shadow-lg),inset 3px 0 0 var(--danger)}
#msg:empty{display:none}

/* ── Dialogs ────────────────────────────────────────────────────────────────── */
#confirm-modal,#move-modal,#pw-modal,#prompt-modal,#modal,#settings-modal,#note-modal,#qr-modal{display:none;position:fixed;inset:0;background:var(--scrim);backdrop-filter:blur(4px);align-items:center;justify-content:center;padding:20px}
#confirm-modal.open,#move-modal.open,#pw-modal.open,#prompt-modal.open,#modal.open,#settings-modal.open,#note-modal.open,#qr-modal.open{display:flex}
#modal{z-index:100}#settings-modal,#note-modal,#qr-modal{z-index:105}#move-modal,#prompt-modal{z-index:110}#confirm-modal{z-index:130}#pw-modal{z-index:135}
#confirm-box,#move-box,#pw-box,#prompt-box,#note-box,#qr-box{background:var(--card);border-radius:18px;box-shadow:var(--shadow-lg);padding:22px;width:100%;max-width:380px}
#note-box{max-width:560px}
#qr-box{max-width:300px;text-align:center}
#confirm-title,#move-title,#pw-title,#prompt-title,.dlg-title{font-size:16px;font-weight:700;color:var(--head);margin-bottom:12px}
#move-title span{color:var(--accent)}
#confirm-text{font-size:14px;color:var(--text);line-height:1.55;word-break:break-word}
#confirm-text b{color:var(--head)}
.confirm-name{font-size:13px;font-weight:600;color:var(--head);background:var(--side);border-radius:10px;padding:9px 12px;margin-top:10px;word-break:break-all}
#confirm-note{font-size:12.5px;color:var(--muted);margin-top:10px}
#confirm-actions,#move-actions,#pw-actions,#prompt-actions,.dlg-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:20px;flex-wrap:wrap}
#pw-sub{font-size:13px;color:var(--muted);margin:-6px 0 12px;word-break:break-all}
#pw-input,#prompt-input{width:100%;height:42px;padding:0 14px;background:var(--side);border:none;border-radius:11px;font-size:14px;outline:none;box-shadow:inset 0 0 0 1px var(--line)}
#pw-input:focus,#prompt-input:focus{box-shadow:inset 0 0 0 2px var(--accent)}
#pw-err,#prompt-err{font-size:12.5px;color:var(--danger);margin-top:8px;display:none}
#move-crumb{display:flex;align-items:center;flex-wrap:wrap;gap:4px;font-size:13px;color:var(--muted);margin-bottom:10px}
.mc-item{cursor:pointer;padding:2px 6px;border-radius:6px}
.mc-item:hover{background:var(--hover);color:var(--accent)}
.mc-sep{opacity:.5}
#move-list{border-radius:12px;min-height:8rem;max-height:15rem;overflow-y:auto;background:var(--side);padding:4px}
.move-row{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:none;border:none;border-radius:8px;color:var(--text);font-size:13.5px;font-weight:500;padding:9px 10px}
.move-row::before{content:'';width:16px;height:13px;border-radius:3px;background:var(--c-folder);opacity:.85;flex-shrink:0}
.move-row:hover:not(.disabled){background:var(--hover);color:var(--head)}
.move-row.disabled{opacity:.4;cursor:default}
.move-empty{font-size:13px;color:var(--muted);padding:14px}
#note-input{width:100%;min-height:9rem;max-height:50vh;resize:vertical;background:var(--side);border:none;border-radius:12px;padding:14px 16px;font-size:14.5px;line-height:1.6;outline:none;box-shadow:inset 0 0 0 1px var(--line)}
#note-input:focus{box-shadow:inset 0 0 0 2px var(--accent)}
#note-input::placeholder{color:var(--muted)}
.dlg-actions .spacer{flex:1}
.qr-img{width:220px;height:220px;image-rendering:pixelated;background:#fff;padding:10px;border-radius:14px;margin:4px auto 12px;display:block}
.qr-url{font-size:12.5px;color:var(--muted);word-break:break-all}

/* preview */
#modal-box{background:var(--card);border-radius:18px;box-shadow:var(--shadow-lg);max-width:92vw;max-height:92vh;overflow:auto;display:flex;flex-direction:column;min-width:320px}
#modal-header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px 14px 20px;flex-shrink:0}
#modal-filename{font-size:14px;font-weight:600;color:var(--head);word-break:break-all}
#modal-close{width:34px;height:34px;border:none;border-radius:10px;background:var(--side);color:var(--text);display:flex;align-items:center;justify-content:center;flex-shrink:0}
#modal-close:hover{background:var(--raised)}
#modal-content{padding:0 20px;display:flex;align-items:center;justify-content:center;min-height:120px}
#modal-content img{max-width:84vw;max-height:72vh;display:block;border-radius:10px}
#modal-content video{max-width:84vw;max-height:72vh;display:block;border-radius:10px;outline:none;background:#000}
#modal-content audio{width:440px;max-width:80vw;outline:none}
#modal-content iframe{width:76vw;height:72vh;border:none;display:block;border-radius:10px;background:#fff}
#modal-content pre{font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:13px;color:var(--text);white-space:pre-wrap;word-break:break-word;width:min(70vw,680px);max-height:66vh;overflow:auto;line-height:1.7;background:var(--side);border-radius:12px;padding:16px;cursor:text}
#note-edit{width:min(70vw,680px);max-width:100%;height:min(60vh,440px);background:var(--side);border:none;border-radius:12px;font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:13px;line-height:1.7;padding:16px;outline:none;resize:vertical;box-shadow:inset 0 0 0 2px var(--accent)}
#modal-footer{padding:16px 20px;display:flex;justify-content:flex-end;gap:8px;flex-shrink:0}
#modal-copy{display:none}
.prep{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;padding:44px 24px;min-width:280px}
.prep-spin{width:28px;height:28px;border:3px solid var(--raised);border-top-color:var(--accent);border-radius:50%;animation:prep-rot .8s linear infinite}
@keyframes prep-rot{to{transform:rotate(360deg)}}
.prep-msg{font-size:14px;font-weight:600;color:var(--head);text-align:center}
.prep-sub{font-size:12.5px;color:var(--muted);text-align:center}

/* settings */
#settings-box{background:var(--card);border-radius:20px;box-shadow:var(--shadow-lg);width:100%;max-width:600px;max-height:88vh;display:flex;flex-direction:column;overflow:hidden}
.set-head{display:flex;align-items:center;justify-content:space-between;padding:18px 18px 10px 24px}
.set-head .dlg-title{margin:0;font-size:18px}
.set-body{overflow-y:auto;padding:0 24px 24px}
.set-group{padding-top:16px}
.set-group-title{font-size:12px;font-weight:700;color:var(--muted);letter-spacing:.04em;text-transform:uppercase;margin-bottom:6px}
.set-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid var(--line)}
.set-row:last-child{border-bottom:none}
.set-label{font-size:14px;font-weight:600;color:var(--head)}
.set-desc{font-size:12.5px;color:var(--muted);margin-top:2px}
.set-row .seg{flex-shrink:0}
.swatches{display:flex;gap:8px}
.swatch{width:28px;height:28px;border-radius:14px;border:none;box-shadow:inset 0 0 0 1px rgba(0,0,0,.1);position:relative}
.swatch.on{box-shadow:0 0 0 2px var(--card),0 0 0 4px var(--sw)}
.switch{width:42px;height:24px;border-radius:12px;border:none;background:var(--raised);position:relative;flex-shrink:0;transition:background .2s}
.switch::after{content:'';position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:9px;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.3);transition:transform .2s}
.switch[aria-checked=true]{background:var(--accent-fill)}
.switch[aria-checked=true]::after{transform:translateX(18px)}
.set-select{height:34px;border:none;border-radius:9px;background:var(--side);padding:0 10px;font-size:13px;font-weight:600;color:var(--head)}
.set-list{display:flex;flex-direction:column;gap:6px;margin-top:8px;width:100%}
.set-item{display:flex;align-items:center;gap:10px;background:var(--side);border-radius:10px;padding:8px 8px 8px 12px;font-size:13px;min-width:0}
.set-item .nm{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600;color:var(--head)}
.set-item .folder-btn{height:30px;padding:0 10px;font-size:12px;background:var(--card)}
.set-col{flex-direction:column;align-items:stretch}
.set-path{font-size:12px;color:var(--muted);word-break:break-all}

/* ── Phone ──────────────────────────────────────────────────────────────────── */
.bottombar{display:none}
@media (max-width:760px){
  .sidebar{position:fixed;left:0;top:0;bottom:0;width:min(300px,86vw);transform:translateX(-102%);transition:transform .25s cubic-bezier(.2,.8,.2,1);box-shadow:var(--shadow-lg);padding-top:max(18px,env(safe-area-inset-top))}
  body.drawer-open .sidebar{transform:none}
  body.drawer-open #scrim{display:block}
  .topbar{height:58px;padding:0 10px 0 8px;gap:6px;padding-top:env(safe-area-inset-top);height:calc(58px + env(safe-area-inset-top))}
  #menu-toggle{display:inline-flex}
  .breadcrumb{visibility:hidden}
  .cmd{display:none}
  body.search-open .cmd{display:flex;position:fixed;top:calc(8px + env(safe-area-inset-top));left:8px;right:8px;width:auto;max-width:none;height:46px;z-index:70;background:var(--card);box-shadow:var(--shadow-lg)}
  body.search-open #search-close{display:flex}
  body.search-open .kbd{display:none}
  .kbd{display:none}
  #qr-btn{display:none}
  .content{padding:4px 16px calc(110px + env(safe-area-inset-bottom))}
  #folder-title{font-size:24px}
  .folder-head{padding-bottom:14px;align-items:center}
  .folder-actions .lbl{display:none}
  .folder-actions .btn:not(.icon){padding:0 10px}
  .pin-strip{display:flex}
  .list-head,.col-size,.col-date{display:none}
  .file-list{margin:0 -8px}
  .file-item,.note-item{padding:8px}
  .file-actions{opacity:1;width:auto}
  .file-actions .view-btn,.file-actions .dl-btn,.file-actions .copy-btn{display:none}
  .note-item.editing-row .file-actions .copy-btn,.note-item.editing-row .file-actions .view-btn{display:inline-flex}
  .act{background:transparent;box-shadow:none;color:var(--muted)}
  .file-list.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:0}
  .file-list.grid .ft-tile{height:118px}
  .file-list.grid .file-actions{top:12px;right:12px}
  .file-list.grid .act{background:var(--card);box-shadow:var(--btn-shadow);color:var(--text)}
  .drop-hint{display:none}
  #share-banner{flex-direction:column;align-items:flex-start}
  #select-bar{top:66px}
  .bottombar{display:flex;position:fixed;left:50%;transform:translateX(-50%);bottom:calc(14px + env(safe-area-inset-bottom));z-index:30;align-items:center;gap:6px;padding:6px;border-radius:22px;background:color-mix(in srgb,var(--card) 92%,transparent);backdrop-filter:blur(14px);box-shadow:var(--shadow-lg)}
  .bb-btn{height:48px;min-width:64px;border:none;border-radius:16px;background:transparent;color:var(--text);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;font-size:11px;font-weight:600}
  .bb-btn svg{width:20px;height:20px}
  .bb-main{width:60px;min-width:60px;height:52px;border-radius:18px;background:var(--accent-fill);color:#fff;box-shadow:0 4px 14px color-mix(in srgb,var(--accent-fill) 45%,transparent)}
  .bb-main svg{width:24px;height:24px}
  #toast-stack{bottom:calc(92px + env(safe-area-inset-bottom))}
  #modal{padding:10px}
  #modal-content{padding:0 10px}
  #modal-content img,#modal-content video{max-width:94vw}
  #modal-content iframe{width:94vw}
  #settings-modal{align-items:flex-end;padding:0}
  #settings-box{max-width:none;border-radius:20px 20px 0 0;max-height:92vh;padding-bottom:env(safe-area-inset-bottom)}
  .set-row{flex-wrap:wrap}
}
body.share-view .owner-only{display:none!important}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar" id="sidebar" aria-label="Folders">
    <div class="brand">
      <div class="brand-mark"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v12"/><path d="M6.5 11l5.5 5.5 5.5-5.5"/><path d="M5 20h14"/></svg></div>
      <div class="brand-name">FileDrop</div>
    </div>
    <div class="side-actions owner-only">
      <div class="upload-split">
        <button class="btn primary" id="upload-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6.5 12.5L12 7l5.5 5.5"/><path d="M5 4h14"/></svg>Upload</button>
        <button class="btn icon" id="folder-upload-btn" title="Upload a folder" aria-label="Upload a folder"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.6l2 2.2h7.4A2.5 2.5 0 0 1 21 9.7v7.8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/><path d="M12 16.5v-6"/><path d="M9.5 13l2.5-2.5 2.5 2.5"/></svg></button>
      </div>
      <button class="btn" id="new-note-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>New note</button>
      <input type="file" id="file-input" multiple hidden>
      <input type="file" id="folder-input" webkitdirectory directory multiple hidden>
    </div>
    <div class="side-section owner-only" id="pin-section">
      <div class="side-title">Pinned</div>
      <div id="pin-list"><div class="side-empty">Pin files or folders from their menu</div></div>
    </div>
    <div class="side-section" style="flex:1;min-height:0">
      <div class="side-title">Folders</div>
      <div class="tree-wrap" id="tree"></div>
    </div>
    <div class="side-foot">
      <div id="disk-bar-wrap" style="display:none;flex-direction:column;gap:8px">
        <div id="disk-bar-track"><div id="disk-bar-fill" style="width:0%"></div></div>
      </div>
      <div class="disk-meta"><span id="disk-label"></span><span title="{{.UploadDir}}">{{.FooterLabel}} · :{{.Port}}</span></div>
    </div>
  </aside>
  <div id="scrim"></div>

  <div class="main" id="main">
    <header class="topbar">
      <button class="btn icon ghost" id="menu-toggle" aria-label="Open folders"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16"/><path d="M4 12h16"/><path d="M4 17h10"/></svg></button>
      <nav class="breadcrumb" id="breadcrumb" aria-label="Location"></nav>
      <div class="cmd" id="cmd">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
        <input id="search-input" type="search" placeholder="Search files or run a command" autocomplete="off" spellcheck="false" aria-label="Search files or run a command">
        <button id="search-clear" style="display:none" aria-label="Clear search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12"/><path d="M18 6L6 18"/></svg></button>
        <span class="kbd">Ctrl K</span>
        <button class="btn icon ghost" id="search-close" aria-label="Close search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12"/><path d="M18 6L6 18"/></svg></button>
        <div id="cmd-menu" role="listbox"></div>
      </div>
      <div class="top-actions">
        <button class="btn icon ghost owner-only" id="qr-btn" title="Open on your phone" aria-label="Open on your phone"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="6" height="6" rx="1.2"/><rect x="14" y="4" width="6" height="6" rx="1.2"/><rect x="4" y="14" width="6" height="6" rx="1.2"/><path d="M14 14h2v2h-2z"/><path d="M18 18h2v2h-2z"/><path d="M18 14h2"/><path d="M14 18v2"/></svg></button>
        <button class="btn icon ghost" id="theme-btn" aria-label="Switch theme"></button>
        <button class="btn icon ghost" id="settings-btn" title="Settings" aria-label="Settings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg></button>
      </div>
    </header>

    <div class="content">
      <div class="folder-head">
        <div>
          <h1 id="folder-title">All files</h1>
          <div class="folder-meta" id="divider-text">Loading…</div>
        </div>
        <div class="folder-actions">
          <div class="ext-filter">
            <button class="btn" id="ext-btn" onclick="toggleExtMenu(event)" title="Filter by file type" disabled><span id="ext-btn-label">All</span><svg class="ext-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg></button>
            <div class="ext-menu" id="ext-menu"></div>
          </div>
          <button class="btn owner-only" id="share-btn" onclick="startShare()" title="Create a shared folder"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5.5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="18.5" r="2.5"/><path d="M8.2 10.8l7.6-4"/><path d="M8.2 13.2l7.6 4"/></svg><span class="lbl">Share</span></button>
          <button class="btn owner-only" id="newfolder-btn" onclick="openNewFolder()" title="Create a folder"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.6l2 2.2h7.4A2.5 2.5 0 0 1 21 9.7v7.8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/><path d="M12 11v5"/><path d="M9.5 13.5h5"/></svg><span class="lbl">New folder</span></button>
          <button class="btn icon owner-only" id="select-trigger" onclick="enterSelectMode()" title="Select items" aria-label="Select items"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="4"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg></button>
          <div class="seg" role="group" aria-label="View">
            <button id="view-list" aria-label="List view" title="List view"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6h11"/><path d="M9 12h11"/><path d="M9 18h11"/><path d="M4.5 6h.01"/><path d="M4.5 12h.01"/><path d="M4.5 18h.01"/></svg></button>
            <button id="view-grid" aria-label="Grid view" title="Grid view"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.6"/></svg></button>
          </div>
        </div>
      </div>

      <div class="pin-strip owner-only" id="pin-strip"></div>
      <div id="share-banner"></div>
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
      <div id="list-head-slot"></div>
      <div class="file-list" id="file-list"></div>
      <div class="drop-hint owner-only"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6.5 12.5L12 7l5.5 5.5"/><path d="M5 4h14"/></svg>Drop files anywhere to upload</div>
    </div>
  </div>
</div>

<nav class="bottombar" aria-label="Quick actions">
  <button class="bb-btn" id="bb-search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>Search</button>
  <button class="bb-btn bb-main owner-only" id="bb-upload" aria-label="Upload"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6.5 12.5L12 7l5.5 5.5"/><path d="M5 4h14"/></svg></button>
  <button class="bb-btn owner-only" id="bb-note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5V15l-5 5H6.5A2.5 2.5 0 0 1 4 17.5z"/><path d="M8 9h8"/><path d="M8 12.5h5"/></svg>Note</button>
</nav>

<div id="drop-overlay"><div class="drop-card"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V7"/><path d="M6.5 12.5L12 7l5.5 5.5"/><path d="M5 4h14"/></svg><span id="drop-label">Drop to upload</span></div></div>
<div id="toast-stack">
  <div id="progress-wrap">
    <div class="prog-row"><span>Uploading…</span><span id="pct">0%</span></div>
    <div id="bar-track"><div id="bar"></div></div>
  </div>
  <div id="msg" role="status" aria-live="polite"></div>
</div>

<div id="note-modal">
  <div id="note-box">
    <div class="dlg-title">New note</div>
    <textarea id="note-input" placeholder="Write a note, or paste text or an image…"></textarea>
    <div class="dlg-actions">
      <button class="folder-btn" id="paste-btn">Paste</button>
      <span class="spacer"></span>
      <button class="folder-btn" onclick="closeNote()">Cancel</button>
      <button class="folder-btn primary" id="note-submit">Save note</button>
    </div>
  </div>
</div>
<div id="qr-modal">
  <div id="qr-box">
    <div class="dlg-title">Open on your phone</div>
    <img class="qr-img" id="qr-img" alt="QR code for this page">
    <div class="qr-url" id="qr-url"></div>
    <div class="dlg-actions" style="justify-content:center"><button class="folder-btn" onclick="closeQr()">Close</button></div>
  </div>
</div>
<div id="settings-modal">
  <div id="settings-box" role="dialog" aria-label="Settings">
    <div class="set-head"><div class="dlg-title">Settings</div><button class="btn icon ghost" onclick="closeSettings()" aria-label="Close settings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12"/><path d="M18 6L6 18"/></svg></button></div>
    <div class="set-body" id="settings-body"></div>
  </div>
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
    <input id="pw-input" type="password" placeholder="Password" autocomplete="off">
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
    <input id="prompt-input" type="text" placeholder="Folder name" autocomplete="off" spellcheck="false">
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
      <button id="modal-close" onclick="closeModal()" aria-label="Close preview"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12"/><path d="M18 6L6 18"/></svg></button>
    </div>
    <div id="modal-content"></div>
    <div id="modal-footer">
      <button class="folder-btn" id="modal-copy">Copy text</button>
      <button class="folder-btn" id="modal-dl">Download</button>
      <button class="folder-btn" id="modal-cancel" style="display:none">Cancel</button>
      <button class="folder-btn primary" id="modal-save" style="display:none">Save</button>
    </div>
  </div>
</div>

<script>
var R2_MODE = {{if .R2Mode}}true{{else}}false{{end}};
var CAN_PUBLISH = {{if .CanPublish}}true{{else}}false{{end}};
var SHARE_MODE = {{if .ShareMode}}true{{else}}false{{end}};
var SHARE_NAME = "{{.ShareName}}";
var VIDEO_TOOLS = {{if .VideoTools}}true{{else}}false{{end}};
var PRIVATE_SERVER = {{if .Private}}true{{else}}false{{end}};
var LAN_URL = "{{.LanURL}}";

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
  btn.parentElement.classList.add('menu-open');
  activeMenu = menu;
}
function closeMenu() {
  if (activeMenu) {
    if (activeMenu.parentElement) activeMenu.parentElement.classList.remove('menu-open');
    activeMenu.remove();
    activeMenu = null;
  }
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
  if (e.target.closest('input,textarea,select,a,.row-menu,#modal,#prompt-modal,#confirm-modal,#move-modal,#pw-modal,#settings-modal,#note-modal,#qr-modal')) { closeMenu(); return; }
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
  if (!settings.confirmDelete) { bulkDeleteNow(); return; }
  var n = selectedPaths.size;
  showConfirm('Delete ' + n + ' item' + (n !== 1 ? 's' : '') + '?',
    'Are you sure you want to delete ' + (n === 1 ? 'this item' : 'these <b>' + n + '</b> items') + '?' +
    '<div id="confirm-note">This cannot be undone.</div>',
    'Delete', bulkDeleteNow);
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
  if (!settings.confirmDelete) { deleteItemNow(path); return; }
  var what = isDir ? 'folder' : 'file';
  showConfirm(isDir ? 'Delete folder?' : 'Delete file?',
    'Are you sure you want to delete this ' + what + '?' +
    '<div class="confirm-name">' + esc(path.split('/').pop()) + '</div>' +
    '<div id="confirm-note">This cannot be undone' +
    (isDir ? ', and everything inside it goes too.' : '.') + '</div>',
    'Delete', function(){ deleteItemNow(path); });
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
    document.getElementById('disk-label').textContent = fmtSize(d.free) + ' free of ' + fmtSize(d.total);
    wrap.style.display = 'flex';
  }).catch(function(){});
}

// ── Settings (per browser) ────────────────────────────────────────────────────
var SETTINGS_DEFAULTS = {
  theme: 'dark', accent: 'ultramarine', tint: true, density: 'comfortable',
  view: 'list', viewPerFolder: true, sort: 'recent', showExt: true, confirmDelete: true
};
var settings = (function(){
  var s = {};
  try { s = JSON.parse(localStorage.getItem('fd_settings') || '{}') || {}; } catch(e){}
  // carry over the theme chosen before settings existed
  if (!s.theme) { try { if (localStorage.getItem('fd_theme') === 'light') s.theme = 'light'; } catch(e){} }
  var out = {};
  for (var k in SETTINGS_DEFAULTS) out[k] = (s[k] === undefined) ? SETTINGS_DEFAULTS[k] : s[k];
  return out;
})();

function saveSettings() {
  try { localStorage.setItem('fd_settings', JSON.stringify(settings)); } catch(e){}
}

function resolvedTheme() {
  if (settings.theme === 'system') return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  return settings.theme;
}

var SUN_SVG  = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2"/><path d="M12 19.5v2"/><path d="M4.6 4.6l1.4 1.4"/><path d="M18 18l1.4 1.4"/><path d="M2.5 12h2"/><path d="M19.5 12h2"/><path d="M4.6 19.4L6 18"/><path d="M18 6l1.4-1.4"/></svg>';
var MOON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>';

function applySettings() {
  var b = document.body;
  var light = resolvedTheme() === 'light';
  b.classList.toggle('light', light);
  document.documentElement.classList.remove('pre-light');
  b.setAttribute('data-accent', settings.accent);
  b.classList.toggle('tint', !!settings.tint);
  b.classList.toggle('compact', settings.density === 'compact');
  b.classList.toggle('hide-ext', !settings.showExt);
  var tb = document.getElementById('theme-btn');
  if (tb) {
    tb.innerHTML = light ? MOON_SVG : SUN_SVG;
    tb.title = light ? 'Switch to dark mode' : 'Switch to light mode';
    tb.setAttribute('aria-label', tb.title);
  }
}

function setSetting(key, val) {
  settings[key] = val;
  saveSettings();
  applySettings();
  if (key === 'sort' || key === 'view' || key === 'viewPerFolder' || key === 'density' || key === 'showExt') {
    applyView();
    rerender();
  }
}

function toggleTheme() {
  setSetting('theme', resolvedTheme() === 'light' ? 'dark' : 'light');
  if (settingsModal.classList.contains('open')) renderSettings();
}
document.getElementById('theme-btn').addEventListener('click', toggleTheme);
try {
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', function(){
    if (settings.theme === 'system') applySettings();
  });
} catch(e){}
applySettings();

// ── View (list / grid) ─────────────────────────────────────────────────────────
function folderViews() {
  try { return JSON.parse(localStorage.getItem('fd_views') || '{}') || {}; } catch(e){ return {}; }
}
function currentView() {
  if (settings.viewPerFolder) {
    var v = folderViews()[currentPath || '/'];
    if (v === 'list' || v === 'grid') return v;
  }
  return settings.view;
}
function setView(v) {
  if (settings.viewPerFolder) {
    var m = folderViews();
    m[currentPath || '/'] = v;
    try { localStorage.setItem('fd_views', JSON.stringify(m)); } catch(e){}
  } else {
    settings.view = v;
    saveSettings();
  }
  applyView();
  rerender();
}
function applyView() {
  var v = currentView();
  list.classList.toggle('grid', v === 'grid');
  list.classList.toggle('list', v !== 'grid');
  document.getElementById('view-list').classList.toggle('on', v !== 'grid');
  document.getElementById('view-grid').classList.toggle('on', v === 'grid');
}
document.getElementById('view-list').addEventListener('click', function(){ setView('list'); });
document.getElementById('view-grid').addEventListener('click', function(){ setView('grid'); });
applyView();

// ── Toasts ─────────────────────────────────────────────────────────────────────
// Status text is still written straight to #msg everywhere; this turns those
// writes into a toast that fades out, and drops the old "// " terminal prefix.
var msgTimer = null;
new MutationObserver(function(){
  var t = msg.textContent;
  if (t.indexOf('// ') === 0) { msg.textContent = t.charAt(3).toUpperCase() + t.slice(4); return; }
  clearTimeout(msgTimer);
  if (!t) { msg.classList.remove('show'); return; }
  msg.classList.add('show');
  msgTimer = setTimeout(function(){ msg.classList.remove('show'); }, msg.className.indexOf('err') !== -1 ? 7000 : 3500);
}).observe(msg, {childList:true, characterData:true, subtree:true});

// ── Clipboard helper — works on HTTP ─────────────────────────────────────────
function copyText(text, btn, originalLabel) {
  function done() {
    if (!btn) return;
    // icon-only buttons keep their icon and just flash green
    if (btn.classList.contains('act')) {
      btn.classList.add('copied');
      setTimeout(function(){ btn.classList.remove('copied'); }, 1800);
      return;
    }
    btn.textContent = 'Copied';
    setTimeout(function(){ btn.textContent = originalLabel; }, 1800);
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
// Files dragged in from the desktop can be dropped anywhere in the window and
// land in the folder on screen. Folder rows, tree nodes and crumbs register their
// own drop handlers (makeDropTarget) and stop propagation, so dropping onto one
// of those uploads into that folder instead.
var folderInput = document.getElementById('folder-input');
var dragDepth = 0;

function isFileDrag(e) {
  if (dragSrcPath !== null || SHARE_MODE) return false;
  var t = e.dataTransfer && e.dataTransfer.types;
  if (!t) return false;
  for (var i = 0; i < t.length; i++) if (t[i] === 'Files') return true;
  return false;
}
function endFileDrag() { dragDepth = 0; document.body.classList.remove('dragging-files'); }

document.addEventListener('dragenter', function(e){
  if (!isFileDrag(e)) return;
  dragDepth++;
  document.getElementById('drop-label').textContent =
    'Drop to upload to ' + (currentPath ? currentPath.split('/').pop() : (SHARE_MODE ? SHARE_NAME : 'All files'));
  document.body.classList.add('dragging-files');
});
document.addEventListener('dragleave', function(e){
  if (!isFileDrag(e)) return;
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) endFileDrag();
});
document.addEventListener('dragover', function(e){
  if (isFileDrag(e)) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; }
});
document.addEventListener('drop', function(e){
  if (!isFileDrag(e)) { endFileDrag(); return; }
  e.preventDefault();
  endFileDrag();
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
document.addEventListener('dragend', endFileDrag);

fi.addEventListener('change', function(){ upload(fi.files); fi.value=''; });
if (folderInput) folderInput.addEventListener('change', function(){ uploadFileListWithRelPaths(folderInput.files); folderInput.value=''; });
document.getElementById('upload-btn').addEventListener('click', function(){ fi.click(); });
document.getElementById('folder-upload-btn').addEventListener('click', function(){ folderInput.click(); });
document.getElementById('bb-upload').addEventListener('click', function(){ fi.click(); });

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
var noteModal  = document.getElementById('note-modal');

function openNote() {
  closeMenu();
  noteModal.classList.add('open');
  setTimeout(function(){ noteInput.focus(); }, 30);
}
function closeNote() { noteModal.classList.remove('open'); }
document.getElementById('new-note-btn').addEventListener('click', openNote);
document.getElementById('bb-note').addEventListener('click', openNote);
noteModal.addEventListener('click', function(e){ if (e.target === noteModal) closeNote(); });

noteInput.addEventListener('keydown', function(e){
  if (e.key==='Enter' && !e.shiftKey){ e.preventDefault(); saveNote(); }
  else if (e.key === 'Escape') { e.stopPropagation(); closeNote(); }
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
  closeNote();
  upload([named]);
});

// Paste button — reads clipboard if available (HTTPS/localhost), otherwise focuses textarea
pasteBtn.addEventListener('click', function() {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.readText().then(function(text) {
      noteInput.value = text;
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
  pasteBtn.textContent = 'Press Ctrl+V';
  setTimeout(function(){ pasteBtn.textContent = 'Paste'; }, 2000);
}

function saveNote() {
  var text = noteInput.value.trim();
  if (!text) return;
  fetch('/note', {method:'POST', body:text})
    .then(function(r){
      if (r.ok){ noteInput.value=''; closeNote(); msg.className='ok'; msg.textContent='Note saved'; loadFiles(); }
      else { msg.className='err'; msg.textContent='Could not save the note'; }
    })
    .catch(function(){ msg.className='err'; msg.textContent='No connection to the server'; });
}

// ── Folder navigation ─────────────────────────────────────────────────────────
var ROOT_LABEL = SHARE_MODE ? SHARE_NAME : 'All files';
var CHEV_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg>';
var BC_SEP = '<span class="bc-sep"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg></span>';

function joinPath(a, b) { return a ? a + '/' + b : b; }

function navigateTo(path) {
  listSeq++;   // discard any listing still in flight for the old folder
  currentPath = path;
  renderShareBanner();
  extFilter = null;
  closeExtMenu();
  renderBreadcrumb();
  revealInTree(path);
  renderTree();
  applyView();
  loadFiles();
  document.getElementById('main').scrollTop = 0;
}

function renderBreadcrumb() {
  if (!breadcrumbEl) return;
  var parts = currentPath ? currentPath.split('/').filter(Boolean) : [];
  var html = parts.length
    ? '<span class="bc-item" data-path="">' + esc(ROOT_LABEL) + '</span>'
    : '<span class="bc-item bc-current">' + esc(ROOT_LABEL) + '</span>';
  var cumPath = '';
  for (var i = 0; i < parts.length; i++) {
    cumPath += (cumPath ? '/' : '') + parts[i];
    html += BC_SEP;
    if (i === parts.length - 1) html += '<span class="bc-item bc-current">' + esc(parts[i]) + '</span>';
    else html += '<span class="bc-item" data-path="' + esc(cumPath) + '">' + esc(parts[i]) + '</span>';
  }
  breadcrumbEl.innerHTML = html;
  breadcrumbEl.querySelectorAll('[data-path]').forEach(function(el) {
    el.addEventListener('click', function() { clearSearch(); navigateTo(this.dataset.path); });
    makeDropTarget(el, el.dataset.path);   // drop onto a crumb to move up a level
  });
  var title = parts.length ? parts[parts.length - 1] : ROOT_LABEL;
  document.getElementById('folder-title').textContent = title;
  document.title = (parts.length ? title + ' · ' : '') + 'FileDrop';
}

// ── Sidebar: folder tree ──────────────────────────────────────────────────────
// Children load lazily, one folder at a time, so a deep tree costs nothing until
// it is opened. The listing of the folder on screen also refreshes its node.
var treeEl = document.getElementById('tree');
var treeKids = {};          // path -> sorted child folder names
var treeOpen = {'': true};
var treeLoading = {};

function setTreeKids(path, files) {
  var dirs = [];
  (files || []).forEach(function(f){
    if (f.is_dir && !(f.locked && !f.unlocked)) dirs.push(f.name.split('/').pop());
  });
  dirs.sort(function(a, b){ return a.localeCompare(b, undefined, {numeric:true, sensitivity:'base'}); });
  var prev = treeKids[path];
  treeKids[path] = dirs;
  return !prev || prev.join('\n') !== dirs.join('\n');
}

function loadTreeKids(path) {
  if (treeLoading[path]) return;
  treeLoading[path] = true;
  fetch('/files' + (path ? '?path=' + encodeURIComponent(path) : ''))
    .then(function(r){ return r.ok ? r.json() : []; })
    .then(function(files){ treeLoading[path] = false; setTreeKids(path, files); renderTree(); })
    .catch(function(){ treeLoading[path] = false; });
}

function renderTree() {
  var html = [];
  function walk(path, label, depth) {
    var kids = treeKids[path];
    var open = !!treeOpen[path];
    var leaf = kids && kids.length === 0;
    html.push('<div class="tree-row' + (path === currentPath ? ' active' : '') + '" data-path="' + esc(path) +
      '" style="padding-left:' + (2 + depth * 16) + 'px">' +
      '<button class="tree-chev' + (open ? ' open' : '') + (leaf ? ' leaf' : '') + '" data-toggle="' + esc(path) +
      '" aria-label="' + (open ? 'Collapse ' : 'Expand ') + esc(label) + '">' + CHEV_SVG + '</button>' +
      '<span class="ico">' + typeIcon('folder') + '</span><span class="nm">' + esc(label) + '</span></div>');
    if (open && kids) kids.forEach(function(n){ walk(joinPath(path, n), n, depth + 1); });
  }
  walk('', ROOT_LABEL, 0);
  treeEl.innerHTML = html.join('');
  treeEl.querySelectorAll('.tree-row').forEach(function(row){
    var p = row.getAttribute('data-path');
    row.addEventListener('click', function(e){
      if (e.target.closest('.tree-chev')) return;
      closeDrawer();
      if (p !== currentPath || (searchInput && searchInput.value)) { clearSearch(); navigateTo(p); }
    });
    makeDropTarget(row, p);
  });
  treeEl.querySelectorAll('.tree-chev').forEach(function(b){
    b.addEventListener('click', function(e){
      e.stopPropagation();
      var p = b.getAttribute('data-toggle');
      treeOpen[p] = !treeOpen[p];
      if (treeOpen[p] && !treeKids[p]) loadTreeKids(p);
      renderTree();
    });
  });
}

// Opens every ancestor of path so the folder on screen is always visible.
function revealInTree(path) {
  var parts = path ? path.split('/') : [];
  var cum = '';
  treeOpen[''] = true;
  if (!treeKids['']) loadTreeKids('');
  for (var i = 0; i < parts.length - 1; i++) {
    cum = joinPath(cum, parts[i]);
    treeOpen[cum] = true;
    if (!treeKids[cum]) loadTreeKids(cum);
  }
}

// ── Sidebar: pinned items ─────────────────────────────────────────────────────
var pinsCache = [];
function loadPins() {
  if (!PRIVATE_SERVER || SHARE_MODE) return;
  fetch('/pins').then(function(r){ return r.ok ? r.json() : []; })
    .then(function(p){ pinsCache = p || []; renderPins(); })
    .catch(function(){});
}
function renderPins() {
  var side = document.getElementById('pin-list');
  var strip = document.getElementById('pin-strip');
  if (!pinsCache.length) {
    side.innerHTML = '<div class="side-empty">Pin files or folders from their menu</div>';
    strip.innerHTML = '';
    strip.classList.add('hidden');
    return;
  }
  var rows = '', chips = '';
  pinsCache.forEach(function(p, i){
    var name = p.path.split('/').pop();
    var k = p.is_dir ? 'folder' : (p.is_note ? 'note' : kindOf(extOf(name)));
    var ico = '<span style="color:var(--k);display:flex">' + typeIcon(k) + '</span>';
    rows += '<div class="side-row k-' + k + '" data-i="' + i + '" title="' + esc(p.path) + '">' + ico + '<span class="nm">' + esc(name) + '</span></div>';
    chips += '<button class="pin-chip k-' + k + '" data-i="' + i + '">' + ico + esc(name) + '</button>';
  });
  side.innerHTML = rows;
  strip.innerHTML = chips;
  strip.classList.remove('hidden');
  [side, strip].forEach(function(root){
    root.querySelectorAll('[data-i]').forEach(function(el){
      el.addEventListener('click', function(){ openPinned(pinsCache[+el.getAttribute('data-i')]); });
    });
  });
}
function openPinned(p) {
  if (!p) return;
  closeDrawer();
  clearSearch();
  if (p.is_dir) { navigateTo(p.path); return; }
  var parent = parentOf(p.path);
  if (parent !== currentPath) navigateTo(parent);
  if (p.is_note) openNotePreview(p.path); else openPreview(p.path);
}

// ── Phone drawer ──────────────────────────────────────────────────────────────
function openDrawer() { document.body.classList.add('drawer-open'); }
function closeDrawer() { document.body.classList.remove('drawer-open'); }
document.getElementById('menu-toggle').addEventListener('click', openDrawer);
document.getElementById('scrim').addEventListener('click', closeDrawer);

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
    if (setTreeKids(forPath, files)) renderTree();
    // a search owns the list: refresh its results instead of swapping in the folder
    var q = searchInput ? searchInput.value.trim() : '';
    if (q) { loadSearch(q); return; }
    currentFiles = files || [];
    lastFilesJSON = JSON.stringify(files);
    renderList(currentFiles);
  }).catch(function(){
    if (seq !== listSeq || forPath !== currentPath) return;
    list.innerHTML = '<div class="empty-state"><b>Could not load this folder</b>Check the connection and reload</div>';
  });
  loadPins();
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
  promptErr.textContent = t.charAt(0).toUpperCase() + t.slice(1);
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

// Pinned items stay on top whatever the sort; within each group the chosen key
// applies. "recent" keeps the server's order, which is already newest-first.
function sortFiles(files) {
  if (settings.sort === 'recent') return files;
  var key = settings.sort;
  var cmpName = function(a, b){ return a.name.localeCompare(b.name, undefined, {numeric:true, sensitivity:'base'}); };
  var cmp = {
    name: cmpName,
    size: function(a, b){ return (b.is_dir ? -1 : (b.size || 0)) - (a.is_dir ? -1 : (a.size || 0)) || cmpName(a, b); },
    type: function(a, b){
      var ka = a.is_dir ? '0' : (a.is_note ? '1' : extOf(a.name) || '~');
      var kb = b.is_dir ? '0' : (b.is_note ? '1' : extOf(b.name) || '~');
      return ka < kb ? -1 : ka > kb ? 1 : cmpName(a, b);
    }
  }[key];
  if (!cmp) return files;
  var pinned = files.filter(function(f){ return f.pinned; });
  var rest = files.filter(function(f){ return !f.pinned; });
  return pinned.concat(rest.slice().sort(cmp));
}

var listHeadSlot = document.getElementById('list-head-slot');
function renderListHead(show) {
  listHeadSlot.innerHTML = show && currentView() !== 'grid'
    ? '<div class="list-head"><span style="width:40px"></span><span class="lh-name">Name</span>' +
      '<span class="col-size">Size</span><span class="col-date">Modified</span><span style="width:112px"></span></div>'
    : '';
}

function renderList(files) {
  files = files || [];
  syncExtMenu(files);
  var shown = sortFiles(visibleFiles(files));
  list.innerHTML = '';
  if (!shown.length) {
    renderListHead(false);
    if (extFilter !== null) {
      divT.textContent = extFilter ? 'No ' + extLabel(extFilter) + ' files here'
                                   : 'No files without an extension here';
      list.innerHTML = '<div class="empty-state"><b>Nothing matches this filter</b>Pick another type above</div>';
    } else {
      divT.textContent = 'Empty folder';
      list.innerHTML = SHARE_MODE
        ? '<div class="empty-state"><b>This folder is empty</b></div>'
        : '<div class="empty-state"><b>Nothing here yet</b>Drop files anywhere, or use Upload</div>';
    }
    return;
  }
  renderListHead(true);
  divT.textContent = countLabel(shown) || 'Empty';
  appendRows(shown);
}

function renderSearchList(files, q) {
  files = files || [];
  syncExtMenu(files);
  var shown = sortFiles(visibleFiles(files));
  list.innerHTML = '';
  document.getElementById('folder-title').textContent = 'Search';
  if (!shown.length) {
    renderListHead(false);
    divT.textContent = 'No results for "' + q + '"';
    list.innerHTML = '<div class="empty-state"><b>No results</b>Nothing matched "' + esc(q) + '"</div>';
    return;
  }
  renderListHead(true);
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
    endFileDrag();
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
  addPinAction(a, p);
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
  addPinAction(a, p);
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
      moveList.innerHTML = html || '<div class="move-empty">No subfolders here</div>';
      var rows = moveList.querySelectorAll('[data-into]');
      for (var k = 0; k < rows.length; k++) {
        rows[k].addEventListener('click', function(){ moveDest = this.getAttribute('data-into'); renderMoveList(); });
      }
    })
    .catch(function(){ moveList.innerHTML = '<div class="move-empty">Could not load folders</div>'; });
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
  pwErr.textContent = t.charAt(0).toUpperCase() + t.slice(1);
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

function pinStateOf(path) {
  for (var i = 0; i < currentFiles.length; i++) {
    var full = currentPath ? currentPath + '/' + currentFiles[i].name : currentFiles[i].name;
    if (full === path) return currentFiles[i];
  }
  return null;
}

function pinItem(p) {
  fetch('/pin?name=' + encodeURIComponent(p), {method:'POST'})
    .then(function(r){
      if (r.ok) { msg.className='ok'; msg.textContent='// pinned ' + p.split('/').pop(); loadFiles(); return; }
      r.text().then(function(t){ msg.className='err'; msg.textContent='// ' + (t.trim() || 'could not pin'); });
    })
    .catch(function(){ msg.className='err'; msg.textContent='// network error'; });
}

function unpinItem(p) {
  fetch('/unpin?name=' + encodeURIComponent(p), {method:'POST'})
    .then(function(r){
      if (r.ok) { msg.className='ok'; msg.textContent='// unpinned ' + p.split('/').pop(); loadFiles(); return; }
      r.text().then(function(t){ msg.className='err'; msg.textContent='// ' + (t.trim() || 'could not unpin'); });
    })
    .catch(function(){ msg.className='err'; msg.textContent='// network error'; });
}

function addPinAction(a, p) {
  if (!PRIVATE_SERVER) return;
  var st = pinStateOf(p);
  if (st && st.pinned) a.push({label:'Unpin', fn:function(){ unpinItem(p); }});
  else a.push({label:'Pin', fn:function(){ pinItem(p); }});
}

// A still-locked entry: greyed, and inert apart from the click that asks for the
// password. No menu, no drag, no selection — there is nothing to act on yet.
function makeLockedRow(f) {
  var el = document.createElement('div');
  el.className = 'file-item locked-row k-lock';
  var p = currentPath ? currentPath + '/' + f.name : f.name;
  var label = (f.is_dir ? 'Locked folder' : 'Locked') + ' · click to unlock';
  el.innerHTML =
    '<div class="ft-tile">' + typeIcon('lock') + '</div>' +
    '<div class="file-info-col">' +
      '<div class="file-name">' + esc(f.name.split('/').pop()) + '</div>' +
      '<div class="file-type-date">' + label + '</div>' +
    '</div>' +
    '<div class="col-size"></div><div class="col-date"></div>' +
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
  var forPath = currentPath;
  fetch('/share-info?name=' + encodeURIComponent(forPath))
    .then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){
      if (forPath !== currentPath) return;
      if (!d || !d.url) { wrap.style.display = 'none'; return; }
      wrap.style.display = 'flex';
      wrap.innerHTML =
        '<img class="share-qr" src="/qr.png?data=' + encodeURIComponent(d.url) + '" alt="QR code for the share link">' +
        '<div class="share-info">' +
          '<div class="share-title">This folder is shared</div>' +
          '<div class="share-url">' + esc(d.url) + '</div>' +
          '<div class="share-links"><button class="folder-btn primary share-copy">Copy link</button>' +
          '<button class="folder-btn share-stop">Stop sharing</button></div>' +
        '</div>';
      wrap.querySelector('.share-copy').addEventListener('click', function(){
        copyText(d.url, this, 'Copy link');
      });
      wrap.querySelector('.share-stop').addEventListener('click', function(){
        fetch('/unshare?name=' + encodeURIComponent(forPath), {method:'POST'})
          .then(function(r){
            if (!r.ok) throw new Error();
            msg.className = 'ok'; msg.textContent = 'Stopped sharing ' + forPath.split('/').pop();
            renderShareBanner();
          })
          .catch(function(){ msg.className = 'err'; msg.textContent = 'Could not stop sharing'; });
      });
    })
    .catch(function(){ wrap.style.display = 'none'; });
}

// ── Icons & file kinds ────────────────────────────────────────────────────────
var ICON_PATHS = {
  folder: '<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.6l2 2.2h7.4A2.5 2.5 0 0 1 21 9.7v7.8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z" fill="currentColor" fill-opacity=".18"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="4"/><circle cx="9" cy="9" r="1.8"/><path d="M21 15.5l-4.8-4.8L5.5 21"/>',
  video: '<rect x="2.5" y="5.5" width="14" height="13" rx="3"/><path d="M16.5 10.2l5-3v9.6l-5-3z"/>',
  audio: '<path d="M9 18V5.5l11-2V16"/><circle cx="6" cy="18" r="3"/><circle cx="17" cy="16" r="3"/>',
  pdf: '<path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8z"/><path d="M14 3v5h5"/><path d="M8.5 15.5h7"/><path d="M8.5 12h3"/>',
  doc: '<path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8z"/><path d="M14 3v5h5"/><path d="M8.5 12.5h7"/><path d="M8.5 16h7"/>',
  note: '<path d="M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5V15l-5 5H6.5A2.5 2.5 0 0 1 4 17.5z"/><path d="M15 20v-3.5a1.5 1.5 0 0 1 1.5-1.5H20"/><path d="M8 9h8"/><path d="M8 12.5h5"/>',
  archive: '<rect x="3" y="4" width="18" height="5" rx="1.5"/><path d="M5 9v9.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V9"/><path d="M10 13h4"/>',
  code: '<path d="M8.5 8l-4.5 4 4.5 4"/><path d="M15.5 8l4.5 4-4.5 4"/><path d="M13.5 5l-3 14"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>'
};
function typeIcon(k) {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
         (ICON_PATHS[k] || ICON_PATHS.doc) + '</svg>';
}
function svgIcon(body, fill) {
  return '<svg viewBox="0 0 24 24" fill="' + (fill ? 'currentColor' : 'none') + '" stroke="' + (fill ? 'none' : 'currentColor') +
         '" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' + body + '</svg>';
}
var SVG = {
  eye:   svgIcon('<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>'),
  dl:    svgIcon('<path d="M12 4v11"/><path d="M7 10.5l5 5 5-5"/><path d="M5 20h14"/>'),
  more:  svgIcon('<circle cx="5.5" cy="12" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="18.5" cy="12" r="1.7"/>', true),
  open:  svgIcon('<path d="M9 6l6 6-6 6"/>'),
  copy:  svgIcon('<rect x="8.5" y="8.5" width="11" height="11" rx="2.5"/><path d="M15.5 8.5V6.5A2 2 0 0 0 13.5 4.5h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2"/>'),
  check: svgIcon('<path d="M5 12.5l4.5 4.5L19 7.5"/>'),
  x:     svgIcon('<path d="M6 6l12 12"/><path d="M18 6L6 18"/>'),
  play:  svgIcon('<path d="M8 5.5v13l11-6.5z"/>', true),
  pin:   svgIcon('<path d="M15 3l6 6-3 1-3.5 3.5L14 18l-2 2-8-8 2-2 4.5-.5L14 6z"/>', true)
};
var IMG_THUMB_EXTS = ['jpg','jpeg','png','gif','webp','svg'];
function kindOf(ext) {
  if (IMG_THUMB_EXTS.indexOf(ext) !== -1 || ['bmp','avif','heic','tiff'].indexOf(ext) !== -1) return 'image';
  if (['mp4','webm','mov','m4v','mkv','avi','wmv','flv','ts','m2ts','mpg','mpeg'].indexOf(ext) !== -1) return 'video';
  if (['mp3','wav','ogg','flac','aac','m4a','opus'].indexOf(ext) !== -1) return 'audio';
  if (ext === 'pdf') return 'pdf';
  if (['zip','rar','7z','tar','gz','bz2','xz','iso','apk','dmg'].indexOf(ext) !== -1) return 'archive';
  if (['js','go','py','rs','kt','java','c','cpp','h','cs','css','html','json','sh','ps1','yml','yaml','xml','sql','rb','php','swift','env'].indexOf(ext) !== -1) return 'code';
  return 'doc';
}
// The type icon sits underneath; a thumbnail that loads covers it, one that
// fails removes itself and the icon shows through.
function tileInner(ext, path, kind) {
  if (IMG_THUMB_EXTS.indexOf(ext) !== -1)
    return typeIcon('image') + '<img src="/file?name=' + encodeURIComponent(path) + '" alt="" loading="lazy" onerror="this.remove()">';
  if (kind === 'video' && VIDEO_TOOLS && thumbExts.indexOf(ext) !== -1)
    return typeIcon('video') + '<img src="/thumb?name=' + encodeURIComponent(path) + '" alt="" loading="lazy"' +
           ' onload="this.parentNode.querySelector(\'.ft-play\').style.visibility=\'visible\'" onerror="this.remove()">' +
           '<span class="ft-play" style="visibility:hidden">' + SVG.play + '</span>';
  return typeIcon(kind);
}
function pinIco(f) { return f.pinned ? '<span class="pin-ico" title="Pinned">' + SVG.pin + '</span>' : ''; }

function makeDirRow(f) {
  var el = document.createElement('div');
  el.className = 'file-item dir-item k-folder';
  el.style.cursor = 'pointer';
  var dirPath = currentPath ? currentPath+'/'+f.name : f.name;
  var displayName = f.name.split('/').pop();
  var parentDir = f.name.includes('/') ? f.name.slice(0, f.name.lastIndexOf('/')) : '';
  var checkHtml = selectMode ? '<label class="row-check"><input type="checkbox"'+(selectedPaths.has(dirPath)?' checked':'')+' data-path="'+esc(dirPath)+'" aria-label="Select folder"></label>' : '';
  var when = fmtDate(f.modified);
  el.innerHTML =
    checkHtml+
    '<div class="ft-tile">'+typeIcon('folder')+'</div>'+
    '<div class="file-info-col">'+
      '<div class="file-name">'+esc(displayName)+pinIco(f)+'</div>'+
      '<div class="file-type-date"><span class="meta-list">Folder'+(parentDir?' · '+esc(parentDir):'')+'</span>'+
        '<span class="meta-grid">Folder'+(when?' · '+when:'')+'</span></div>'+
    '</div>'+
    '<div class="col-size">—</div>'+
    '<div class="col-date">'+when+'</div>'+
    '<div class="file-actions">'+
      '<button class="act view-btn" title="Open" aria-label="Open">'+SVG.open+'</button>'+
      (!R2_MODE ? '<button class="act dl-btn" title="Download as zip" aria-label="Download as zip">'+SVG.dl+'</button>' : '')+
      '<button class="act menu-btn" title="More" aria-label="More actions">'+SVG.more+'</button>'+
    '</div>';
  if (selectMode) {
    var cb = el.querySelector('input[type=checkbox]');
    el.addEventListener('click', function(e) {
      if (e.target.tagName==='BUTTON'||e.target.tagName==='INPUT'||e.target.tagName==='LABEL') return;
      cb.checked = !cb.checked; toggleSelect(dirPath, cb.checked);
    });
    cb.addEventListener('change', function() { toggleSelect(dirPath, this.checked); });
  } else {
    var enterDir = (function(p){ return function(){ clearSearch(); navigateTo(p); }; })(dirPath);
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
  row.classList.toggle('editing-row', editing);
  if (editing) {
    copy.innerHTML = SVG.check; copy.title = 'Save'; copy.setAttribute('aria-label', 'Save');
    view.innerHTML = SVG.x;     view.title = 'Cancel'; view.setAttribute('aria-label', 'Cancel');
    copy.classList.add('save-btn');
  } else {
    copy.innerHTML = SVG.copy;  copy.title = 'Copy text'; copy.setAttribute('aria-label', 'Copy text');
    view.innerHTML = SVG.eye;   view.title = 'Open'; view.setAttribute('aria-label', 'Open');
    copy.classList.remove('save-btn');
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
  el.className = 'note-item k-note';
  var notePath = currentPath ? currentPath+'/'+f.name : f.name;
  var parentDir = f.name.includes('/') ? f.name.slice(0, f.name.lastIndexOf('/')) : '';
  var checkHtml = selectMode ? '<label class="row-check"><input type="checkbox"'+(selectedPaths.has(notePath)?' checked':'')+' data-path="'+esc(notePath)+'" aria-label="Select note"></label>' : '';
  var when = fmtDate(f.modified);
  el.innerHTML =
    checkHtml+
    '<div class="ft-tile">'+typeIcon('note')+'</div>'+
    '<div class="note-body">'+
      '<div class="note-snippet">'+esc(f.snippet||'')+'</div>'+
      '<div class="note-meta">Note'+pinIco(f)+(when?' · '+when:'')+(parentDir?' · '+esc(parentDir):'')+'</div>'+
    '</div>'+
    '<div class="col-size">'+fmtSize(f.size||0)+'</div>'+
    '<div class="col-date">'+when+'</div>'+
    '<div class="file-actions note-actions">'+
      '<button class="act copy-btn" title="Copy text" aria-label="Copy text">'+SVG.copy+'</button>'+
      '<button class="act view-btn" title="Open" aria-label="Open">'+SVG.eye+'</button>'+
      '<button class="act menu-btn" title="More" aria-label="More actions">'+SVG.more+'</button>'+
    '</div>';
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
          copyText(text, btn, '');
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
  var checkHtml = selectMode ? '<label class="row-check"><input type="checkbox"'+(selectedPaths.has(filePath)?' checked':'')+' data-path="'+esc(filePath)+'" aria-label="Select file"></label>' : '';
  var tk = kindOf(ext);
  var el = document.createElement('div');
  el.className = 'file-item k-' + tk;
  var when = fmtDate(f.modified);
  var where = parentDir ? ' · '+esc(parentDir) : '';
  el.innerHTML =
    checkHtml+
    '<div class="ft-tile">'+tileInner(ext, filePath, tk)+'</div>'+
    '<div class="file-info-col">'+
      '<div class="file-name">'+esc(base)+'<span class="file-name-ext">'+(ext?'.'+esc(ext):'')+'</span>'+pinIco(f)+'</div>'+
      '<div class="file-type-date"><span class="meta-list">'+fileType(ext)+where+'</span>'+
        '<span class="meta-grid">'+fmtSize(f.size)+(when?' · '+when:'')+'</span></div>'+
      (f.snippet?'<div class="search-snippet">'+esc(f.snippet)+'</div>':'')+
    '</div>'+
    '<div class="col-size">'+fmtSize(f.size)+'</div>'+
    '<div class="col-date">'+when+'</div>'+
    '<div class="file-actions">'+
      (canOpen ? '<button class="act view-btn" title="Preview" aria-label="Preview">'+SVG.eye+'</button>' : '')+
      '<button class="act dl-btn" title="Download" aria-label="Download">'+SVG.dl+'</button>'+
      '<button class="act menu-btn" title="More" aria-label="More actions">'+SVG.more+'</button>'+
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
      '<div class="prep-sub">Use Download, or open it in a video app</div></div>';
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
            '<div class="prep-sub">This format needs re-encoding, which can take a few minutes</div></div>';
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

// ── Search & command bar ──────────────────────────────────────────────────────
// Search spans the whole tree and returns paths relative to the root, so while
// it is active the root is the working folder; the folder you searched from is
// restored when the search is cleared.
var searchInput = document.getElementById('search-input');
var searchClear = document.getElementById('search-clear');
var cmdMenu = document.getElementById('cmd-menu');
var searchTimer = null;
var searchHome = null;
var cmdIndex = -1;

function beginSearchScope() { if (searchHome === null) { searchHome = currentPath; currentPath = ''; } }
function endSearchScope() { if (searchHome !== null) { currentPath = searchHome; searchHome = null; } }

function clearSearch() {
  clearTimeout(searchTimer);
  var had = !!searchInput.value;
  searchInput.value = '';
  searchClear.style.display = 'none';
  endSearchScope();
  if (had) renderBreadcrumb();
}

searchInput.addEventListener('input', function() {
  var q = this.value.trim();
  searchClear.style.display = q ? '' : 'none';
  cmdIndex = -1;
  renderCmdMenu();
  clearTimeout(searchTimer);
  searchTimer = setTimeout(function() {
    if (q) { beginSearchScope(); loadSearch(q); }
    else { endSearchScope(); renderBreadcrumb(); loadFiles(); }
  }, 300);
});

searchClear.addEventListener('click', function() {
  clearSearch();
  loadFiles();
  searchInput.focus();
});

function loadSearch(q) {
  fetch('/search?q='+encodeURIComponent(q))
    .then(function(r){return r.json();})
    .then(function(files){
      if (searchInput.value.trim() !== q) return;   // typed on since
      currentFiles = files || [];
      renderSearchList(currentFiles, q);
    })
    .catch(function(){ list.innerHTML='<div class="empty-state"><b>Search failed</b>Try again in a moment</div>'; });
}

var CMD_ICON = {
  upload: svgIcon('<path d="M12 19V7"/><path d="M6.5 12.5L12 7l5.5 5.5"/><path d="M5 4h14"/>'),
  folder: svgIcon('<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.6l2 2.2h7.4A2.5 2.5 0 0 1 21 9.7v7.8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/><path d="M12 11v5"/><path d="M9.5 13.5h5"/>'),
  note: svgIcon('<path d="M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5V15l-5 5H6.5A2.5 2.5 0 0 1 4 17.5z"/><path d="M8 9h8"/><path d="M8 12.5h5"/>'),
  share: svgIcon('<circle cx="18" cy="5.5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="18.5" r="2.5"/><path d="M8.2 10.8l7.6-4"/><path d="M8.2 13.2l7.6 4"/>'),
  select: svgIcon('<rect x="4" y="4" width="16" height="16" rx="4"/><path d="M8.5 12l2.5 2.5 4.5-5"/>'),
  grid: svgIcon('<rect x="4" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.6"/>'),
  list: svgIcon('<path d="M9 6h11"/><path d="M9 12h11"/><path d="M9 18h11"/><path d="M4.5 6h.01"/><path d="M4.5 12h.01"/><path d="M4.5 18h.01"/>'),
  theme: svgIcon('<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>'),
  phone: svgIcon('<rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M11 18h2"/>'),
  gear: svgIcon('<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3"/><path d="M12 18.5v3"/><path d="M2.5 12h3"/><path d="M18.5 12h3"/><path d="M5.3 5.3l2.1 2.1"/><path d="M16.6 16.6l2.1 2.1"/><path d="M5.3 18.7l2.1-2.1"/><path d="M16.6 7.4l2.1-2.1"/>')
};
var COMMANDS = [
  {label:'Upload files', icon:'upload', owner:true, run:function(){ fi.click(); }},
  {label:'Upload a folder', icon:'upload', owner:true, run:function(){ folderInput.click(); }},
  {label:'New note', icon:'note', owner:true, run:function(){ openNote(); }},
  {label:'New folder', icon:'folder', owner:true, run:function(){ openNewFolder(); }},
  {label:'Share a new folder', icon:'share', owner:true, run:function(){ startShare(); }},
  {label:'Select items', icon:'select', owner:true, run:function(){ if (!selectMode) enterSelectMode(); }},
  {label:'Grid view', icon:'grid', run:function(){ setView('grid'); }},
  {label:'List view', icon:'list', run:function(){ setView('list'); }},
  {label:'Switch light / dark', icon:'theme', run:function(){ toggleTheme(); }},
  {label:'Open on your phone', icon:'phone', owner:true, run:function(){ openQr(); }},
  {label:'Settings', icon:'gear', run:function(){ openSettings(); }}
];

function matchingCommands() {
  var q = searchInput.value.trim().toLowerCase();
  return COMMANDS.filter(function(c){
    if (c.owner && SHARE_MODE) return false;
    return !q || c.label.toLowerCase().indexOf(q) !== -1;
  });
}

function renderCmdMenu() {
  if (document.activeElement !== searchInput) { cmdMenu.classList.remove('open'); return; }
  var cmds = matchingCommands();
  if (!cmds.length) { cmdMenu.classList.remove('open'); return; }
  if (cmdIndex >= cmds.length) cmdIndex = cmds.length - 1;
  var html = '<div class="cmd-head">' + (searchInput.value.trim() ? 'Actions' : 'Actions — or type to search files') + '</div>';
  cmds.forEach(function(c, i){
    html += '<button class="cmd-item' + (i === cmdIndex ? ' on' : '') + '" data-i="' + i + '" role="option">' +
            CMD_ICON[c.icon] + esc(c.label) + '</button>';
  });
  cmdMenu.innerHTML = html;
  cmdMenu.classList.add('open');
  cmdMenu.querySelectorAll('[data-i]').forEach(function(b){
    // mousedown so it fires before the input loses focus and hides the menu
    b.addEventListener('mousedown', function(e){ e.preventDefault(); runCmd(cmds[+b.getAttribute('data-i')]); });
  });
}

function runCmd(c) {
  var wasSearching = !!searchInput.value.trim();
  clearSearch();
  if (wasSearching) loadFiles();
  cmdMenu.classList.remove('open');
  searchInput.blur();
  closeSearchUI();
  c.run();
}

function openSearch() {
  document.body.classList.add('search-open');
  searchInput.focus();
  renderCmdMenu();
}
function closeSearchUI() {
  document.body.classList.remove('search-open');
  cmdMenu.classList.remove('open');
}

searchInput.addEventListener('focus', function(){ cmdIndex = -1; renderCmdMenu(); });
searchInput.addEventListener('blur', function(){ setTimeout(function(){ cmdMenu.classList.remove('open'); }, 120); });
searchInput.addEventListener('keydown', function(e){
  var cmds = matchingCommands();
  if (e.key === 'ArrowDown' && cmds.length) { e.preventDefault(); cmdIndex = (cmdIndex + 1) % cmds.length; renderCmdMenu(); }
  else if (e.key === 'ArrowUp' && cmds.length) { e.preventDefault(); cmdIndex = cmdIndex <= 0 ? cmds.length - 1 : cmdIndex - 1; renderCmdMenu(); }
  else if (e.key === 'Enter') {
    e.preventDefault();
    if (cmdIndex >= 0 && cmds[cmdIndex]) { runCmd(cmds[cmdIndex]); return; }
    cmdMenu.classList.remove('open');
    var q = searchInput.value.trim();
    if (q) { clearTimeout(searchTimer); beginSearchScope(); loadSearch(q); }
  }
  else if (e.key === 'Escape') {
    e.stopPropagation();
    if (cmdMenu.classList.contains('open')) { cmdMenu.classList.remove('open'); return; }
    if (searchInput.value) { clearSearch(); loadFiles(); return; }
    searchInput.blur();
    closeSearchUI();
  }
});
document.getElementById('search-close').addEventListener('click', function(){
  if (searchInput.value) { clearSearch(); loadFiles(); }
  closeSearchUI();
});
document.getElementById('bb-search').addEventListener('click', openSearch);
document.addEventListener('keydown', function(e){
  if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); openSearch(); }
});

// ── Phone QR ──────────────────────────────────────────────────────────────────
// The server encodes its LAN address, so the code works even when this page is
// open on localhost.
var qrModal = document.getElementById('qr-modal');
function openQr() {
  document.getElementById('qr-img').src = '/qr.png?lan=1&t=' + Date.now();
  document.getElementById('qr-url').textContent = LAN_URL || (location.origin + '/');
  qrModal.classList.add('open');
}
function closeQr() { qrModal.classList.remove('open'); }
document.getElementById('qr-btn').addEventListener('click', openQr);
qrModal.addEventListener('click', function(e){ if (e.target === qrModal) closeQr(); });

// ── Settings panel ────────────────────────────────────────────────────────────
var settingsModal = document.getElementById('settings-modal');
var settingsBody = document.getElementById('settings-body');
var serverInfo = null;

function openSettings() {
  closeMenu();
  closeDrawer();
  serverInfo = null;
  renderSettings();
  settingsModal.classList.add('open');
  if (PRIVATE_SERVER && !SHARE_MODE) loadServerInfo();
}
function closeSettings() { settingsModal.classList.remove('open'); }
document.getElementById('settings-btn').addEventListener('click', openSettings);
settingsModal.addEventListener('click', function(e){ if (e.target === settingsModal) closeSettings(); });

function loadServerInfo() {
  fetch('/settings-info').then(function(r){ return r.ok ? r.json() : null; })
    .then(function(d){ serverInfo = d; if (settingsModal.classList.contains('open')) renderSettings(); })
    .catch(function(){});
}

function segCtl(key, opts) {
  return '<div class="seg" data-key="' + key + '">' + opts.map(function(o){
    return '<button data-val="' + o[0] + '"' + (String(settings[key]) === String(o[0]) ? ' class="on"' : '') + '>' + o[1] + '</button>';
  }).join('') + '</div>';
}
function switchCtl(key, on, extra) {
  return '<button class="switch" role="switch" aria-checked="' + (on ? 'true' : 'false') + '" data-switch="' + key + '"' + (extra || '') + '></button>';
}
function setRow(label, desc, ctl, cls) {
  return '<div class="set-row' + (cls ? ' ' + cls : '') + '"><div><div class="set-label">' + label + '</div>' +
         (desc ? '<div class="set-desc">' + desc + '</div>' : '') + '</div>' + ctl + '</div>';
}

var ACCENT_SWATCHES = [
  ['ultramarine', 'Ultramarine', '#2f3fd6'], ['cobalt', 'Cobalt', '#1f4fff'],
  ['steel', 'Steel', '#3d6a9e'], ['original', 'Classic blue', '#2563eb']
];

function renderSettings() {
  var h = '';
  h += '<div class="set-group"><div class="set-group-title">Appearance</div>';
  h += setRow('Theme', 'System follows your device', segCtl('theme', [['light','Light'],['dark','Dark'],['system','System']]));
  h += setRow('Accent color', 'Buttons, selection and the active folder',
    '<div class="swatches">' + ACCENT_SWATCHES.map(function(s){
      return '<button class="swatch' + (settings.accent === s[0] ? ' on' : '') + '" data-accent="' + s[0] + '" title="' + s[1] +
             '" aria-label="' + s[1] + '" style="background:' + s[2] + ';--sw:' + s[2] + '"></button>';
    }).join('') + '</div>');
  h += setRow('Tinted backgrounds', 'Mix a hint of the accent into the greys', switchCtl('tint', settings.tint));
  h += setRow('Density', '', segCtl('density', [['comfortable','Comfortable'],['compact','Compact']]));
  h += setRow('Default view', '', segCtl('view', [['list','List'],['grid','Grid']]));
  h += setRow('Remember view per folder', 'Each folder keeps the last view you picked', switchCtl('viewPerFolder', settings.viewPerFolder));
  h += '</div>';

  h += '<div class="set-group"><div class="set-group-title">Files</div>';
  h += setRow('Sort by', 'Pinned items always stay on top', segCtl('sort', [['recent','Recent'],['name','Name'],['size','Size'],['type','Type']]));
  h += setRow('Show file extensions', '', switchCtl('showExt', settings.showExt));
  h += setRow('Confirm before deleting', '', switchCtl('confirmDelete', settings.confirmDelete));
  h += '</div>';

  if (PRIVATE_SERVER && !SHARE_MODE) {
    h += '<div class="set-group"><div class="set-group-title">Server</div>';
    if (!serverInfo) {
      h += '<div class="set-row"><div class="set-desc">Loading…</div></div>';
    } else {
      var si = serverInfo;
      h += setRow('Login page', si.login_disabled
          ? 'Off: only devices already signed in can open FileDrop'
          : 'On: new devices can sign in with the password',
        switchCtl('login', !si.login_disabled, ' data-server="1"'));
      if (si.public_configured) {
        h += setRow('Public login page', si.public_login_disabled ? 'Off for the public server' : 'On for the public server',
          switchCtl('public_login', !si.public_login_disabled, ' data-server="1"'));
      }
      h += setRow('Media cache', 'Thumbnails and converted videos · ' + fmtSize(si.cache_bytes || 0) +
          '<div class="set-path">' + esc(si.cache_dir || '') + '</div>',
        '<div style="display:flex;gap:8px;align-items:center">' +
          '<select class="set-select" id="set-prune" aria-label="Remove cache entries unwatched for">' +
          [3, 7, 14, 30].map(function(n){ return '<option value="' + n + '"' + (si.prune_days === n ? ' selected' : '') + '>' + n + ' days</option>'; }).join('') +
          '</select><button class="folder-btn" id="set-clear-cache">Clear now</button></div>');
      h += '<div class="set-row set-col"><div><div class="set-label">Locked items</div><div class="set-desc">Removing a lock asks for its password</div></div>' +
           '<div class="set-list">' + (si.locks && si.locks.length ? si.locks.map(function(p, i){
             return '<div class="set-item"><span class="nm" title="' + esc(p) + '">' + esc(p) + '</span><button class="folder-btn" data-unlock="' + i + '">Remove lock</button></div>';
           }).join('') : '<div class="set-desc">No locked items</div>') + '</div></div>';
      h += '<div class="set-row set-col"><div><div class="set-label">Shared folders</div><div class="set-desc">Anyone with a link can open that folder</div></div>' +
           '<div class="set-list">' + (si.shares && si.shares.length ? si.shares.map(function(s, i){
             return '<div class="set-item"><span class="nm" title="' + esc(s.url) + '">' + esc(s.path) + '</span>' +
                    '<button class="folder-btn" data-copyshare="' + i + '">Copy link</button>' +
                    '<button class="folder-btn danger" data-unshare="' + i + '">Stop</button></div>';
           }).join('') : '<div class="set-desc">No shared folders</div>') + '</div></div>';
    }
    h += '</div>';
  }
  settingsBody.innerHTML = h;
  bindSettings();
}

function bindSettings() {
  settingsBody.querySelectorAll('.seg[data-key] button').forEach(function(b){
    b.addEventListener('click', function(){
      setSetting(b.parentNode.getAttribute('data-key'), b.getAttribute('data-val'));
      renderSettings();
    });
  });
  settingsBody.querySelectorAll('[data-accent]').forEach(function(b){
    b.addEventListener('click', function(){ setSetting('accent', b.getAttribute('data-accent')); renderSettings(); });
  });
  settingsBody.querySelectorAll('[data-switch]').forEach(function(b){
    b.addEventListener('click', function(){
      var key = b.getAttribute('data-switch');
      if (b.hasAttribute('data-server')) { toggleServerLogin(key === 'login' ? 'private' : 'public'); return; }
      setSetting(key, !settings[key]);
      renderSettings();
    });
  });
  var prune = document.getElementById('set-prune');
  if (prune) prune.addEventListener('change', function(){
    fetch('/settings?prune_days=' + encodeURIComponent(prune.value), {method:'POST'})
      .then(function(r){ if (!r.ok) throw new Error(); msg.className = 'ok'; msg.textContent = 'Cache cleanup set to ' + prune.value + ' days'; loadServerInfo(); })
      .catch(function(){ msg.className = 'err'; msg.textContent = 'Could not save that setting'; });
  });
  var clr = document.getElementById('set-clear-cache');
  if (clr) clr.addEventListener('click', function(){
    clr.disabled = true;
    fetch('/cache-clear', {method:'POST'})
      .then(function(r){ if (!r.ok) throw new Error(); msg.className = 'ok'; msg.textContent = 'Media cache cleared'; loadServerInfo(); })
      .catch(function(){ clr.disabled = false; msg.className = 'err'; msg.textContent = 'Could not clear the cache'; });
  });
  settingsBody.querySelectorAll('[data-unlock]').forEach(function(b){
    b.addEventListener('click', function(){
      var p = serverInfo.locks[+b.getAttribute('data-unlock')];
      askPassword('Remove lock', p, 'Remove', function(pw){
        fetch('/remove-lock?name=' + encodeURIComponent(p), {method:'POST', body:pw})
          .then(function(r){
            if (r.ok) { closePw(); msg.className = 'ok'; msg.textContent = 'Lock removed'; loadServerInfo(); loadFiles(); return; }
            r.text().then(function(t){ pwError(t.trim() || 'incorrect password'); });
          })
          .catch(function(){ pwError('network error'); });
      });
    });
  });
  settingsBody.querySelectorAll('[data-copyshare]').forEach(function(b){
    b.addEventListener('click', function(){ copyText(serverInfo.shares[+b.getAttribute('data-copyshare')].url, b, 'Copy link'); });
  });
  settingsBody.querySelectorAll('[data-unshare]').forEach(function(b){
    b.addEventListener('click', function(){
      var s = serverInfo.shares[+b.getAttribute('data-unshare')];
      fetch('/unshare?name=' + encodeURIComponent(s.path), {method:'POST'})
        .then(function(r){ if (!r.ok) throw new Error(); msg.className = 'ok'; msg.textContent = 'Stopped sharing ' + s.path.split('/').pop(); loadServerInfo(); renderShareBanner(); })
        .catch(function(){ msg.className = 'err'; msg.textContent = 'Could not stop sharing'; });
    });
  });
}

function toggleServerLogin(target) {
  fetch('/toggle-login?target=' + target, {method:'POST'})
    .then(function(r){ if (!r.ok) throw new Error(); return r.json(); })
    .then(function(){ loadServerInfo(); })
    .catch(function(){ msg.className = 'err'; msg.textContent = 'Could not change the login setting'; });
}

document.addEventListener('keydown', function(e){
  if (e.key !== 'Escape') return;
  if (settingsModal.classList.contains('open')) closeSettings();
  if (qrModal.classList.contains('open')) closeQr();
  closeDrawer();
});

// ── Start ─────────────────────────────────────────────────────────────────────
// A share visitor may only look: everything that writes is hidden (.owner-only),
// so the UI matches what the server will actually allow.
if (SHARE_MODE) document.body.classList.add('share-view');
if (!PRIVATE_SERVER) {
  document.getElementById('pin-section').classList.add('hidden');
  document.getElementById('pin-strip').classList.add('hidden');
}
renderBreadcrumb();
revealInTree('');
renderTree();
applyView();
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
      if (setTreeKids(forPath, currentFiles)) renderTree();
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

// ─── Pins ─────────────────────────────────────────────────────────────────────
// A pin just hoists an item to the top of its folder's listing, in place of the
// old unconditional "folders first" rule — no password, no visibility change.
// Persisted the same way locks are, in its own file beside config.json.

var (
	pinsMu sync.RWMutex
	pins   = map[string]bool{}
)

func pinsPath() string { return filepath.Join(filepath.Dir(cfgPath), "pins.json") }

func loadPins() {
	data, err := os.ReadFile(pinsPath())
	if err != nil {
		return
	}
	pinsMu.Lock()
	defer pinsMu.Unlock()
	if err := json.Unmarshal(data, &pins); err != nil {
		logger.Printf("pins.json: %v", err)
		pins = map[string]bool{}
	}
}

func savePins() error {
	pinsMu.RLock()
	data, err := json.MarshalIndent(pins, "", "  ")
	pinsMu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(pinsPath(), data, 0600)
}

func (c *serverCtx) handlePin(w http.ResponseWriter, r *http.Request)   { c.setPin(w, r, true) }
func (c *serverCtx) handleUnpin(w http.ResponseWriter, r *http.Request) { c.setPin(w, r, false) }

func (c *serverCtx) setPin(w http.ResponseWriter, r *http.Request, pinned bool) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.r2 != nil {
		http.Error(w, "pinning is not available on this server", http.StatusNotFound)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	if c.blockedByLock(r, name) {
		http.Error(w, "this item is locked", http.StatusForbidden)
		return
	}
	key := normLock(name)
	pinsMu.Lock()
	if pinned {
		pins[key] = true
	} else {
		delete(pins, key)
	}
	pinsMu.Unlock()
	if err := savePins(); err != nil {
		logger.Printf("savePins: %v", err)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// repinOnRename keeps a pin attached to its item when it is moved or renamed.
func repinOnRename(oldRel, newRel string) {
	oldKey, newKey := normLock(oldRel), normLock(newRel)
	pinsMu.Lock()
	defer pinsMu.Unlock()
	if pins[oldKey] {
		delete(pins, oldKey)
		pins[newKey] = true
		go savePins()
	}
}

// dropPin forgets a pin whose item no longer exists.
func dropPin(rel string) {
	key := normLock(rel)
	pinsMu.Lock()
	_, ok := pins[key]
	if ok {
		delete(pins, key)
	}
	pinsMu.Unlock()
	if ok {
		go savePins()
	}
}

// handlePins lists every pin that still exists and is not hidden by a lock, for
// the sidebar's Pinned section.
func (c *serverCtx) handlePins(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) || c.r2 != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	type pinOut struct {
		Path   string `json:"path"`
		IsDir  bool   `json:"is_dir"`
		IsNote bool   `json:"is_note"`
	}
	pinsMu.RLock()
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	pinsMu.RUnlock()
	out := []pinOut{}
	for _, k := range keys {
		full, ok := safeSubpath(c.rootDir, k)
		if !ok || c.blockedByLock(r, k) {
			continue
		}
		fi, err := os.Stat(full)
		if err != nil {
			continue
		}
		// pins are stored lower-cased; report the name as it is on disk
		rel, err := filepath.Rel(c.rootDir, full)
		if err != nil {
			continue
		}
		if real, err := filepath.EvalSymlinks(full); err == nil {
			if realRel, err := filepath.Rel(c.rootDir, real); err == nil && !strings.HasPrefix(realRel, "..") {
				rel = realRel
			}
		}
		name := filepath.Base(rel)
		out = append(out, pinOut{
			Path:   filepath.ToSlash(rel),
			IsDir:  fi.IsDir(),
			IsNote: strings.HasPrefix(name, "note_") && strings.HasSuffix(name, ".txt"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Path) < strings.ToLower(out[j].Path)
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func dirSize(root string) int64 {
	var n int64
	filepath.Walk(root, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

// handleSettingsInfo gathers the server-side settings for the settings panel.
func (c *serverCtx) handleSettingsInfo(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	locksMu.RLock()
	lockList := make([]string, 0, len(locks))
	for k := range locks {
		lockList = append(lockList, k)
	}
	locksMu.RUnlock()
	sort.Strings(lockList)

	type shareOut struct {
		Path string `json:"path"`
		URL  string `json:"url"`
	}
	sharesMu.RLock()
	shareList := make([]shareOut, 0, len(shares))
	for tok, s := range shares {
		shareList = append(shareList, shareOut{Path: s.Path, URL: shareURL(r, tok)})
	}
	sharesMu.RUnlock()
	sort.Slice(shareList, func(i, j int) bool { return strings.ToLower(shareList[i].Path) < strings.ToLower(shareList[j].Path) })

	info := map[string]interface{}{
		"login_disabled":        c.loginDisabled.Load(),
		"public_configured":     pubSrv != nil,
		"public_login_disabled": pubSrv != nil && pubSrv.loginDisabled.Load(),
		"cache_dir":             cacheRoot(),
		"cache_bytes":           dirSize(cacheRoot()),
		"prune_days":            pruneDays(),
		"locks":                 lockList,
		"shares":                shareList,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// handleSettings saves server-side settings sent from the settings panel.
func (c *serverCtx) handleSettings(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if v := r.URL.Query().Get("prune_days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			http.Error(w, "prune_days must be 1–365", http.StatusBadRequest)
			return
		}
		cfg.CachePruneDays = n
	}
	if err := saveConfig(); err != nil {
		logger.Printf("settings save error: %v", err)
		http.Error(w, "could not save settings", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// handleCacheClear empties the media cache. Everything in it is regenerated on
// demand, so this only costs re-conversion time.
func (c *serverCtx) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if !c.isAuthed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for _, kind := range []string{"thumbs", "remux", "hls"} {
		dir := mediaCacheDir(kind)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			// an in-progress HLS build writes into a .part folder; leave it be
			if strings.HasSuffix(e.Name(), ".part") {
				continue
			}
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	logger.Printf("media cache cleared")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// applyPins hoists pinned entries to the front of a listing. It runs after
// applyLocks, so a pin wins even over a locked item's placement — "pin it to
// the top" is the strongest ordering signal in the list.
func applyPins(c *serverCtx, r *http.Request, in []fileEntry) []fileEntry {
	if c.r2 != nil {
		return in // pinning is a private-server feature
	}
	pinsMu.RLock()
	defer pinsMu.RUnlock()
	if len(pins) == 0 {
		return in
	}
	base := strings.Trim(filepath.ToSlash(r.URL.Query().Get("path")), "/")
	if _, sharePath, ok := c.shareRoot(r); ok && !c.isAuthed(r) {
		base = strings.Trim(strings.Trim(sharePath, "/")+"/"+base, "/")
	}
	var pinned, plain []fileEntry
	for _, e := range in {
		rel := e.Name
		if base != "" {
			rel = base + "/" + e.Name
		}
		if pins[normLock(rel)] {
			e.Pinned = true
			pinned = append(pinned, e)
		} else {
			plain = append(plain, e)
		}
	}
	return append(pinned, plain...)
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

// cacheRoot keeps generated media out of the install folder. That folder is
// usually the source checkout, and HLS segments are named *.ts — editors and
// TypeScript tooling scanning the workspace would try to parse gigabytes of
// video as code.
func cacheRoot() string {
	if cfg.CacheDir != "" {
		return cfg.CacheDir
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "filedrop", "media_cache")
	}
	return filepath.Join(filepath.Dir(cfgPath), "media_cache")
}

func mediaCacheDir(kind string) string {
	dir := filepath.Join(cacheRoot(), kind)
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
	if file == "master.m3u8" {
		// Serving never writes, so mtime alone can't tell the pruner a stream is
		// still being watched — mark each playback start explicitly.
		now := time.Now()
		os.Chtimes(full, now, now)
	}
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
// the size of its source and an HLS ladder can be several times it, so the
// cache cannot be left to grow forever.
func pruneDays() int {
	if cfg.CachePruneDays > 0 {
		return cfg.CachePruneDays
	}
	return 7
}

func pruneMediaCache() {
	cutoff := time.Now().Add(-time.Duration(pruneDays()) * 24 * time.Hour)
	for _, kind := range []string{"thumbs", "remux", "hls"} {
		dir := mediaCacheDir(kind)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			// An HLS entry is a folder; its master playlist is touched on every
			// playback, so that is the last-watched time. A stale .part folder
			// (a crashed build) has no playlist and falls back to its own mtime.
			stamp := p
			if e.IsDir() {
				if _, err := os.Stat(filepath.Join(p, "master.m3u8")); err == nil {
					stamp = filepath.Join(p, "master.m3u8")
				}
			}
			fi, err := os.Stat(stamp)
			if err == nil && fi.ModTime().Before(cutoff) {
				os.RemoveAll(p)
			}
		}
	}
}

// pruneMediaCacheLoop prunes at startup and then daily — the service can run
// for months without a restart, so a startup-only pass never fires.
func pruneMediaCacheLoop() {
	for {
		pruneMediaCache()
		time.Sleep(24 * time.Hour)
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
		"Private":     c.private,
		"LanURL":      lanURL(c.port),
	})
}

// lanURL is this machine's address on the local network, for the phone QR.
// The page may be open on localhost, whose address a phone cannot reach.
func lanURL(port int) string {
	conn, err := net.Dial("udp", "192.0.2.1:9") // no packet is sent; this only picks the outbound interface
	if err != nil {
		return ""
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	if ip == nil || ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("http://%s:%d/", ip.String(), port)
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
	Pinned       bool      `json:"pinned,omitempty"`
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
	var all, files []fileEntry
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if e.IsDir() {
			all = append(all, fileEntry{Name: e.Name(), Modified: fi.ModTime(), IsDir: true})
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
	all = append(all, files...)
	// Folders no longer sort to the top automatically — everything is ordered
	// by recency together, and pinning (applyPins) is how an item gets hoisted.
	sort.Slice(all, func(i, j int) bool { return all[i].Modified.After(all[j].Modified) })
	result := applyPins(c, r, applyLocks(c, r, all))
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
	// keep any lock or pin attached to the item it belongs to
	newRel := strings.Trim(filepath.ToSlash(to), "/") + "/" + destName
	relockOnRename(name, newRel)
	repinOnRename(name, newRel)
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
	dropPin(rawName)
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
	if r.URL.Query().Get("lan") == "1" {
		if u := lanURL(c.port); u != "" {
			target = u
		}
	} else if d := r.URL.Query().Get("data"); d != "" {
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
		private:     true,
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
	mux.HandleFunc("/pin", c.handlePin)
	mux.HandleFunc("/unpin", c.handleUnpin)
	mux.HandleFunc("/pins", c.handlePins)
	mux.HandleFunc("/settings-info", c.handleSettingsInfo)
	mux.HandleFunc("/settings", c.handleSettings)
	mux.HandleFunc("/cache-clear", c.handleCacheClear)
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
	loadPins()
	loadShares()
	resolveMediaTools()
	nvencAvailable = probeNvenc()
	go pruneMediaCacheLoop()
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
		loadPins()
		loadShares()
		resolveMediaTools()
		nvencAvailable = probeNvenc()
		go pruneMediaCacheLoop()
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