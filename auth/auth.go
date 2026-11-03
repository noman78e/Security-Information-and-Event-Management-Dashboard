package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	CookieName  = "homesiem_session"
	SessionIdle = 12 * time.Hour // a sign-in ends after this long without use
	maxSessions = 50
	maxFails    = 5                // wrong guesses allowed ...
	failWindow  = 10 * time.Minute // ... within this time
	lockFor     = 15 * time.Minute
	settingKey  = "auth_hash"
)

var (
	ErrWrong      = errors.New("wrong password")
	ErrBadCode    = errors.New("wrong setup code")
	ErrNoPassword = errors.New("no password has been set yet")
	ErrSetupDone  = errors.New("a password is already set")
)

// LockedError means too many wrong guesses were made from one address.
type LockedError struct{ Until time.Time }

func (e *LockedError) Error() string { return "too many wrong attempts" }

// Settings is where the password hash is kept (the HomeSIEM database).
type Settings interface {
	GetSetting(key string) (string, error) // "" if missing
	SetSetting(key, value string) error
}

type fail struct {
	n           int
	first       time.Time
	lockedUntil time.Time
}

// Manager holds the sign-ins. It is safe for concurrent use.
type Manager struct {
	set    Settings
	secure bool // mark the cookie "Secure" (HTTPS only)

	// Now, Log, Lockout and FailDelay can be changed before use.
	Now       func() time.Time
	Log       func(level, msg string)
	Lockout   func(ip string, minutes int)
	FailDelay time.Duration // pause after a wrong password, slows guessing

	mu       sync.Mutex
	code     string // first-run setup code, "" once a password exists
	sessions map[string]time.Time
	fails    map[string]*fail
}

// New creates a manager. If no password is set yet, a setup code is created.
func New(set Settings, secureCookie bool) (*Manager, error) {
	m := &Manager{set: set, secure: secureCookie, Now: time.Now, FailDelay: 400 * time.Millisecond,
		sessions: map[string]time.Time{}, fails: map[string]*fail{}}
	h, err := set.GetSetting(settingKey)
	if err != nil {
		return nil, err
	}
	if h == "" {
		m.code = randomCode(10)
	}
	return m, nil
}

// randomCode makes a code from letters and digits that cannot be mixed up (no 0, O, 1, I).
func randomCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rand.Read(b)
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

func (m *Manager) log(level, msg string) {
	if m.Log != nil {
		m.Log(level, msg)
	}
}

// SetupCode returns the first-run code ("" if a password already exists).
func (m *Manager) SetupCode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.code
}

// SetupRequired is true until the first password is created.
func (m *Manager) SetupRequired() (bool, error) {
	h, err := m.set.GetSetting(settingKey)
	return h == "", err
}

func (m *Manager) lockedLocked(ip string, now time.Time) (time.Time, bool) {
	if f := m.fails[ip]; f != nil && now.Before(f.lockedUntil) {
		return f.lockedUntil, true
	}
	return time.Time{}, false
}

// noteFail counts a wrong guess and reports whether the address is now locked.
func (m *Manager) noteFail(ip string, now time.Time) bool {
	f := m.fails[ip]
	if f == nil {
		if len(m.fails) >= 1000 {
			for k, v := range m.fails {
				if now.Sub(v.first) > failWindow && now.After(v.lockedUntil) {
					delete(m.fails, k)
				}
			}
		}
		f = &fail{first: now}
		m.fails[ip] = f
	}
	if now.Sub(f.first) > failWindow && now.After(f.lockedUntil) {
		f.n, f.first = 0, now
	}
	f.n++
	if f.n >= maxFails {
		f.lockedUntil = now.Add(lockFor)
		f.n = 0
		return true
	}
	return false
}

func (m *Manager) newSession(now time.Time) string {
	for t, exp := range m.sessions {
		if now.After(exp) {
			delete(m.sessions, t)
		}
	}
	for len(m.sessions) >= maxSessions { // drop the one that would expire first
		var oldest string
		var oldestExp time.Time
		for t, exp := range m.sessions {
			if oldest == "" || exp.Before(oldestExp) {
				oldest, oldestExp = t, exp
			}
		}
		delete(m.sessions, oldest)
	}
	b := make([]byte, 32)
	rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	m.sessions[tok] = now.Add(SessionIdle)
	return tok
}

// Valid reports whether a session token is good, and keeps the session alive.
func (m *Manager) Valid(token string) bool {
	if token == "" {
		return false
	}
	now := m.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.sessions[token]
	if !ok || now.After(exp) {
		delete(m.sessions, token)
		return false
	}
	m.sessions[token] = now.Add(SessionIdle)
	return true
}

// Logout ends a session.
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

// check verifies a password for a client address, with lock-out handling.
func (m *Manager) check(pw, ip string, wrong error) error {
	now := m.Now()
	m.mu.Lock()
	if until, locked := m.lockedLocked(ip, now); locked {
		m.mu.Unlock()
		return &LockedError{Until: until}
	}
	m.mu.Unlock()

	hash, err := m.set.GetSetting(settingKey)
	if err != nil {
		return err
	}
	if hash == "" {
		return ErrNoPassword
	}
	ok := VerifyPassword(pw, hash) // slow on purpose, done outside the lock

	m.mu.Lock()
	var lockedNow bool
	if ok {
		delete(m.fails, ip)
	} else {
		lockedNow = m.noteFail(ip, now)
	}
	m.mu.Unlock()

	if ok {
		return nil
	}
	m.log("warn", "Wrong dashboard password from "+ip)
	if lockedNow {
		m.log("warn", fmt.Sprintf("Dashboard sign-in locked for %s after repeated wrong passwords from %s", lockFor, ip))
		if m.Lockout != nil {
			m.Lockout(ip, int(lockFor.Minutes()))
		}
	}
	return wrong
}

// Login checks the password and starts a session.
func (m *Manager) Login(pw, ip string) (string, error) {
	if err := m.check(pw, ip, ErrWrong); err != nil {
		return "", err
	}
	m.mu.Lock()
	tok := m.newSession(m.Now())
	m.mu.Unlock()
	m.log("info", "Dashboard sign-in from "+ip)
	return tok, nil
}

// Setup creates the first password. It needs the code shown on the console.
func (m *Manager) Setup(code, pw, ip string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}
	now := m.Now()
	m.mu.Lock()
	if until, locked := m.lockedLocked(ip, now); locked {
		m.mu.Unlock()
		return "", &LockedError{Until: until}
	}
	want := m.code
	m.mu.Unlock()

	if need, err := m.SetupRequired(); err != nil {
		return "", err
	} else if !need || want == "" {
		return "", ErrSetupDone
	}
	given := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if subtle.ConstantTimeCompare([]byte(given), []byte(want)) != 1 {
		m.mu.Lock()
		lockedNow := m.noteFail(ip, now)
		m.mu.Unlock()
		m.log("warn", "Wrong setup code from "+ip)
		if lockedNow && m.Lockout != nil {
			m.Lockout(ip, int(lockFor.Minutes()))
		}
		return "", ErrBadCode
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.code == "" { // someone else finished the setup first
		return "", ErrSetupDone
	}
	if err := m.set.SetSetting(settingKey, hash); err != nil {
		return "", err
	}
	m.code = ""
	m.log("info", "Dashboard password created from "+ip)
	return m.newSession(now), nil
}

// ChangePassword sets a new password, ends every other sign-in, and returns a fresh session.
func (m *Manager) ChangePassword(current, next, ip string) (string, error) {
	if err := ValidatePassword(next); err != nil {
		return "", err
	}
	if err := m.check(current, ip, ErrWrong); err != nil {
		return "", err
	}
	hash, err := HashPassword(next)
	if err != nil {
		return "", err
	}
	if err := m.set.SetSetting(settingKey, hash); err != nil {
		return "", err
	}
	m.mu.Lock()
	m.sessions = map[string]time.Time{}
	tok := m.newSession(m.Now())
	m.mu.Unlock()
	m.log("warn", "Dashboard password changed from "+ip)
	return tok, nil
}

// Reset sets a password without asking for the old one. It is used by the
// "homesiem passwd" command, which needs access to the database file.
func Reset(set Settings, pw string) error {
	if err := ValidatePassword(pw); err != nil {
		return err
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	return set.SetSetting(settingKey, h)
}
