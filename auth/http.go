package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// publicPaths can be opened without signing in: the sign-in page itself and what it needs.
var publicPaths = map[string]bool{
	"/login": true, "/login.html": true, "/login.js": true, "/style.css": true,
	"/api/login": true, "/api/setup": true, "/api/auth/status": true,
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	return host
}

// Protect lets only signed-in visitors through to next.
func (m *Manager) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie(CookieName); err == nil && m.Valid(c.Value) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/events" {
			http.Error(w, "sign in required", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

func (m *Manager) setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: m.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(SessionIdle.Seconds())})
}

func (m *Manager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: m.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// guard accepts only POST requests that carry our custom header (which web
// pages from other sites cannot send) and limits the size of the body.
func guard(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost || r.Header.Get("X-Requested-With") != "homesiem" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	return true
}

func (m *Manager) finish(w http.ResponseWriter, token string, err error) {
	var le *LockedError
	switch {
	case err == nil:
		m.setCookie(w, token)
		w.WriteHeader(http.StatusNoContent)
	case errors.As(err, &le):
		mins := int(le.Until.Sub(m.Now()).Minutes()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(mins*60))
		http.Error(w, fmt.Sprintf("Too many wrong attempts. Try again in %d minutes.", mins), http.StatusTooManyRequests)
	case errors.Is(err, ErrWrong):
		time.Sleep(m.FailDelay)
		http.Error(w, "Wrong password.", http.StatusUnauthorized)
	case errors.Is(err, ErrBadCode):
		time.Sleep(m.FailDelay)
		http.Error(w, "Wrong setup code.", http.StatusUnauthorized)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (m *Manager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if !guard(w, r) {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, err := m.Login(in.Password, clientIP(r))
	m.finish(w, tok, err)
}

func (m *Manager) HandleSetup(w http.ResponseWriter, r *http.Request) {
	if !guard(w, r) {
		return
	}
	var in struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, err := m.Setup(in.Code, in.Password, clientIP(r))
	m.finish(w, tok, err)
}

func (m *Manager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if !guard(w, r) {
		return
	}
	if c, err := r.Cookie(CookieName); err == nil {
		m.Logout(c.Value)
	}
	m.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (m *Manager) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !guard(w, r) {
		return
	}
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, err := m.ChangePassword(in.Current, in.New, clientIP(r))
	if errors.Is(err, ErrWrong) {
		// not 401: the page treats 401 as "your sign-in ended" and would jump to the sign-in page
		time.Sleep(m.FailDelay)
		http.Error(w, "The current password is wrong.", http.StatusBadRequest)
		return
	}
	m.finish(w, tok, err)
}

// HandleStatus tells the sign-in page what to show. It reveals nothing secret.
func (m *Manager) HandleStatus(w http.ResponseWriter, r *http.Request) {
	setup, err := m.SetupRequired()
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	signedIn := false
	if c, err := r.Cookie(CookieName); err == nil {
		signedIn = m.Valid(c.Value)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"authRequired": true, "setupRequired": setup, "authenticated": signedIn})
}
