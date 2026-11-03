package auth

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memSettings struct{ m map[string]string }

func (s *memSettings) GetSetting(k string) (string, error) { return s.m[k], nil }
func (s *memSettings) SetSetting(k, v string) error        { s.m[k] = v; return nil }

func newManager(t *testing.T) (*Manager, *time.Time) {
	t.Helper()
	Iterations = 1000 // fast for tests
	m, err := New(&memSettings{m: map[string]string{}}, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	m.FailDelay = 0
	return m, &now
}

// Known-answer tests from the PBKDF2-HMAC-SHA256 reference values.
func TestPBKDF2KnownAnswers(t *testing.T) {
	cases := []struct {
		pw, salt string
		iter, n  int
		want     string
	}{
		{"password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{"password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
			"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2SHA256([]byte(c.pw), []byte(c.salt), c.iter, c.n))
		if got != c.want {
			t.Fatalf("pbkdf2(%q, %q, %d, %d) = %s, want %s", c.pw, c.salt, c.iter, c.n, got, c.want)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	Iterations = 1000
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery", h) || VerifyPassword("wrong", h) {
		t.Fatal("verify gave the wrong answer")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("two hashes of the same password must differ (random salt)")
	}
	for _, bad := range []string{"", "x", "pbkdf2-sha256$1$AA$AA", "md5$1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if VerifyPassword("x", bad) {
			t.Fatalf("garbage hash %q must never verify", bad)
		}
	}
	if ValidatePassword("short") == nil || ValidatePassword("long enough password") != nil {
		t.Fatal("password rules wrong")
	}
}

func TestSetupThenLogin(t *testing.T) {
	m, _ := newManager(t)
	if need, _ := m.SetupRequired(); !need || len(m.SetupCode()) != 10 {
		t.Fatalf("a fresh install needs setup and a 10 character code, got %q", m.SetupCode())
	}
	if _, err := m.Login("anything at all", "10.0.0.5"); err != ErrNoPassword {
		t.Fatalf("login before setup must fail, got %v", err)
	}
	if _, err := m.Setup("WRONGCODE1", "a good long password", "10.0.0.5"); err != ErrBadCode {
		t.Fatalf("a wrong code must be refused, got %v", err)
	}
	if _, err := m.Setup(m.SetupCode(), "short", "10.0.0.5"); err == nil {
		t.Fatal("a short password must be refused")
	}
	tok, err := m.Setup(strings.ToLower(m.SetupCode()), "a good long password", "10.0.0.5") // case does not matter
	if err != nil || !m.Valid(tok) {
		t.Fatalf("setup failed: %v", err)
	}
	if need, _ := m.SetupRequired(); need || m.SetupCode() != "" {
		t.Fatal("setup must be finished")
	}
	if _, err := m.Setup("ANYTHING12", "another good password", "10.0.0.6"); err != ErrSetupDone {
		t.Fatalf("a second setup must be refused, got %v", err)
	}
	if _, err := m.Login("not the password", "10.0.0.5"); err != ErrWrong {
		t.Fatalf("wrong password: %v", err)
	}
	tok2, err := m.Login("a good long password", "10.0.0.5")
	if err != nil || !m.Valid(tok2) {
		t.Fatalf("login failed: %v", err)
	}
	m.Logout(tok2)
	if m.Valid(tok2) {
		t.Fatal("a signed-out session must stop working")
	}
}

func TestLockoutAfterFiveWrongGuesses(t *testing.T) {
	m, now := newManager(t)
	tok, _ := m.Setup(m.SetupCode(), "a good long password", "10.0.0.5")
	_ = tok
	lockouts := 0
	m.Lockout = func(ip string, minutes int) { lockouts++ }
	for i := 0; i < 5; i++ {
		if _, err := m.Login("guess", "10.0.0.9"); err != ErrWrong {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if lockouts != 1 {
		t.Fatalf("expected one lock-out report, got %d", lockouts)
	}
	_, err := m.Login("a good long password", "10.0.0.9") // the RIGHT password, but locked
	if _, ok := err.(*LockedError); !ok {
		t.Fatalf("a locked address must be refused even with the right password, got %v", err)
	}
	if _, err := m.Login("a good long password", "10.0.0.77"); err != nil {
		t.Fatalf("other addresses must not be affected: %v", err)
	}
	*now = now.Add(16 * time.Minute)
	if _, err := m.Login("a good long password", "10.0.0.9"); err != nil {
		t.Fatalf("the lock must end after 15 minutes: %v", err)
	}
}

func TestSessionsExpireWhenIdle(t *testing.T) {
	m, now := newManager(t)
	tok, _ := m.Setup(m.SetupCode(), "a good long password", "10.0.0.5")
	*now = now.Add(11 * time.Hour)
	if !m.Valid(tok) { // use keeps it alive
		t.Fatal("session should still be valid after 11 hours")
	}
	*now = now.Add(11 * time.Hour)
	if !m.Valid(tok) {
		t.Fatal("use must extend the session")
	}
	*now = now.Add(13 * time.Hour)
	if m.Valid(tok) {
		t.Fatal("an idle session must expire")
	}
}

func TestChangePasswordEndsOtherSessions(t *testing.T) {
	m, _ := newManager(t)
	old, _ := m.Setup(m.SetupCode(), "a good long password", "10.0.0.5")
	if _, err := m.ChangePassword("not it", "a brand new password", "10.0.0.5"); err != ErrWrong {
		t.Fatalf("wrong current password: %v", err)
	}
	fresh, err := m.ChangePassword("a good long password", "a brand new password", "10.0.0.5")
	if err != nil || !m.Valid(fresh) || m.Valid(old) {
		t.Fatalf("change failed or left an old session open: %v", err)
	}
	if _, err := m.Login("a brand new password", "10.0.0.5"); err != nil {
		t.Fatalf("the new password must work: %v", err)
	}
}

func TestMiddlewareAndHandlers(t *testing.T) {
	m, _ := newManager(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("login page")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) })
	mux.HandleFunc("/api/login", m.HandleLogin)
	mux.HandleFunc("/api/setup", m.HandleSetup)
	mux.HandleFunc("/api/logout", m.HandleLogout)
	h := m.Protect(mux)

	do := func(method, path, body string, cookie *http.Cookie, header bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "192.168.1.50:50000"
		if header {
			req.Header.Set("X-Requested-With", "homesiem")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := do("GET", "/api/devices", "", nil, false); rec.Code != 401 {
		t.Fatalf("an API call without sign-in must give 401, got %d", rec.Code)
	}
	if rec := do("GET", "/", "", nil, false); rec.Code != 302 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("a page without sign-in must redirect to /login, got %d", rec.Code)
	}
	if rec := do("GET", "/login", "", nil, false); rec.Code != 200 || rec.Body.String() != "login page" {
		t.Fatal("the login page must be public")
	}
	if rec := do("POST", "/api/setup", `{"code":"X","password":"a good long password"}`, nil, false); rec.Code != 403 {
		t.Fatalf("a POST without the custom header must be refused, got %d", rec.Code)
	}
	setup := `{"code":"` + m.SetupCode() + `","password":"a good long password"}`
	rec := do("POST", "/api/setup", setup, nil, true)
	if rec.Code != 204 {
		t.Fatalf("setup should work, got %d %s", rec.Code, rec.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("the session cookie must be HttpOnly and SameSite=Strict: %+v", cookie)
	}
	if rec := do("GET", "/", "", cookie, false); rec.Code != 200 || rec.Body.String() != "secret" {
		t.Fatalf("a signed-in visitor must get through, got %d", rec.Code)
	}
	if rec := do("POST", "/api/login", `{"password":"nope nope nope"}`, nil, true); rec.Code != 401 {
		t.Fatalf("a wrong password must give 401, got %d", rec.Code)
	}
	if rec := do("POST", "/api/logout", "", cookie, true); rec.Code != 204 {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := do("GET", "/api/devices", "", cookie, false); rec.Code != 401 {
		t.Fatalf("after logout the old cookie must stop working, got %d", rec.Code)
	}
}
