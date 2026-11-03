package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Notifier sends alerts to Telegram, a webhook and/or email.
type Notifier struct {
	cfg    NotifyCfg
	client *http.Client
}

func NewNotifier(cfg NotifyCfg) *Notifier {
	return &Notifier{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}
}

// Channels lists the channels that are fully configured.
func (n *Notifier) Channels() []string {
	var c []string
	if n.cfg.Telegram.BotToken != "" && n.cfg.Telegram.ChatID != "" {
		c = append(c, "telegram")
	}
	if n.cfg.Webhook.URL != "" {
		c = append(c, "webhook")
	}
	if n.cfg.Email.SMTPHost != "" && n.cfg.Email.To != "" {
		c = append(c, "email")
	}
	return c
}

// Send delivers a message on every configured channel and reports the result of each.
func (n *Notifier) Send(title, body string) map[string]error {
	res := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ch := range n.Channels() {
		wg.Add(1)
		go func(ch string) {
			defer wg.Done()
			var err error
			switch ch {
			case "telegram":
				err = n.postJSON("https://api.telegram.org/bot"+n.cfg.Telegram.BotToken+"/sendMessage",
					map[string]any{"chat_id": n.cfg.Telegram.ChatID, "text": title + "\n" + body})
			case "webhook":
				msg := title + "\n" + body
				// "text" is used by Slack and Mattermost, "content" by Discord.
				err = n.postJSON(n.cfg.Webhook.URL, map[string]any{"text": msg, "content": msg,
					"title": title, "message": body})
			case "email":
				err = n.sendEmail(title, body)
			}
			mu.Lock()
			res[ch] = err
			mu.Unlock()
		}(ch)
	}
	wg.Wait()
	return res
}

// postJSON never puts the URL in its errors, because Telegram URLs contain the bot token.
func (n *Notifier) postJSON(target string, v any) error {
	b, _ := json.Marshal(v)
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return errors.New("invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("request failed: %v", ue.Err)
		}
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("server answered HTTP %d", resp.StatusCode)
	}
	return nil
}

func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func (n *Notifier) sendEmail(title, body string) error {
	e := n.cfg.Email
	port := e.SMTPPort
	if port == 0 {
		port = 587
	}
	from := e.From
	if from == "" {
		from = e.Username
	}
	var auth smtp.Auth
	if e.Username != "" {
		auth = smtp.PlainAuth("", e.Username, e.Password, e.SMTPHost)
	}
	msg := "From: " + oneLine(from) + "\r\nTo: " + oneLine(e.To) + "\r\nSubject: " + oneLine(title) +
		"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n"
	addr := net.JoinHostPort(e.SMTPHost, strconv.Itoa(port))
	done := make(chan error, 1)
	go func() { done <- smtp.SendMail(addr, auth, from, []string{e.To}, []byte(msg)) }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		return errors.New("timed out")
	}
}
