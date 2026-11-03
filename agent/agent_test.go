package agent

import (
	"strings"
	"testing"
	"time"
)

func TestBuildMessage(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 5, 0, time.UTC)
	plain := BuildMessage("disk almost full", "pc1", "app", 6, now)
	if plain != "<134>Oct 28 12:00:05 pc1 app: disk almost full" {
		t.Fatalf("unexpected message: %q", plain)
	}
	already := BuildMessage("Oct 28 11:59:59 kali sshd[7]: Failed password for root", "pc1", "auth", 6, now)
	if !strings.HasPrefix(already, "<134>Oct 28 11:59:59 kali sshd[7]:") {
		t.Fatalf("a syslog line must be forwarded as it is: %q", already)
	}
	iso := BuildMessage("2026-10-28T11:59:59.123+00:00 kali sudo: session opened", "pc1", "auth", 6, now)
	if !strings.HasPrefix(iso, "<134>2026-10-28T11:59:59") {
		t.Fatalf("an ISO-time line must be forwarded as it is: %q", iso)
	}
}
