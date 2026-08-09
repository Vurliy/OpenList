package webdavauth

import (
	"testing"
	"time"
)

func TestIssueAndVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	token, err := Issue("secret", Ticket{Audience: "webdav-1", Path: "/download/movie.mp4", UserID: 42, Username: "alice", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: "nonce-1"})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	ticket, err := VerifyAudience("secret", token, "webdav-1", now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("VerifyAudience failed: %v", err)
	}
	if ticket.Path != "/download/movie.mp4" || ticket.UserID != 42 || ticket.Username != "alice" {
		t.Fatalf("unexpected ticket claims: %+v", ticket)
	}
}

func TestVerifyRejectsTamperingAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	token, err := Issue("secret", Ticket{Path: "/download/file.txt", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify("wrong", token, now); err == nil {
		t.Fatal("expected wrong secret to be rejected")
	}
	if _, err := Verify("secret", token+"x", now); err == nil {
		t.Fatal("expected tampered ticket to be rejected")
	}
	if _, err := Verify("secret", token, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected expired ticket to be rejected")
	}
}
