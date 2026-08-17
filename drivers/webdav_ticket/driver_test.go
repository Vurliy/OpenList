package webdav_ticket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/gowebdav"
	"github.com/OpenListTeam/OpenList/v4/pkg/webdavauth"
)

func TestWebDavTicketDriverInitAndTicketIssuance(t *testing.T) {
	var requests atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer control.Close()

	d := &WebDavTicket{
		Addition: Addition{
			Address:            "https://webdav.example/download/",
			WebDAVAuthSecret:   "secret",
			WebDAVAuthAudience: "storage-1",
		},
		authClient: gowebdav.NewClient(control.URL+"/webdav-auth/grants/", "", ""),
	}
	ctx := context.WithValue(context.Background(), conf.UserKey, &model.User{ID: 7, Username: "alice"})
	ctx = context.WithValue(ctx, conf.TokenKey, "jwt-a")

	one, err := d.withWebDAVTicket(ctx, "https://webdav.example/download/file.mp4?existing=1")
	if err != nil {
		t.Fatalf("withWebDAVTicket failed: %v", err)
	}
	two, err := d.withWebDAVTicket(ctx, "https://webdav.example/download/file.mp4?existing=1")
	if err != nil || one != two {
		t.Fatalf("same file ticket changed: %q / %q / %v", one, two, err)
	}
	if requests.Load() != 0 {
		t.Fatalf("Link path unexpectedly created a grant: %d requests", requests.Load())
	}
	u, err := url.Parse(one)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := webdavauth.VerifyPathBound("secret", d.WebDAVAuthNonce, u.Query().Get(webdavauth.QueryParameter), "/download/file.mp4")
	if err != nil {
		t.Fatalf("ticket verification failed: %v", err)
	}
	if ticket.Path != "/download/file.mp4" || ticket.UserID != 7 || ticket.TokenDigest != webdavauth.TokenDigest("jwt-a") {
		t.Fatalf("unexpected ticket claims: %+v", ticket)
	}
	if u.Query().Get("existing") != "1" {
		t.Fatalf("existing query parameter was lost: %q", u.RawQuery)
	}
}

func TestWebDavTicketAuthorizeWebDAVState(t *testing.T) {
	var grantPayload map[string]any
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if err := json.NewDecoder(r.Body).Decode(&grantPayload); err != nil {
				t.Fatalf("decode grant: %v", err)
			}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer control.Close()

	d := &WebDavTicket{
		Addition: Addition{
			Address:            "https://webdav.example/download/",
			WebDAVAuthSecret:   "secret",
			WebDAVAuthAudience: "storage-1",
		},
		authClient: gowebdav.NewClient(control.URL+"/webdav-auth/grants/", "", ""),
	}
	ticket, err := webdavauth.IssuePathBound("secret", d.WebDAVAuthNonce, webdavauth.Ticket{
		Audience:    "storage-1",
		Path:        "/download/file.mp4",
		Scope:       "/download",
		Type:        webdavauth.TicketTypeFile,
		UserID:      7,
		TokenDigest: webdavauth.TokenDigest("jwt-a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.AuthorizeWebDAVState(ticket, "state-123", "jwt-a", &model.User{ID: 7, Username: "alice"})
	if err != nil {
		t.Fatalf("AuthorizeWebDAVState failed: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/webdav-auth/exchange" || parsed.Query().Get("state") != "state-123" || parsed.Query().Get("grant_id") == "" {
		t.Fatalf("unexpected exchange URL: %s", got)
	}
	if grantPayload["state"] != "state-123" {
		t.Fatalf("grant state = %#v, want state-123", grantPayload["state"])
	}
	if _, err := d.AuthorizeWebDAVState(ticket, "state-123", "jwt-a", &model.User{ID: 8, Username: "bob"}); err == nil {
		t.Fatal("expected a user mismatch to be rejected")
	}
}

func TestWebDavTicketRevokeUser(t *testing.T) {
	var published atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		published.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer control.Close()

	d := &WebDavTicket{
		Addition: Addition{
			Address:            control.URL,
			WebDAVAuthSecret:   "secret",
			WebDAVAuthAudience: "storage-1",
		},
	}
	if err := d.RevokeWebDAVUser(&model.User{ID: 7, Username: "alice"}); err != nil {
		t.Fatalf("RevokeWebDAVUser failed: %v", err)
	}
	if published.Load() == 0 {
		t.Fatal("expected revocation requests")
	}
}
