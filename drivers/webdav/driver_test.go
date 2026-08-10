package webdav

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/gowebdav"
	"github.com/OpenListTeam/OpenList/v4/pkg/webdavauth"
	"github.com/go-resty/resty/v2"
)

func TestGetMapsMissingPathToObjectNotFound(t *testing.T) {
	d, cleanup := newTestDriver(t, nil)
	defer cleanup()

	_, err := d.Get(context.Background(), "/missing")
	if !errs.IsObjectNotFound(err) {
		t.Fatalf("expected object not found, got %v", err)
	}
}

func TestGetAdditionNormalizesMissingTicketTTL(t *testing.T) {
	d := &WebDav{}
	addition, ok := d.GetAddition().(*Addition)
	if !ok {
		t.Fatalf("GetAddition returned %T, want *Addition", d.GetAddition())
	}
	if addition.WebDAVAuthTicketTTL != defaultWebDAVAuthTicketTTL {
		t.Fatalf("ticket TTL = %d, want %d", addition.WebDAVAuthTicketTTL, defaultWebDAVAuthTicketTTL)
	}
}

func TestMakeDirAfterMissingWebDAVStat(t *testing.T) {
	var mkcolCount atomic.Int32
	d, cleanup := newTestDriver(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "MKCOL" && (r.URL.Path == "/new" || r.URL.Path == "/new/") {
			mkcolCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			return true
		}
		return false
	})
	defer cleanup()

	if err := op.MakeDir(context.Background(), d, "/new"); err != nil {
		t.Fatalf("MakeDir failed: %v", err)
	}
	if got := mkcolCount.Load(); got != 1 {
		t.Fatalf("expected one MKCOL request, got %d", got)
	}
}

func TestLinkAcceptsSuccessfulWebDAVResponse(t *testing.T) {
	base.NoRedirectClient = resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
	d, cleanup := newTestDriver(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/file" {
			w.WriteHeader(http.StatusOK)
			return true
		}
		return false
	})
	defer cleanup()

	_, err := d.Link(context.Background(), &model.Object{Path: "/file", Name: "file"}, model.LinkArgs{Redirect: true})
	if err != nil {
		t.Fatalf("Link rejected a successful WebDAV response: %v", err)
	}
}

func TestWithWebDAVTicketBindsUserAndPath(t *testing.T) {
	var grantPayload map[string]any
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != "MOVE" {
			t.Fatalf("grant request method = %s, want PUT or MOVE", r.Method)
		}
		if r.Method == http.MethodPut {
			if err := json.NewDecoder(r.Body).Decode(&grantPayload); err != nil {
				t.Fatalf("decode grant: %v", err)
			}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer control.Close()

	d := &WebDav{Addition: Addition{
		WebDAVAuthEnabled:   true,
		WebDAVAuthSecret:    "secret",
		WebDAVAuthAudience:  "storage-1",
		WebDAVAuthTicketTTL: 60,
	}, authClient: gowebdav.NewClient(control.URL+"/webdav-auth/grants/", "", "")}
	ctx := context.WithValue(context.Background(), conf.UserKey, &model.User{ID: 7, Username: "alice"})
	got, err := d.withWebDAVTicket(ctx, "https://webdav.example/download/file.mp4?existing=1")
	if err != nil {
		t.Fatalf("withWebDAVTicket failed: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := webdavauth.VerifyAudience("secret", u.Query().Get(webdavauth.QueryParameter), "storage-1", time.Now())
	if err != nil {
		t.Fatalf("ticket verification failed: %v", err)
	}
	if ticket.Path != "/download/file.mp4" || ticket.UserID != 7 || ticket.Username != "alice" {
		t.Fatalf("unexpected ticket claims: %+v", ticket)
	}
	if u.Query().Get("existing") != "1" {
		t.Fatalf("existing query parameter was lost: %q", u.RawQuery)
	}
	if grantPayload["ticket"] != u.Query().Get(webdavauth.QueryParameter) {
		t.Fatalf("grant did not register the issued ticket: %#v", grantPayload)
	}
}

func TestAuthorizeWebDAVStateBindsUserAndReturnsExchangeURL(t *testing.T) {
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

	d := &WebDav{Addition: Addition{
		Address:            "https://webdav.example/download/",
		WebDAVAuthEnabled:  true,
		WebDAVAuthSecret:   "secret",
		WebDAVAuthAudience: "storage-1",
	}, authClient: gowebdav.NewClient(control.URL+"/webdav-auth/grants/", "", "")}
	ticket, err := webdavauth.Issue("secret", webdavauth.Ticket{
		Audience:  "storage-1",
		Path:      "/download/file.mp4",
		UserID:    7,
		Username:  "alice",
		IssuedAt:  time.Now().Add(-time.Second).Unix(),
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.AuthorizeWebDAVState(ticket, "state-123", &model.User{ID: 7, Username: "alice"})
	if err != nil {
		t.Fatalf("AuthorizeWebDAVState failed: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/webdav-auth/exchange" || parsed.Query().Get("state") != "state-123" {
		t.Fatalf("unexpected exchange URL: %s", got)
	}
	if grantPayload["state"] != "state-123" {
		t.Fatalf("grant state = %#v, want state-123", grantPayload["state"])
	}
	if _, err := d.AuthorizeWebDAVState(ticket, "state-123", &model.User{ID: 8, Username: "bob"}); err == nil {
		t.Fatal("expected a user mismatch to be rejected")
	}
}

func TestTicketedLinkLeavesExchangeForTheClient(t *testing.T) {
	var dataGets atomic.Int32
	data := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			dataGets.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer data.Close()
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != "MOVE" {
			t.Fatalf("grant request method = %s, want PUT or MOVE", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer control.Close()

	d := &WebDav{
		Addition: Addition{
			WebDAVAuthEnabled:   true,
			WebDAVAuthSecret:    "secret",
			WebDAVAuthAudience:  "storage-1",
			WebDAVAuthTicketTTL: 60,
		},
		client:     gowebdav.NewClient(data.URL+"/download/", "", ""),
		authClient: gowebdav.NewClient(control.URL+"/webdav-auth/grants/", "", ""),
	}
	ctx := context.WithValue(context.Background(), conf.UserKey, &model.User{ID: 7, Username: "alice"})
	link, err := d.Link(ctx, &model.Object{Path: "/file", Name: "file"}, model.LinkArgs{Redirect: true})
	if err != nil {
		t.Fatalf("Link failed: %v", err)
	}
	if dataGets.Load() != 0 {
		t.Fatalf("ticketed link was resolved by OpenList; got %d GETs", dataGets.Load())
	}
	u, err := url.Parse(link.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get(webdavauth.QueryParameter) == "" {
		t.Fatalf("ticketed link did not contain a ticket: %q", link.URL)
	}
}

func newTestDriver(t *testing.T, extra func(http.ResponseWriter, *http.Request) bool) (*WebDav, func()) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extra != nil && extra(w, r) {
			return
		}
		switch r.Method {
		case "PROPFIND":
			if r.URL.Path == "/" {
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.WriteHeader(http.StatusMultiStatus)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/</d:href>
    <d:propstat>
      <d:prop>
        <d:displayname>/</d:displayname>
        <d:resourcetype><d:collection/></d:resourcetype>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>`))
				return
			}
			http.NotFound(w, r)
		case "MKCOL":
			w.WriteHeader(http.StatusConflict)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	d := &WebDav{Addition: Addition{Address: srv.URL, RootPath: driver.RootPath{RootFolderPath: "/"}}}
	if err := d.Init(context.Background()); err != nil {
		srv.Close()
		t.Fatalf("init driver: %v", err)
	}
	return d, func() {
		_ = d.Drop(context.Background())
		srv.Close()
	}
}
