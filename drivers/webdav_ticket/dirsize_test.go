package webdav_ticket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebDavTicketGetDetailsAndDirSize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "openlist" || p != "Xi0cange" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/dirsize-api/v1/disk_usage" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"total": 983171104768, "used": 480109449216, "free": 493044674560}`))
			return
		}
		if r.URL.Path == "/dirsize-api/v1/query" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status": "ready", "total_size": 422505387406, "direct_children_sizes": {"anime": 7140112762, "tidy": 415365272841}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	d := &WebDavTicket{
		Addition: Addition{
			Address:  ts.URL,
			Username: "openlist",
			Password: "Xi0cange",
		},
	}

	// Test GetDetails
	details, err := d.GetDetails(context.Background())
	if err != nil {
		t.Fatalf("GetDetails failed: %v", err)
	}
	if details.DiskUsage.TotalSpace != 983171104768 {
		t.Errorf("expected total space 983171104768, got %d", details.DiskUsage.TotalSpace)
	}
	if details.DiskUsage.UsedSpace != 480109449216 {
		t.Errorf("expected used space 480109449216, got %d", details.DiskUsage.UsedSpace)
	}

	// Test queryDirSizes
	sizes := d.queryDirSizes(context.Background(), "/aria2/completed")
	if sizes == nil {
		t.Fatalf("expected non-nil dir sizes")
	}
	if sizes["anime"] != 7140112762 {
		t.Errorf("expected anime size 7140112762, got %d", sizes["anime"])
	}
	if sizes["tidy"] != 415365272841 {
		t.Errorf("expected tidy size 415365272841, got %d", sizes["tidy"])
	}
}
