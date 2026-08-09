package gowebdav

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSupportsRangeRequiresPartialContent(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		contentRange  string
		expectSupport bool
	}{
		{name: "partial content", status: http.StatusPartialContent, contentRange: "bytes 0-0/10", expectSupport: true},
		{name: "full response", status: http.StatusOK, expectSupport: false},
		{name: "invalid content range", status: http.StatusPartialContent, contentRange: "bytes 1-1/10", expectSupport: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Range"); got != "bytes=0-0" {
					t.Fatalf("unexpected Range header: %q", got)
				}
				if tt.contentRange != "" {
					w.Header().Set("Content-Range", tt.contentRange)
				}
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			client := NewClient(srv.URL, "", "")
			got, err := client.SupportsRange("/")
			if err != nil {
				t.Fatalf("SupportsRange returned error: %v", err)
			}
			if got != tt.expectSupport {
				t.Fatalf("SupportsRange = %v, want %v", got, tt.expectSupport)
			}
		})
	}
}
