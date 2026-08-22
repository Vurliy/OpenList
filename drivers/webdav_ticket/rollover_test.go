package webdav_ticket

import (
	"testing"
)

func TestWebDavTicketRolloverGeneration(t *testing.T) {
	d := &WebDavTicket{
		Addition: Addition{
			StorageGeneration: 2,
			WebDAVAuthAudience: "storage-test",
		},
	}
	if d.StorageGeneration != 2 {
		t.Fatalf("expected generation 2, got %d", d.StorageGeneration)
	}

	// Test GetAddition initializes generation to at least 1
	d2 := &WebDavTicket{}
	d2.GetAddition()
	if d2.StorageGeneration != 1 {
		t.Fatalf("expected default generation 1, got %d", d2.StorageGeneration)
	}
}
