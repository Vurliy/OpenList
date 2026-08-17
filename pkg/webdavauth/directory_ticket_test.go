package webdavauth

import "testing"

func TestDirectoryTicketIsStableAndCoversNestedPaths(t *testing.T) {
	claims := Ticket{
		Type: TicketTypeDirectory, Audience: "storage-1", UserID: 42,
		TokenDigest: TokenDigest("jwt-a"), Scope: "/thumbnails/movie", Recursive: true,
		Generation: AuthGeneration,
	}
	one, err := IssuePathBound("secret", DefaultAuthNonce, claims)
	if err != nil {
		t.Fatal(err)
	}
	two, err := IssuePathBound("secret", DefaultAuthNonce, claims)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("directory ticket changed: %q / %q", one, two)
	}
	decoded, err := VerifyPathBound("secret", DefaultAuthNonce, one, "/thumbnails/movie/sub/a.mp4.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != TicketTypeDirectory || decoded.Path != "" || !decoded.Recursive {
		t.Fatalf("unexpected claims: %+v", decoded)
	}
	if _, err := VerifyPathBound("secret", DefaultAuthNonce, one, "/thumbnails/movies/a.mp4.jpg"); err == nil {
		t.Fatal("directory boundary was crossed")
	}
}

func TestNonRecursiveDirectoryTicketRejectsNestedPath(t *testing.T) {
	claims := Ticket{Type: TicketTypeDirectory, Audience: "storage-1", UserID: 42,
		TokenDigest: TokenDigest("jwt-a"), Scope: "/thumbnails/movie", Generation: AuthGeneration}
	token, err := IssuePathBound("secret", DefaultAuthNonce, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPathBound("secret", DefaultAuthNonce, token, "/thumbnails/movie/sub/a.jpg"); err == nil {
		t.Fatal("nested path accepted by non-recursive ticket")
	}
	if _, err := VerifyPathBound("secret", DefaultAuthNonce, token, "/thumbnails/movie/a.jpg"); err != nil {
		t.Fatal(err)
	}
}
