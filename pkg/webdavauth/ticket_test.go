package webdavauth

import "testing"

func TestPathBoundTicketIsStableAndCarriesNoSecretOrExpiry(t *testing.T) {
	nonce := DefaultAuthNonce
	claims := Ticket{Audience: "webdav-1", UserID: 42, TokenDigest: TokenDigest("jwt-a"), Scope: "/download", Path: "/download/movie.mp4", Generation: AuthGeneration}
	one, err := IssuePathBound("secret", nonce, claims)
	if err != nil {
		t.Fatal(err)
	}
	two, err := IssuePathBound("secret", nonce, claims)
	if err != nil || one != two {
		t.Fatalf("same claims did not produce a stable ticket: %q / %q / %v", one, two, err)
	}
	decoded, err := VerifyPathBound("secret", nonce, one, "/download/movie.mp4")
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Path != claims.Path || decoded.TokenDigest != claims.TokenDigest || decoded.Generation != AuthGeneration {
		t.Fatalf("unexpected claims: %+v", decoded)
	}
	if decoded.Username != "" || decoded.ExpiresAt != 0 || decoded.Nonce != "" {
		t.Fatalf("v3 ticket retained deprecated material: %+v", decoded)
	}
}

func TestPathAndNonceAreBoundBySignature(t *testing.T) {
	claims := Ticket{Audience: "webdav-1", UserID: 42, TokenDigest: TokenDigest("jwt-a"), Scope: "/download", Path: "/download/a.mp4", Generation: AuthGeneration}
	token, err := IssuePathBound("secret", DefaultAuthNonce, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPathBound("wrong", DefaultAuthNonce, token, claims.Path); err == nil {
		t.Fatal("wrong secret was accepted")
	}
	if _, err := VerifyPathBound("secret", DefaultAuthNonce, token, "/download/b.mp4"); err == nil {
		t.Fatal("ticket was accepted for another path")
	}
	if _, err := VerifyPathBound("secret", "AQ", token, claims.Path); err == nil {
		t.Fatal("invalid nonce was accepted")
	}
}

func TestScopeBoundary(t *testing.T) {
	if !ScopeContains("/download", "/download/sub/file.mp4") {
		t.Fatal("scope should include children")
	}
	if ScopeContains("/download", "/download2/file.mp4") {
		t.Fatal("scope crossed a directory boundary")
	}
	if _, err := CanonicalPath("/download/../secret"); err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestGrantIDAndCanonicalSignature(t *testing.T) {
	grantID, err := NewGrantID()
	if err != nil || grantID == "" {
		t.Fatal(err)
	}
	claims := Ticket{Audience: "webdav-1", UserID: 7, TokenDigest: TokenDigest("jwt"), Scope: "/download", Path: "/download/a.mp4", Generation: AuthGeneration}
	grant, err := NewGrant(grantID, "ticket", DefaultAuthNonce, "state", claims, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = SignGrant("secret", grant)
	if got := SignGrant("secret", grant); got != grant.Signature {
		t.Fatal("grant signature is not deterministic")
	}
	if grant.TicketFingerprint != TicketFingerprint("ticket") || grant.AuthNonce != DefaultAuthNonce {
		t.Fatalf("unexpected grant: %+v", grant)
	}
}
