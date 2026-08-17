// Package webdavauth defines the signed, path-bound capability exchanged by
// OpenList and an external WebDAV authorization service.
package webdavauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

const (
	TicketVersion        = 4
	QueryParameter       = "ticket"
	AuthGeneration       = "fixed-v1"
	GrantVersion         = 4
	GrantTypeSessionBind = "session_bind"
	TicketTypeFile       = "file"
	TicketTypeDirectory  = "directory"
	// DefaultAuthNonce is only a compatibility value for old storage records.
	// Production storage records should set webdav_auth_nonce explicitly.
	DefaultAuthNonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// Ticket is the deterministic v4 payload. File tickets bind one resource to
// Path; directory tickets bind a whole directory scope and leave Path empty so
// every thumbnail in that directory can reuse one ticket.
type Ticket struct {
	Version     int    `json:"v"`
	Type        string `json:"type"`
	Audience    string `json:"aud"`
	UserID      uint   `json:"uid"`
	TokenDigest string `json:"token_digest"`
	Scope       string `json:"scope"`
	Path        string `json:"path,omitempty"`
	Recursive   bool   `json:"recursive,omitempty"`
	Generation  string `json:"auth_generation"`
	// Deprecated v1 fields are kept only so older callers can be migrated
	// without a source-level break. v4 issuance and verification ignore them.
	Username  string `json:"-"`
	IssuedAt  int64  `json:"-"`
	ExpiresAt int64  `json:"-"`
	Nonce     string `json:"-"`
}

// Grant is a one-time session-bind record. It is deliberately independent of
// the stable Ticket, so refreshing the same file does not create a new grant.
type Grant struct {
	Version           int    `json:"v"`
	Type              string `json:"type"`
	GrantID           string `json:"grant_id"`
	Audience          string `json:"aud"`
	UserID            uint   `json:"uid"`
	TokenDigest       string `json:"token_digest"`
	Scope             string `json:"scope"`
	TicketFingerprint string `json:"ticket_fingerprint"`
	AuthNonce         string `json:"auth_nonce"`
	Generation        string `json:"auth_generation"`
	State             string `json:"state"`
	CreatedAt         int64  `json:"created_at"`
	ExpiresAt         int64  `json:"expires_at"`
	Signature         string `json:"signature"`
}

// TokenDigest returns the non-reversible identifier used in Tickets and
// sessions. The raw token must never be persisted or logged by this package.
func TokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// ValidateNonce validates the configured base64url nonce. Requiring exactly
// 32 decoded bytes keeps the protocol deterministic and prevents accidental
// use of a human password as key material.
func ValidateNonce(value string) error {
	if value == "" {
		return errors.New("webdav auth nonce is empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("webdav auth nonce must be an unpadded base64url value encoding 32 bytes")
	}
	return nil
}

func NormalizeNonce(value string) (string, error) {
	if value == "" {
		value = DefaultAuthNonce
	}
	if err := ValidateNonce(value); err != nil {
		return "", err
	}
	return value, nil
}

// CanonicalPath normalizes the public URL path and rejects traversal. The
// external WebDAV path, not the provider's private filesystem path, is signed.
func CanonicalPath(value string) (string, error) {
	if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsRune(value, '\x00') || strings.Contains(value, "\\") {
		return "", errors.New("invalid webdav public path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", errors.New("webdav public path traversal is not allowed")
		}
	}
	clean := path.Clean(value)
	if clean == "." || !strings.HasPrefix(clean, "/") {
		return "", errors.New("invalid webdav public path")
	}
	return clean, nil
}

func ScopeContains(scope, candidate string) bool {
	scope, err := CanonicalPath(scope)
	if err != nil || scope == "/" {
		return err == nil && scope == "/"
	}
	candidate, err = CanonicalPath(candidate)
	if err != nil {
		return false
	}
	return candidate == scope || strings.HasPrefix(candidate, scope+"/")
}

// DeriveKey binds the HMAC key to this storage's configured auth nonce without
// exposing the nonce in the Ticket payload.
func DeriveKey(secret, nonce string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("webdav ticket secret is empty")
	}
	nonce, err := NormalizeNonce(nonce)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte("openlist-webdav-ticket-v4\x00"))
	decoded, _ := base64.RawURLEncoding.DecodeString(nonce)
	_, _ = h.Write(decoded)
	return h.Sum(nil), nil
}

func IssuePathBound(secret, nonce string, ticket Ticket) (string, error) {
	if ticket.Version == 0 {
		ticket.Version = TicketVersion
	}
	if ticket.Version != TicketVersion || ticket.Audience == "" || ticket.TokenDigest == "" || ticket.Scope == "" {
		return "", errors.New("invalid webdav ticket claims")
	}
	if ticket.Type == "" {
		ticket.Type = TicketTypeFile
	}
	if ticket.Type != TicketTypeFile && ticket.Type != TicketTypeDirectory {
		return "", errors.New("invalid webdav ticket type")
	}
	if ticket.Type == TicketTypeFile && ticket.Path == "" {
		return "", errors.New("file webdav ticket path is empty")
	}
	if ticket.Type == TicketTypeDirectory && ticket.Path != "" {
		return "", errors.New("directory webdav ticket must not contain a path")
	}
	var err error
	ticket.Scope, err = CanonicalPath(ticket.Scope)
	if err != nil {
		return "", err
	}
	if ticket.Path != "" {
		ticket.Path, err = CanonicalPath(ticket.Path)
		if err != nil || !ScopeContains(ticket.Scope, ticket.Path) {
			return "", errors.New("webdav ticket path is outside scope")
		}
	}
	if ticket.Generation == "" {
		ticket.Generation = AuthGeneration
	}
	if _, err := NormalizeNonce(nonce); err != nil {
		return "", err
	}
	payload, err := json.Marshal(ticket)
	if err != nil {
		return "", fmt.Errorf("marshal webdav ticket: %w", err)
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	key, err := DeriveKey(secret, nonce)
	if err != nil {
		return "", err
	}
	signature := hmacBytes(key, []byte(payloadPart))
	return payloadPart + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func VerifyPathBound(secret, nonce, token, publicPath string) (Ticket, error) {
	var ticket Ticket
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ticket, errors.New("invalid webdav ticket format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 4096 {
		return ticket, errors.New("invalid webdav ticket payload")
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(provided) != sha256.Size {
		return ticket, errors.New("invalid webdav ticket signature")
	}
	key, err := DeriveKey(secret, nonce)
	if err != nil || !hmac.Equal(provided, hmacBytes(key, []byte(parts[0]))) {
		return ticket, errors.New("invalid webdav ticket signature")
	}
	if err := json.Unmarshal(payload, &ticket); err != nil || ticket.Version != TicketVersion ||
		ticket.Type == "" || ticket.Audience == "" || ticket.TokenDigest == "" || ticket.Scope == "" {
		return ticket, errors.New("invalid webdav ticket claims")
	}
	if ticket.Type != TicketTypeFile && ticket.Type != TicketTypeDirectory {
		return ticket, errors.New("invalid webdav ticket type")
	}
	if ticket.Type == TicketTypeFile && ticket.Path == "" {
		return ticket, errors.New("file webdav ticket path is empty")
	}
	if ticket.Type == TicketTypeDirectory && ticket.Path != "" {
		return ticket, errors.New("directory webdav ticket must not contain a path")
	}
	if ticket.Generation == "" {
		return ticket, errors.New("webdav ticket generation is empty")
	}
	ticket.Scope, err = CanonicalPath(ticket.Scope)
	if err != nil {
		return ticket, err
	}
	if ticket.Path != "" {
		ticket.Path, err = CanonicalPath(ticket.Path)
		if err != nil || !ScopeContains(ticket.Scope, ticket.Path) {
			return ticket, errors.New("webdav ticket path is outside scope")
		}
	}
	if publicPath != "" {
		publicPath, err = CanonicalPath(publicPath)
		if err != nil {
			return ticket, errors.New("webdav ticket path mismatch")
		}
		if ticket.Type == TicketTypeFile {
			if publicPath != ticket.Path {
				return ticket, errors.New("webdav ticket path mismatch")
			}
		} else if !ScopeContains(ticket.Scope, publicPath) || (!ticket.Recursive && path.Dir(publicPath) != ticket.Scope) {
			return ticket, errors.New("webdav directory ticket scope mismatch")
		}
	}
	return ticket, nil
}

// NewGrant creates a v3 grant. The state is filled only by the authorize API;
// Link must never create an unbound grant.
func NewGrant(grantID, ticketText, nonce, state string, claims Ticket, now, expiry int64) (Grant, error) {
	if !safeGrantID(grantID) {
		return Grant{}, errors.New("invalid webdav grant id")
	}
	nonce, err := NormalizeNonce(nonce)
	if err != nil {
		return Grant{}, err
	}
	grant := Grant{
		Version: GrantVersion, Type: GrantTypeSessionBind, GrantID: grantID,
		Audience: claims.Audience, UserID: claims.UserID, TokenDigest: claims.TokenDigest,
		Scope: claims.Scope, TicketFingerprint: TicketFingerprint(ticketText),
		AuthNonce: nonce, Generation: claims.Generation, State: state,
		CreatedAt: now, ExpiresAt: expiry,
	}
	grant.Signature = SignGrant("", grant)
	return grant, nil
}

// SignGrant uses the shared WebDAV secret. The empty-secret result is useful
// for callers that want to build the canonical body before signing; production
// callers must pass the configured secret.
func SignGrant(secret string, grant Grant) string {
	return base64.RawURLEncoding.EncodeToString(hmacBytes([]byte(secret), []byte(CanonicalGrant(grant))))
}

func CanonicalGrant(grant Grant) string {
	return fmt.Sprintf("v=%d\ntype=%s\ngrant_id=%s\naud=%s\nuid=%d\ntoken_digest=%s\nscope=%s\nticket_fingerprint=%s\nauth_nonce=%s\nauth_generation=%s\nstate=%s\ncreated_at=%d\nexpires_at=%d\n",
		grant.Version, grant.Type, grant.GrantID, grant.Audience, grant.UserID,
		grant.TokenDigest, grant.Scope, grant.TicketFingerprint, grant.AuthNonce,
		grant.Generation, grant.State, grant.CreatedAt, grant.ExpiresAt)
}

func TicketFingerprint(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func NewGrantID() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func safeGrantID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func hmacBytes(key, value []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(value)
	return h.Sum(nil)
}

// Issue/Verify are compatibility helpers for callers that only need a
// path-bound ticket and have already selected the default nonce.
func Issue(secret string, ticket Ticket) (string, error) {
	if ticket.TokenDigest == "" {
		// Compatibility callers used Username as the identity field. This path
		// is not used by the v3 driver, but gives old integrations a safe,
		// deterministic migration result.
		ticket.TokenDigest = TokenDigest(ticket.Username)
	}
	if ticket.Scope == "" {
		parts := strings.Split(strings.TrimPrefix(ticket.Path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			return "", errors.New("webdav ticket scope is empty")
		}
		ticket.Scope = "/" + parts[0]
	}
	return IssuePathBound(secret, DefaultAuthNonce, ticket)
}

func Verify(secret, token string, _ ...interface{}) (Ticket, error) {
	return VerifyPathBound(secret, DefaultAuthNonce, token, "")
}

func VerifyAudience(secret, token, audience string, _ ...interface{}) (Ticket, error) {
	ticket, err := Verify(secret, token)
	if err != nil {
		return ticket, err
	}
	if ticket.Audience != audience {
		return ticket, errors.New("webdav ticket audience mismatch")
	}
	return ticket, nil
}
