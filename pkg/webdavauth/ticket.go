// Package webdavauth defines the signed ticket exchanged between OpenList
// and an external WebDAV authentication service.
package webdavauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	TicketVersion  = 1
	QueryParameter = "ticket"
)

type Ticket struct {
	Version   int    `json:"v"`
	Audience  string `json:"aud,omitempty"`
	Path      string `json:"path"`
	UserID    uint   `json:"uid"`
	Username  string `json:"user"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"jti"`
}

func Issue(secret string, ticket Ticket) (string, error) {
	if secret == "" {
		return "", errors.New("webdav ticket secret is empty")
	}
	if ticket.Path == "" {
		return "", errors.New("webdav ticket path is empty")
	}
	if ticket.Version == 0 {
		ticket.Version = TicketVersion
	}
	if ticket.Version != TicketVersion {
		return "", fmt.Errorf("unsupported webdav ticket version: %d", ticket.Version)
	}
	if ticket.IssuedAt == 0 {
		ticket.IssuedAt = time.Now().Unix()
	}
	if ticket.ExpiresAt <= ticket.IssuedAt {
		return "", errors.New("webdav ticket expiration must be after issue time")
	}
	if ticket.Nonce == "" {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return "", fmt.Errorf("generate webdav ticket nonce: %w", err)
		}
		ticket.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	}
	payload, err := json.Marshal(ticket)
	if err != nil {
		return "", fmt.Errorf("marshal webdav ticket: %w", err)
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	signature := sign(secret, []byte(payloadPart))
	return payloadPart + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func Verify(secret, token string, now time.Time) (Ticket, error) {
	var ticket Ticket
	if secret == "" {
		return ticket, errors.New("webdav ticket secret is empty")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ticket, errors.New("invalid webdav ticket format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ticket, errors.New("invalid webdav ticket payload")
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ticket, errors.New("invalid webdav ticket signature")
	}
	if !hmac.Equal(provided, sign(secret, []byte(parts[0]))) {
		return ticket, errors.New("invalid webdav ticket signature")
	}
	if err := json.Unmarshal(payload, &ticket); err != nil {
		return ticket, errors.New("invalid webdav ticket payload")
	}
	if ticket.Version != TicketVersion || ticket.Path == "" || ticket.Nonce == "" {
		return ticket, errors.New("invalid webdav ticket claims")
	}
	if now.IsZero() {
		now = time.Now()
	}
	nowUnix := now.Unix()
	if ticket.IssuedAt > nowUnix || ticket.ExpiresAt <= nowUnix || ticket.ExpiresAt <= ticket.IssuedAt {
		return ticket, errors.New("webdav ticket is expired or not active")
	}
	return ticket, nil
}

func VerifyAudience(secret, token, audience string, now time.Time) (Ticket, error) {
	ticket, err := Verify(secret, token, now)
	if err != nil {
		return ticket, err
	}
	if ticket.Audience != audience {
		return ticket, errors.New("webdav ticket audience mismatch")
	}
	return ticket, nil
}

func sign(secret string, data []byte) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write(data)
	return h.Sum(nil)
}
