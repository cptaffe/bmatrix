package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

var encoding = base64.URLEncoding

// Session stores the user's session token
type Session struct {
	Token []byte
}

// New creates a new Session with a random token
func New() (*Session, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return &Session{
		Token: b,
	}, nil
}

// MarshalJSON returns a URL-safe base64'd string encoded to JSON
func (s *Session) MarshalJSON() ([]byte, error) {
	return json.Marshal(encoding.EncodeToString(s.Token))
}

// UnmarshalJSON decodes from a JSON encoded URL-safe base64 string
func (s *Session) UnmarshalJSON(b []byte) error {
	str := ""
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	b, err := encoding.DecodeString(str)
	if err != nil {
		return err
	}
	s.Token = b
	return nil
}
