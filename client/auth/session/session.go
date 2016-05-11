package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

type Session struct {
	Token string
}

func New() (*Session, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return &Session{
		Token: base64.StdEncoding.EncodeToString(b),
	}, nil
}

func (s *Session) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Token)
}

func (s *Session) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.Token)
}
