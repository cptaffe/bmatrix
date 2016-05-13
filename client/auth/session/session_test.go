package session

import (
	"encoding/json"
	"testing"
)

func TestSessionJSON(t *testing.T) {
	b := []byte(`"a2RrZGtka2RrZGtka2RrZGtka2RrZGtka2RrZGtka2RrZGtka2RrZGtka2RrZGtka2RrZGtka2RrZGtka2RrZA=="`)
	t.Log("source string: " + string(b))
	s := Session{}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Error(err)
	}
	t.Log("parsed bytes: " + string(s.Token[:len(s.Token)]))
	buf, err := json.Marshal(&s)
	if err != nil {
		t.Error(err)
	}
	t.Log("encoded string: " + string(buf))
	if string(buf) != string(b) {
		t.Errorf("JSON representation of a session does not match the representation it was parsed from")
	}
}
