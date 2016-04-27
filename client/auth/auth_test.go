package auth

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestAuthJSON(t *testing.T) {
	b := []byte(`{"flows":[{"stages":["example.type.foo","example.type.bar"]},{"stages":["example.type.foo","example.type.baz"]}],"params":{"example.type.baz":{"example_key":"foobar"}},"session":"xxxxxx"}`)
	a := Auth{}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Error(err)
	}
	t.Log(a)
	buf, err := json.Marshal(a)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(buf))
	if string(buf) != string(b) {
		t.Error(fmt.Errorf("Serializes incorrectly"))
	}
}

// TODO: fill in login method testing

func TestDummyPasswordLogin(*testing.T) {}

func TestDummyCaptchaLogin(*testing.T) {}

func TestDummyOAuth2Login(*testing.T) {}
