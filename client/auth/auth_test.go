package auth

import (
	"encoding/json"
	"testing"

	"github.com/cptaffe/bmatrix/client/auth/session"
)

func TestAuthJSON(t *testing.T) {
	b := []byte(`{"flows":[{"stages":["example.type.foo","example.type.bar"]},{"stages":["example.type.foo","example.type.baz"]}],"params":{"example.type.baz":{"example_key":"foobar"}},"session":"xxxxxx"}`)
	a := Resp{}
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
		t.Errorf("Serializes incorrectly")
	}
}

// TODO: fill in login method testing

func TestDummyPasswordLogin(t *testing.T) {
	s, err := session.New()
	if err != nil {
		t.Error(err)
	}
	// Craft auth response to supposed unauthenticated request
	a := Resp{
		Flows: []Flow{
			// A single password flow
			Flow{
				Stages: []Stage{
					PasswordStage,
				},
			},
		},
		Session: s,
	}

	buf, err := json.Marshal(a)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(buf))
}

func TestDummyCaptchaLogin(*testing.T) {}

func TestDummyOAuth2Login(*testing.T) {}
