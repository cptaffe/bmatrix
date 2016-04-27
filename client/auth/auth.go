package auth

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cptaffe/bmatrix/client/errors"
)

// Stage represents the Matrix login type
type Stage string

const (
	PasswordStage  Stage = "m.login.password"
	RecaptchaStage       = "m.login.recaptcha"
	Oauth2Stage          = "m.login.oauth2"
	IdentityStage        = "m.login.email.identity"
	TokenStage           = "m.login.token"
	DummyStage           = "m.login.dummy"
)

// Flow represents a login/register flow for Matrix
type Flow struct {
	Stages []Stage `json:"stages"`
}

// Params represents a parameter dictionary
// for a login type
type Params map[string]interface{}

// Handler interface exposes the HandleAuth function
type Handler interface {
	// HandleAuth takes an auth request and returns a bool
	// or an error
	HandleAuth(auth map[string]interface{}) (bool, error)
}

// Auth represents Matrix login flows
type Auth struct {
	Flows    []Flow           `json:"flows"`
	Params   map[Stage]Params `json:"params"`
	Session  []byte           `json:"session"`
	handlers map[Stage]Handler
}

func (a *Auth) RegisterHandler(s Stage, h Handler) {
	a.handlers[s] = h
}

// Successful is the response given a successful auth
// attempt
type Successful struct {
	Completed []Stage          `json:"completed"`
	Flows     []Flow           `json:"flows"`
	Params    map[Stage]Params `json:"params"`
	Session   []byte           `json:"session"`
}

// Request represents the inner 'auth' key structure
// in a Matrix-compliant Auth request resubmittal of the original
// query
type Request struct {
	Stage   Stage
	Session string
	// Map is dependent on the type of authentication,
	// e.g. for password it would have the keys
	Auth map[string]interface{}
}

// MarshalJSON returns Matrix-compliant JSON for an 'auth' key value of
// an auth request
func (a *Request) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{}
	m["type"] = a.Stage
	m["session"] = string(a.Session)
	for k, v := range a.Auth {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// UnmarshalJSON unmarshals JSON
func (a *Request) UnmarshalJSON(b []byte) error {
	log.Println(string(b))
	m := map[string]interface{}{}
	if err := json.Unmarshal(b, &m); err != nil {
		return errors.New(errors.BadJSON, err)
	}
	if m["type"] == nil {
		return errors.New(errors.BadJSON, fmt.Errorf("Missing 'type' key in auth request auth section"))
	}
	a.Stage = m["type"].(Stage)
	if m["session"] == nil {
		return errors.New(errors.BadJSON, fmt.Errorf("Missing 'session' key in auth request auth section"))
	}
	a.Session = m["session"].(string)
	delete(m, "type")
	delete(m, "session")
	a.Auth = m
	return nil
}
