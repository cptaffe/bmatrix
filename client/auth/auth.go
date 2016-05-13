package auth

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/cptaffe/bmatrix/client/auth/session"
	"github.com/cptaffe/bmatrix/client/errors"
)

// Stage represents the Matrix login type
type Stage string

const (
	PasswordStage      Stage = "m.login.password"
	RecaptchaStage           = "m.login.recaptcha"
	Oauth2Stage              = "m.login.oauth2"
	EmailIdentityStage       = "m.login.email.identity"
	TokenStage               = "m.login.token"
	DummyStage               = "m.login.dummy"
)

// Handler interface exposes the HandleAuth function
type Handler interface {
	// HandleAuth takes an auth request and returns a bool
	// or an error
	HandleAuth(auth map[string]interface{}) (bool, error)
}

// Auth represents a map of authentication stages to authentication handlers
type Auth struct {
	Handlers map[Stage]Handler
}

// Flow represents a login/register flow for Matrix
type Flow struct {
	Stages []Stage `json:"stages"`
}

// Params represents a parameter dictionary
// for a login type
type Params map[string]interface{}

// Resp is the response sent to a client in response
// to an unauthenticated request
type Resp struct {
	Flows   []Flow           `json:"flows"`
	Params  map[Stage]Params `json:"params"`
	Session *session.Session `json:"session"`
}

func (a *Auth) RegisterHandler(s Stage, h Handler) {
	a.Handlers[s] = h
}

// SuccessResp is the response given a successful auth
// attempt
type SuccessResp struct {
	Completed []Stage          `json:"completed"`
	Flows     []Flow           `json:"flows"`
	Params    map[Stage]Params `json:"params"`
	Session   *session.Session `json:"session"`
}

// Reply represents the inner 'auth' key structure
// in a Matrix-compliant Auth request resubmittal of the original
// query
type Reply struct {
	Stage   Stage
	Session *session.Session
	// Map is dependent on the type of authentication,
	// e.g. for password it would have the keys
	Auth map[string]interface{}
}

// MarshalJSON returns Matrix-compliant JSON for an 'auth' key value of
// an auth request
func (a *Reply) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{}
	m["type"] = a.Stage
	m["session"] = a.Session.Token
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
func (a *Reply) UnmarshalJSON(b []byte) error {
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
	a.Session = m["session"].(*session.Session)
	delete(m, "type")
	delete(m, "session")
	a.Auth = m
	return nil
}
