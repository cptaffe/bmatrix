package password

import (
	"encoding/json"
	"fmt"

	"github.com/cptaffe/bmatrix/client/auth"
	"github.com/cptaffe/bmatrix/client/errors"
	zxcbvn "github.com/nbutton23/zxcvbn-go"
)

// Implements Matrix r0.1.0 §3.1.2.1

var (
	// Xkcd is the password entropy for the famous
	// xkcd password 'correcthorsebatterystaple',
	// it is given here as a reference for a good password
	Xkcd = Password("correcthorsebatterystaple")
)

// Password represents a passsword
type Password string

// Entropy returns a password's entropy
func (p Password) Entropy() float64 {
	return zxcbvn.PasswordStrength(string(p), nil).Entropy
}

// Handler implements auth.Handler
type Handler struct {
	AuthUser AuthUser
	Auth3PID Auth3PID
}

// AuthUser authenticates a user reply
type AuthUser interface {
	AuthenticateUser(*ReplyUser) (bool, error)
}

// Auth3PID authenticates a 3pid reply
type Auth3PID interface {
	Authenticate3PID(*Reply3PID) (bool, error)
}

// HandleAuth handles parsing the authentication information into the
// correct type and calling Authenticate
// NOTE: on absence of corresponding Auth member, silently fails
func (h *Handler) HandleAuth(a map[string]interface{}) (bool, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return false, errors.New(errors.BadJSON, err)
	}
	if a["user"] != nil {
		// ReplyUser style reply
		rp := &ReplyUser{}
		if err := json.Unmarshal(b, rp); err != nil {
			return false, errors.New(errors.BadJSON, err)
		}
		if h.AuthUser != nil {
			return rp.Authenticate(h.AuthUser)
		}
		return false, nil
	} else if a["medium"] != nil {
		// medium must equal 'email'
		// Reply3PID style reply
		rp := &Reply3PID{}
		if err := json.Unmarshal(b, rp); err != nil {
			return false, errors.New(errors.BadJSON, err)
		}
		if h.Auth3PID != nil {
			return rp.Authenticate(h.Auth3PID)
		}
		return false, nil
	}
	return false, errors.New(errors.UnknownToken, fmt.Errorf("Improper format for reply, see §3.1.2.1"))
}

func testPasswordEntropy(p Password) error {
	if p.Entropy() < 0.8*Xkcd.Entropy() {
		return errors.New(errors.WeakPassword, fmt.Errorf("Password is %fx < 0.8x the entropy of the reference password '%s'; see https://xkcd.com/936/", p.Entropy()/Xkcd.Entropy(), string(Xkcd)))
	}
	return nil
}

// ReplyUser is the Auth reply
type ReplyUser struct {
	Type     auth.Stage `json:"type"` // must be auth.PasswordStage
	User     string     `json:"user"`
	Password Password   `json:"password"`
}

// Authenticate authenticates a user
func (r *ReplyUser) Authenticate(auth AuthUser) (bool, error) {
	if err := testPasswordEntropy(r.Password); err != nil {
		return false, err
	}
	// TODO: authenticate with credentials
	return auth.AuthenticateUser(r)
}

// Medium represents possible mediums
type Medium string

const (
	// EmailMedium is currently the only supported medium
	EmailMedium Medium = "email"
)

// TODO: UnmarshalJSON check that it equals EmailMedium

// Reply3PID is 3rd party identification
type Reply3PID struct {
	Type     auth.Stage `json:"type"`
	Medium   Medium     `json:"medium"` // "has to be 'email'"
	Address  string     `json:"address"`
	Password Password   `json:"password"`
}

// Authenticate authenticates a user via 3pid
func (r *Reply3PID) Authenticate(auth Auth3PID) (bool, error) {
	// sanity check because we don't have special checks in parsing
	if r.Medium != EmailMedium {
		return false, errors.New(errors.UnknownToken, fmt.Errorf("3pid requests must have 'medium' as 'email'; see §3.1.2.1"))
	}
	if err := testPasswordEntropy(r.Password); err != nil {
		return false, err
	}
	// TODO: authenticate with credentials
	return auth.Authenticate3PID(r)
}
