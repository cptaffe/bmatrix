package password

import (
	"encoding/json"
	"testing"
)

func TestEntropy(t *testing.T) {
	e := Xkcd.Entropy()
	if e < 45 || e > 46 {
		t.Errorf("Entropy for '%s' is ~45, but returned '%f'", string(Xkcd), e)
	}
}

type testAuther struct {
	Pass string
}

func (t *testAuther) Authenticate3PID(r *Reply3PID) (bool, error) {
	return string(r.Password) == t.Pass, nil
}

func (t *testAuther) AuthenticateUser(r *ReplyUser) (bool, error) {
	return string(r.Password) == t.Pass, nil
}

func TestHandleAuth(t *testing.T) {
	ur := []byte(`{
  "type": "m.login.password",
  "user": "cptaffe",
  "password": "abc"
}`)
	urm := map[string]interface{}{}
	if err := json.Unmarshal(ur, &urm); err != nil {
		t.Error(err)
	}
	ta := &testAuther{Pass: "abc"}
	b, err := (&Handler{
		Auth3PID: ta,
		AuthUser: ta,
	}).HandleAuth(urm)
	t.Log(err)
	if b != false || err == nil {
		t.Errorf("Password should have been too weak")
	}
}

func TestHandleAuth3PID(t *testing.T) {
	ur := []byte(`{
  "type": "m.login.password",
  "user": "cptaffe",
  "medium": "email",
	"address": "cpaynetaffe@gmail.com",
	"password": "zaba;"
}`)
	urm := map[string]interface{}{}
	if err := json.Unmarshal(ur, &urm); err != nil {
		t.Error(err)
	}
	ta := &testAuther{Pass: "abc"}
	b, err := (&Handler{
		Auth3PID: ta,
		AuthUser: ta,
	}).HandleAuth(urm)
	t.Log(err)
	if b != false || err == nil {
		t.Errorf("Password should have been too weak")
	}
}
