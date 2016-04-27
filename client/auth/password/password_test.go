package password

import "testing"

func TestEntropy(t *testing.T) {
	p := "correcthorsebatterystaple"
	e := Entropy(p)
	if e < 45 || e > 46 && e == Xkcd {
		t.Errorf("Entropy for '%s' is ~45, but returned '%f'", p, e)
	}
}
