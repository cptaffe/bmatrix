package password

import zxcbvn "github.com/nbutton23/zxcvbn-go"

var (
	// Xkcd is the password entropy for the famous
	// xkcd password 'correcthorsebatterystaple',
	// it is given here as a reference for a good password
	Xkcd = Entropy("correcthorsebatterystaple")
)

// Entropy returns a password's entropy
func Entropy(p string) float64 {
	return zxcbvn.PasswordStrength(p, nil).Entropy
}
