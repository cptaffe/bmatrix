package versions

// Versions represents the response from _matrix/client/versions
type Versions struct {
	Versions []string `json:"versions"`
}
