package errors

import "fmt"

// Errorer exposes an interface for Matrix Errors
// allowing them to be returned as normal errors
type Errorer interface {
	ErrorMatrix() *Error
}

// Code is used to specify a Matrix error
type Code string

// Error represents a Matrix "standard error response"
type Error struct {
	Code   Code   `json:"errcode"`
	Reason string `json:"error"`
}

const (
	Forbidden     Code = "M_FORBIDDEN"
	UnknownToken       = "M_UNKNOWN_TOKEN"
	BadJSON            = "M_BAD_JSON"
	NotJSON            = "M_NOT_JSON"
	NotFound           = "M_NOT_FOUND"
	LimitExceeded      = "M_LIMIT_EXCEEDED"
	UserInUse          = "M_USER_IN_USE"
	RoomInUse          = "M_ROOM_IN_USE"
	BadPagination      = "M_BAD_PAGINATION"
	WeakPassword       = "M_WEAK_PASSWORD"
)

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Reason)
}

// New ErrError Errorer from Code and error
func New(c Code, e error) *Error {
	return &Error{
		Code:   c,
		Reason: e.Error(),
	}
}
