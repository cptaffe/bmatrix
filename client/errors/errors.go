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
)

type ErrError struct {
	Code   Code
	Reason error
}

// ErrorMatrix implements Errorer for ErrError
func (e *ErrError) ErrorMatrix() *Error {
	return &Error{
		Code:   e.Code,
		Reason: e.Error(),
	}
}

// Error implements error for ErrError
func (e *ErrError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Reason)
}

// New ErrError Errorer from Code and error
func New(c Code, e error) *ErrError {
	return &ErrError{
		Code:   c,
		Reason: e,
	}
}
