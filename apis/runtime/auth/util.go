package auth

import "errors"

// LoginWay 登录方式枚举。
type LoginWay uint8

const (
	LoginWayUnknown LoginWay = 0
	LoginWayEmail   LoginWay = 1
	LoginWayPhone   LoginWay = 2
)

var (
	ErrInvalidLoginWay = errors.New("invalid login way")
)
