package dbtools

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeMySQL 将 mysql:// URI 转换为 go-sql-driver/mysql 的 DSN
func NormalizeMySQL(u *url.URL) (string, error) {
	user := u.User.Username()
	pass, _ := u.User.Password()
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "3306"
	}
	db := strings.TrimPrefix(u.Path, "/")

	query := u.RawQuery
	if query != "" {
		query = "?" + query
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s%s", user, pass, host, port, db, query), nil
}
