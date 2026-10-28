package middleware

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var errInvalidCanonicalHost = errors.New("host is not canonical")

func validateCanonicalHost(host string) error {
	if host == "" || host != strings.ToLower(host) || strings.TrimSpace(host) != host || strings.Contains(host, "\\") {
		return errInvalidCanonicalHost
	}
	parsed, err := url.Parse("http://" + host)
	if err != nil || parsed.Host != host || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errInvalidCanonicalHost
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.HasSuffix(hostname, ".") || strings.HasSuffix(host, ":") {
		return errInvalidCanonicalHost
	}
	if ip := net.ParseIP(hostname); ip == nil {
		if strings.Trim(hostname, "0123456789.") == "" || validateDNSName(hostname) != nil {
			return errInvalidCanonicalHost
		}
	} else if ip.String() != hostname {
		return errInvalidCanonicalHost
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return errInvalidCanonicalHost
		}
	}
	return nil
}

func validateDNSName(hostname string) error {
	if len(hostname) > 253 {
		return errInvalidCanonicalHost
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errInvalidCanonicalHost
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errInvalidCanonicalHost
			}
		}
	}
	return nil
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}\t", character) {
			return false
		}
	}
	return true
}
