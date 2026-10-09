package dbtools

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/logs"
)

func TestDatabaseInitializationErrorsDoNotExposeCredentials(t *testing.T) {
	if os.Getenv("JXPKG_DB_ERROR_HELPER") == "1" {
		if err := logs.ReloadConfig("db-error-test", logs.LogsConfig{
			"default": {{Writer: "console"}},
		}); err != nil {
			t.Fatal(err)
		}
		defer logs.Close()
		for _, url := range []string{
			"mysql://PRIVATE_USER_CANARY:PRIVATE_PASSWORD_CANARY%zz@localhost/db",
			"mysql://PRIVATE_USER_CANARY:PRIVATE_PASSWORD_CANARY@localhost/db?timeout=PRIVATE_OPTION_CANARY",
			"mysql://PRIVATE_USER_CANARY:PRIVATE_PASSWORD_CANARY@127.0.0.1:bad/db",
			"private_scheme_canary://PRIVATE_USER_CANARY:PRIVATE_PASSWORD_CANARY@localhost/db",
			"mysql://127.0.0.1:bad/db",
		} {
			if _, err := InitDBConn("test", url); err == nil {
				t.Fatal("expected database initialization error")
			} else {
				fmt.Println(err)
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDatabaseInitializationErrorsDoNotExposeCredentials$")
	cmd.Env = append(os.Environ(), "JXPKG_DB_ERROR_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("database error helper failed: %v", err)
	}
	for _, canary := range []string{"PRIVATE_USER_CANARY", "PRIVATE_PASSWORD_CANARY", "PRIVATE_OPTION_CANARY", "private_scheme_canary"} {
		if strings.Contains(string(output), canary) {
			t.Fatalf("database startup output exposed a credential or option canary")
		}
	}
}

func TestNormalizeMySQLPreservesEmptyUserInformation(t *testing.T) {
	parsed, err := url.Parse("mysql://localhost/db")
	if err != nil {
		t.Fatal(err)
	}
	got, err := NormalizeMySQL(parsed)
	if err != nil || got != ":@tcp(localhost:3306)/db" {
		t.Fatalf("empty user information compatibility changed: %q, %v", got, err)
	}
}
