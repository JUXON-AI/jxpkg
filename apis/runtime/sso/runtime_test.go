package sso

import "testing"

func TestValidPrefix(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "JUXONONE", want: true},
		{value: "MY_APP_2", want: true},
		{value: "", want: false},
		{value: "JUXONONE_", want: false},
		{value: "juxonone", want: false},
		{value: "JUXONONE-API", want: false},
	} {
		if got := validPrefix(test.value); got != test.want {
			t.Fatalf("validPrefix(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestDecodeHostsRejectsAmbiguousInput(t *testing.T) {
	for _, raw := range []string{"", "[]", "[\"one.example.com\",\"one.example.com\"]", "[\"one.example.com\"] {}"} {
		if _, err := decodeHosts(raw); err == nil {
			t.Fatalf("decodeHosts(%q) unexpectedly succeeded", raw)
		}
	}
	hosts, err := decodeHosts("[\"one.example.com\",\"api.example.com\"]")
	if err != nil || len(hosts) != 2 {
		t.Fatalf("decodeHosts(valid) = %#v, %v", hosts, err)
	}
}

func TestLoadEnvFailsClosedBeforeReadingFiles(t *testing.T) {
	if runtime, err := LoadEnv(nil, "JUXONONE"); err == nil || runtime != nil {
		t.Fatalf("LoadEnv(nil) = %#v, %v", runtime, err)
	}
	if runtime, err := LoadEnv(func(string) string { return "" }, "juxonone"); err == nil || runtime != nil {
		t.Fatalf("LoadEnv(invalid prefix) = %#v, %v", runtime, err)
	}
}
