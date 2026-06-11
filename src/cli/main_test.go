package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestTruncate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"under limit", "short", 10, "short"},
		{"exactly limit", "abcde", 5, "abcde"},
		{"word boundary", "alpha beta gamma delta", 14, "alpha beta…"},
		{"single long token hard cut", "supercalifragilisticexpialidocious", 10, "supercali…"},
		{"early boundary keeps hard cut", "a verylongtokenwithoutspaces here", 12, "a verylongt…"},
		{"trailing spaces trimmed before ellipsis", "alpha   gamma delta", 12, "alpha…"},
		{"multibyte counted by rune", "ünïcödé wörds here", 10, "ünïcödé…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.in, tc.n); got != tc.want {
				t.Fatalf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
			if r := []rune(truncate(tc.in, tc.n)); len(r) > tc.n {
				t.Fatalf("truncate(%q, %d) = %d runes, exceeds limit %d", tc.in, tc.n, len(r), tc.n)
			}
		})
	}
}

// newCreateFlagCmd builds a command carrying just the secret-source flags resolveCreateSecret
// inspects, so tests can drive Changed() exactly as cmdCreate would.
func newCreateFlagCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "create", RunE: func(*cobra.Command, []string) error { return nil }}
	c.Flags().String("secret", "", "")
	c.Flags().Bool("secret-stdin", false, "")
	c.Flags().String("secret-env", "", "")
	if err := c.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags(%v): %v", args, err)
	}
	return c
}

func TestResolveCreateSecret(t *testing.T) {
	t.Run("flag value", func(t *testing.T) {
		c := newCreateFlagCmd(t, "--secret", "sek")
		got, err := resolveCreateSecret(c, "sek", "", false)
		if err != nil || got != "sek" {
			t.Fatalf("got (%q, %v), want (\"sek\", nil)", got, err)
		}
	})

	t.Run("none provided", func(t *testing.T) {
		c := newCreateFlagCmd(t)
		if _, err := resolveCreateSecret(c, "", "", false); err == nil {
			t.Fatal("expected error when no secret source is given")
		}
	})

	t.Run("mutually exclusive", func(t *testing.T) {
		c := newCreateFlagCmd(t, "--secret", "a", "--secret-env", "X")
		if _, err := resolveCreateSecret(c, "a", "X", false); err == nil {
			t.Fatal("expected error when --secret and --secret-env both set")
		}
	})

	t.Run("env value", func(t *testing.T) {
		t.Setenv("DWVAULT_TEST_SECRET", "fromenv")
		c := newCreateFlagCmd(t, "--secret-env", "DWVAULT_TEST_SECRET")
		got, err := resolveCreateSecret(c, "", "DWVAULT_TEST_SECRET", false)
		if err != nil || got != "fromenv" {
			t.Fatalf("got (%q, %v), want (\"fromenv\", nil)", got, err)
		}
	})

	t.Run("env unset", func(t *testing.T) {
		c := newCreateFlagCmd(t, "--secret-env", "DWVAULT_TEST_MISSING")
		if _, err := resolveCreateSecret(c, "", "DWVAULT_TEST_MISSING", false); err == nil {
			t.Fatal("expected error when the named env var is unset")
		}
	})

	t.Run("empty flag value", func(t *testing.T) {
		c := newCreateFlagCmd(t, "--secret", "")
		if _, err := resolveCreateSecret(c, "", "", false); err == nil {
			t.Fatal("expected error when the resolved secret is empty")
		}
	})
}
