package blackhole

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestSetupblackhole(t *testing.T) {
	c := caddy.NewTestController("dns", `blackhole`)
	if err := setupblackhole(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `blackhole example.org 127.0.0.1`)
	if err := setupblackhole(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}
}
