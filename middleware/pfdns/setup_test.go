package pfdns

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestSetuppfdns(t *testing.T) {
	c := caddy.NewTestController("dns", `pfdns`)
	if err := setuppfdns(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `pfdns example.org`)
	if err := setuppfdns(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}
}
