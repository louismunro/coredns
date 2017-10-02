package pfdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/coredns/core/dnsserver"
	"github.com/miekg/coredns/middleware"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("pfdns", caddy.Plugin{
		ServerType: "dns",
		Action:     setuppfdns,
	})
}

func setuppfdns(c *caddy.Controller) error {
	var pf *pfdns = &pfdns{}
	var ip net.IP
	enforce := false

	for c.Next() {
		// block with extra parameters
		var hadBlock bool
		for c.NextBlock() {
			hadBlock = true
			switch c.Val() {
			case "enforcement":
				arg := c.RemainingArgs()
				if strings.ToUpper(arg[0]) == "FALSE" {
					enforce = false
				} else if strings.ToUpper(arg[0]) == "TRUE" {
					enforce = true
				} else {
					return c.Errf("Wrong value type name or value type not supported: '%s'", c.Val())
				}
			case "redirectTo":
				arg := c.RemainingArgs()
				ip = net.ParseIP(arg[0])
				if ip == nil {
					return c.Errf("Invalid IP address '%s'", c.Val())
				}
			case "blackhole":
				// The possible values are:
				// blackhole (using the defaults)
				// blackhole disabled (or false)
				// blackhole $CNAME $IP
				pf.BhIp = net.ParseIP("127.0.0.1")
				pf.BhCname = "localhost.localdomain."
				pf.Bh = true

				args := c.RemainingArgs()
				switch len(args) {
				case 1:
					if (strings.ToUpper(args[1]) == "DISABLED") || (strings.ToUpper(args[1]) == "FALSE") {
						pf.Bh = false
					} else {
						return c.Errf("pfdns: blackhole incorrect value type name or value type not supported: '%s'", args[1])
					}
				case 2:
					pf.BhCname = args[0]
					if pf.BhCname[len(pf.BhCname)-1] != '.' {
						return c.Errf("pfdns: blackhole domains must be dot terminated and fully qualified")
					}
					pf.BhIp = net.ParseIP(args[1])
					if pf.BhIp == nil {
						return middleware.Error("blackhole", c.Err("unparseable IP address argument"))
					}
				}
			default:
				return c.Errf("Unknown keyword '%s'", c.Val())
			}
		}
		if !(hadBlock) {
			return c.Errf("pfdns: missing configuration")
		}
	}

	if enforce {
		if err := pf.DbInit(); err != nil {
			return c.Errf("pfdns: unable to initialize database connection")
		}
		fmt.Println("pfdns: Enforcement mode enabled.")
	}

	dnsserver.GetConfig(c).AddMiddleware(
		func(next middleware.Handler) middleware.Handler {
			pf.RedirectIp = ip
			pf.Enforce = enforce
			pf.Next = next
			return pf
		})

	return nil
}
