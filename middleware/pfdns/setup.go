package pfdns

import (
	"net"

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
	var ip net.IP
	for c.Next() {
		if !c.NextArg() {
			return middleware.Error("pfdns", c.ArgErr())
		}
		ip = net.ParseIP(c.Val())
	}

	dnsserver.GetConfig(c).AddMiddleware(func(next middleware.Handler) middleware.Handler {
		return pfdns{RedirectIp: ip, Next: next}
	})

	return nil
}
