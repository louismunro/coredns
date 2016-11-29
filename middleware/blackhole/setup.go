package blackhole

import (
	"net"

	"github.com/miekg/coredns/core/dnsserver"
	"github.com/miekg/coredns/middleware"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("blackhole", caddy.Plugin{
		ServerType: "dns",
		Action:     setupBlackhole,
	})
}

func setupBlackhole(c *caddy.Controller) error {
	bh := blackhole{
		BlackholeIp: net.ParseIP("127.0.0.1"),
		Cname:       "localhost.localdomain.",
		Next:        nil,
	}

	args := c.RemainingArgs()
	switch len(args) {
	case 1: //use the defaults
	case 2:
		return middleware.Error("blackhole", c.ArgErr())
	case 3:
		bh.Cname = args[1]
		if bh.Cname[len(bh.Cname)-1] != '.' {
			return middleware.Error("blackhole", c.Err("domains must be dot terminated and fully qualified"))
		}
		bh.BlackholeIp = net.ParseIP(args[2])
		if bh.BlackholeIp == nil {
			return middleware.Error("blackhole", c.Err("unparseable IP address argument"))
		}
	}

	dnsserver.GetConfig(c).AddMiddleware(func(next middleware.Handler) middleware.Handler {
		bh.Next = next
		return bh
	})
	return nil
}
