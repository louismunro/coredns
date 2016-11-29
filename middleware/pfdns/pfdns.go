// Package pfdns implements a middleware that returns details about the resolving
// querying it.
package pfdns

import (
	"net"

	"github.com/miekg/coredns/middleware"
	"github.com/miekg/coredns/request"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

type pfdns struct {
	RedirectIp net.IP
	Next       middleware.Handler
}

// ServeDNS implements the middleware.Handler interface.
func (pf pfdns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	// we only handle A and AAAA requests
	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA {
		return pf.Next.ServeDNS(ctx, w, r)
	}

	a := new(dns.Msg)
	a.SetReply(r)
	a.Compress = true
	a.Authoritative = true

	ip := pf.RedirectIp
	var rr dns.RR

	switch state.Family() {
	case 1:
		rr = new(dns.A)
		rr.(*dns.A).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass()}
		rr.(*dns.A).A = ip.To4()
	case 2:
		rr = new(dns.AAAA)
		rr.(*dns.AAAA).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: state.QClass()}
		rr.(*dns.AAAA).AAAA = ip.To16()
	}

	a.Answer = []dns.RR{rr}

	state.SizeAndDo(a)
	w.WriteMsg(a)

	return 0, nil
}

// Name implements the Handler interface.
func (pf pfdns) Name() string { return "pfdns" }
