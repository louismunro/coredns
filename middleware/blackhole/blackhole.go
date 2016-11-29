package blackhole

import (
	"net"

	"github.com/miekg/coredns/middleware"
	"github.com/miekg/coredns/request"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

type blackhole struct {
	BlackholeIp net.IP
	Cname       string
	Next        middleware.Handler
}

// ServeDNS implements the middleware.Handler interface.
func (bh blackhole) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	a := new(dns.Msg)
	a.SetReply(r)
	a.Compress = true
	a.Authoritative = true

	ip := bh.BlackholeIp
	var ar, rr dns.RR

	rr = new(dns.CNAME)
	rr.(*dns.CNAME).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeCNAME, Class: state.QClass()}
	rr.(*dns.CNAME).Target = bh.Cname

	switch state.Family() {
	case 1:
		ar = new(dns.A)
		ar.(*dns.A).Hdr = dns.RR_Header{Name: bh.Cname, Rrtype: dns.TypeA, Class: state.QClass()}
		ar.(*dns.A).A = ip.To4()
	case 2:
		ar = new(dns.AAAA)
		ar.(*dns.AAAA).Hdr = dns.RR_Header{Name: bh.Cname, Rrtype: dns.TypeAAAA, Class: state.QClass()}
		ar.(*dns.AAAA).AAAA = ip.To16()
	}

	a.Answer = []dns.RR{rr}
	a.Extra = []dns.RR{ar}

	state.SizeAndDo(a)
	w.WriteMsg(a)

	return 0, nil
}

// Name implements the Handler interface.
func (bh blackhole) Name() string { return "blackhole" }
