// Package pfdns implements a middleware that returns details about the resolving
// querying it.
package pfdns

import (
	"database/sql"
	"fmt"
	"net"
	"os"

	"github.com/inverse-inc/packetfence/go/pfconfigdriver"
	"github.com/miekg/coredns/middleware"
	"github.com/miekg/coredns/request"

	_ "github.com/go-sql-driver/mysql"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

type pfdns struct {
	RedirectIp net.IP
	Enforce    bool // whether DNS enforcement is enabled
	Db         *sql.DB
	Ip4log     *sql.Stmt // prepared statement for ip4log queries
	Ip6log     *sql.Stmt // prepared statement for ip6log queries
	Nodedb     *sql.Stmt // prepared statement for node table queries
	Bh         bool      //  whether blackholing is enabled or not
	BhIp       net.IP
	BhCname    string
	Next       middleware.Handler
}

type dbConf struct {
	DBHost     string `json:"host"`
	DBPort     string `json:"port"`
	DBUser     string `json:"user"`
	DBPassword string `json:"pass"`
	DB         string `json:"db"`
}

func (pf *pfdns) DbInit() error {
	var ctx = context.Background()

	var err error
	configDatabase := readConfig(ctx)
	pf.Db, err = connectDB(configDatabase)
	if err != nil {
		// logging the error is handled in connectDB
		return err
	}

	pf.Ip4log, err = pf.Db.Prepare("Select MAC from ip4log where IP = ? ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pfdns: database ip4log prepared statement error: %s", err)
		return err
	}

	pf.Ip6log, err = pf.Db.Prepare("Select MAC from ip6log where IP = ? ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pfdns: database ip6log prepared statement error: %s", err)
		return err
	}

	pf.Nodedb, err = pf.Db.Prepare("Select STATUS from node where MAC = ? ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pfdns: database nodedb prepared statement error: %s", err)
		return err
	}

	if err != nil {
		fmt.Printf("Error while connecting to database: %s", err)
		return err
	}

	return nil
}

// ServeDNS implements the middleware.Handler interface.
func (pf pfdns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	a := new(dns.Msg)
	a.SetReply(r)
	a.Compress = true
	a.Authoritative = true
	var rr dns.RR

	if pf.Enforce {

		var ipVersion int
		srcIp := state.IP()
		bIp := net.ParseIP(srcIp)
		if bIp.To4() == nil {
			ipVersion = 6
		} else {
			ipVersion = 4
		}

		var mac string
		if ipVersion == 4 {
			err := pf.Ip4log.QueryRow(srcIp).Scan(&mac)
			if err != nil {
				fmt.Printf("ERROR pfdns database query returned %s\n", err)
				return 0, nil
			}
		} else {
			err := pf.Ip6log.QueryRow(srcIp).Scan(&mac)
			if err != nil {
				fmt.Printf("ERROR pfdns database query returned %s\n", err)
				return 0, nil
			}
		}

		var status string
		err := pf.Nodedb.QueryRow(mac).Scan(&status)
		if err != nil {
			fmt.Printf("ERROR pfdns database query returned %s\n", err)
			return 0, nil
		}

		// Defer to the proxy middleware if the device is registered
		if status == "reg" {
			return pf.Next.ServeDNS(ctx, w, r)
		}
	}

	// Not allowed through enforcement, or not enforcing.
	// We only handle A and AAAA requests, all others are subject to blackholing.
	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA {
		// blackhole
		if pf.Bh {
			rr = new(dns.CNAME)
			rr.(*dns.CNAME).Hdr = dns.RR_Header{
				Name:   state.QName(),
				Rrtype: dns.TypeCNAME,
				Class:  state.QClass(),
			}
			rr.(*dns.CNAME).Target = pf.BhCname

			var ar dns.RR
			switch state.Family() {
			case 1: // ipv4
				ar = new(dns.A)
				ar.(*dns.A).Hdr = dns.RR_Header{
					Name:   pf.BhCname,
					Rrtype: dns.TypeA,
					Class:  state.QClass(),
				}
				ar.(*dns.A).A = pf.BhIp.To4()
			case 2: // ipv6
				ar = new(dns.AAAA)
				ar.(*dns.AAAA).Hdr = dns.RR_Header{
					Name:   pf.BhCname,
					Rrtype: dns.TypeAAAA,
					Class:  state.QClass(),
				}
				ar.(*dns.AAAA).AAAA = pf.BhIp.To16()
			}

			a.Answer = []dns.RR{rr}
			a.Extra = []dns.RR{ar}

			state.SizeAndDo(a)
			w.WriteMsg(a)

			return 0, nil
		} else {
			return pf.Next.ServeDNS(ctx, w, r)
		}
	}

	// Not blackholed, not allowed through due to DNS enforcement.
	// Let's redirect to RedirectIp
	switch state.Family() {
	case 1:
		rr = new(dns.A)
		rr.(*dns.A).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass()}
		rr.(*dns.A).A = pf.RedirectIp.To4()
	case 2:
		rr = new(dns.AAAA)
		rr.(*dns.AAAA).Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: state.QClass()}
		rr.(*dns.AAAA).AAAA = pf.RedirectIp.To16()
	}

	a.Answer = []dns.RR{rr}

	state.SizeAndDo(a)
	w.WriteMsg(a)

	return 0, nil
}

// Name implements the Handler interface.
func (pf pfdns) Name() string { return "pfdns" }

func readConfig(ctx context.Context) pfconfigdriver.PfconfigDatabase {
	var sections pfconfigdriver.PfconfigDatabase
	sections.PfconfigNS = "config::Pf"
	sections.PfconfigMethod = "hash_element"
	sections.PfconfigHashNS = "database"

	pfconfigdriver.FetchDecodeSocket(ctx, &sections)
	return sections
}

func connectDB(configDatabase pfconfigdriver.PfconfigDatabase) (*sql.DB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		configDatabase.DBUser,
		configDatabase.DBPassword,
		configDatabase.DBHost,
		configDatabase.DBPort,
		configDatabase.DBName,
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pfdns: database connection error: %s", err)
		return nil, err
	}
	return db, nil
}
