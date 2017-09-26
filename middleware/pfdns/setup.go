package pfdns

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"

	_ "github.com/go-sql-driver/mysql"

	"github.com/inverse-inc/packetfence/go/pfconfigdriver"
	"github.com/miekg/coredns/core/dnsserver"
	"github.com/miekg/coredns/middleware"

	"github.com/mholt/caddy"
)

type dbConf struct {
	DBHost     string `json:"host"`
	DBPort     string `json:"port"`
	DBUser     string `json:"user"`
	DBPassword string `json:"pass"`
	DB         string `json:"db"`
}

func init() {
	caddy.RegisterPlugin("pfdns", caddy.Plugin{
		ServerType: "dns",
		Action:     setuppfdns,
	})
}

func setuppfdns(c *caddy.Controller) error {
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
			default:
				return c.Errf("Unknown keyword '%s'", c.Val())
			}
		}
		if !(hadBlock) {
			return c.Errf("pfdns: missing configuration")
		}
	}

	var ip4log, ip6log, nodedb *sql.Stmt
	var db *sql.DB
	var ctx = context.Background()
	if enforce {
		configDatabase := readConfig(ctx)
		db, err := connectDB(configDatabase)
		if err != nil {
			return c.Errf("pfdns: database connection error: %s", err)
		}
		ip4log, err = db.Prepare("Select MAC from ip4log where IP = ? ")
		if err != nil {
			return c.Errf("pfdns: database prepared statement error: %s", err)
		}
		ip6log, err = db.Prepare("Select MAC from ip6log where IP = ? ")
		if err != nil {
			return c.Errf("pfdns: database prepared statement error: %s", err)
		}
		nodedb, err = db.Prepare("Select STATUS from node where MAC = ? ")
		if err != nil {
			return c.Errf("pfdns: database prepared statement error: %s", err)
		}
	}

	dnsserver.GetConfig(c).AddMiddleware(func(next middleware.Handler) middleware.Handler {
		return pfdns{
			RedirectIp: ip,
			Enforce:    enforce,
			Db:         db,
			Ip4log:     ip4log,
			Ip6log:     ip6log,
			Nodedb:     nodedb,
			Next:       next,
		}
	})

	return nil
}

func readConfig(ctx context.Context) pfconfigdriver.PfconfigDatabase {
	var sections pfconfigdriver.PfconfigDatabase
	sections.PfconfigNS = "config::Pf"
	sections.PfconfigMethod = "hash_element"
	sections.PfconfigHashNS = "database"

	pfconfigdriver.FetchDecodeSocket(ctx, &sections)
	return sections
}

func connectDB(configDatabase pfconfigdriver.PfconfigDatabase) (*sql.DB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", configDatabase.DBUser, configDatabase.DBPassword, configDatabase.DBHost, configDatabase.DBName))
	if err != nil {
		return nil, err
	}
	return db, nil
}
