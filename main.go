package caddy_maxmind_asn

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ caddy.Module             = (*MaxmindASN)(nil)
	_ caddyhttp.RequestMatcher = (*MaxmindASN)(nil)
	_ caddy.Provisioner        = (*MaxmindASN)(nil)
	_ caddy.CleanerUpper       = (*MaxmindASN)(nil)
	_ caddyfile.Unmarshaler    = (*MaxmindASN)(nil)
)

type Record struct {
	ASN int    `maxminddb:"autonomous_system_number"`
	ASO string `maxminddb:"autonomous_system_organization"`
}

func init() {
	caddy.RegisterModule(MaxmindASN{})
}

// Allows to filter requests based on source IP ASN or ASO.
type MaxmindASN struct {
	// The path of the MaxMind GeoLite2-ASN.mmd file
	DbPath string `json:"db_path"`

	// A list of
	AllowASOs []string `json:"allow_asos,omitempty"`
	DenyASOs  []string `json:"deny_asos,omitempty"`

	// AS numbers (exact match). Accepts comma-separated values
	// and an optional "AS" prefix, e.g. 1103,1136 or AS1136.
	AllowASNs []int `json:"allow_asns,omitempty"`
	DenyASNs  []int `json:"deny_asns,omitempty"`

	// MaxMind database reader
	dbInst *maxminddb.Reader
	logger *zap.Logger
}

func (m *MaxmindASN) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	current := 0
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "db_path":
				current = 1
			case "allow_asos":
				current = 2
			case "deny_asos":
				current = 3
			case "allow_asns":
				current = 4
			case "deny_asns":
				current = 5
			default:
				switch current {
				case 1:
					m.DbPath = d.Val()
					current = 0
				case 2:
					m.AllowASOs = append(m.AllowASOs, strings.ToLower(d.Val()))
				case 3:
					m.DenyASOs = append(m.DenyASOs, strings.ToLower(d.Val()))
				case 4:
					asns, err := parseASNs(d.Val())
					if err != nil {
						return err
					}
					m.AllowASNs = append(m.AllowASNs, asns...)
				case 5:
					asns, err := parseASNs(d.Val())
					if err != nil {
						return err
					}
					m.DenyASNs = append(m.DenyASNs, asns...)
				default:
					return fmt.Errorf("unexpected config parameter %s", d.Val())
				}
			}
		}
	}
	return nil
}

// parseASNs turns one Caddyfile token into a list of AS numbers.
// "1103,1136,1145" -> [1103, 1136, 1145]
// "AS1136"         -> [1136]
// Space-separated tokens ("allow_asns 1103 1136") are appended by
// the parser loop itself, one call per token.
func parseASNs(token string) ([]int, error) {
	var asns []int
	for _, raw := range strings.Split(token, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		raw = strings.TrimPrefix(strings.ToUpper(raw), "AS")
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 || n > 4294967295 {
			return nil, fmt.Errorf("invalid ASN %q", raw)
		}
		asns = append(asns, int(n))
	}
	return asns, nil
}

func (MaxmindASN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.maxmind_asn",
		New: func() caddy.Module { return new(MaxmindASN) },
	}
}

func (m *MaxmindASN) Provision(ctx caddy.Context) error {
	var err error
	m.logger = ctx.Logger(m)
	m.dbInst, err = maxminddb.Open(m.DbPath)
	if err != nil {
		return fmt.Errorf("cannot open database file %s: %v", m.DbPath, err)
	}
	m.logger.Info("provisioned",
		zap.String("maxmind_db", m.DbPath),
		zap.Int("allowed_asos", len(m.AllowASOs)),
		zap.Int("denied_asos", len(m.DenyASOs)),
		zap.Int("allowed_asns", len(m.AllowASNs)),
		zap.Int("denied_asns", len(m.DenyASNs)),
	)
	return nil
}

func (m *MaxmindASN) Cleanup() error {
	if m.dbInst != nil {
		return m.dbInst.Close()
	}
	return nil
}

func containsInt(list []int, v int) bool {
	for _, i := range list {
		if i == v {
			return true
		}
	}
	return false
}

func (m *MaxmindASN) checkAllowed(asn int, asoresult string) bool {
	// Deny lists take precedence over allow lists.
	if len(m.DenyASNs) > 0 && containsInt(m.DenyASNs, asn) {
		return false
	}
	if len(m.DenyASOs) > 0 {
		for _, i := range m.DenyASOs {
			if strings.Contains(asoresult, i) {
				return false
			}
		}
		return true
	}

	// Allow lists: pass if matched by either the ASN or the ASO list.
	// Note: an allow_asns list matches on the exact number, so an IP
	// without an ASN record in the database (private ranges, unknown
	// space) does NOT pass, unlike allow_asos.
	if len(m.AllowASNs) > 0 || len(m.AllowASOs) > 0 {
		if len(m.AllowASNs) > 0 && containsInt(m.AllowASNs, asn) {
			return true
		}
		if len(m.AllowASOs) > 0 {
			if asoresult == "" {
				return true
			}
			for _, i := range m.AllowASOs {
				if strings.Contains(asoresult, i) {
					return true
				}
			}
		}
		return false
	}
	return true
}

func (m *MaxmindASN) Match(r *http.Request) bool {
	// If no allow or deny fields are set, let the request pass
	if len(m.AllowASOs) < 1 && len(m.DenyASOs) < 1 &&
		len(m.AllowASNs) < 1 && len(m.DenyASNs) < 1 {
		return false
	}

	// Get the remote address from the web request
	remoteIp, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.logger.Warn("cannot split IP address", zap.String("address", r.RemoteAddr), zap.Error(err))
	}

	// Convert the IP string to net.IP
	addr := net.ParseIP(remoteIp)
	if addr == nil {
		m.logger.Warn("cannot parse IP address", zap.String("address", r.RemoteAddr))
		return false
	}

	// Get the record from the database
	var record Record
	err = m.dbInst.Lookup(addr, &record)
	if err != nil {
		m.logger.Warn("cannot lookup IP address", zap.String("address", r.RemoteAddr), zap.Error(err))
		return false
	}

	m.logger.Debug(
		"detected MaxMind data",
		zap.String("ip", r.RemoteAddr),
		zap.Int("autonomous_system_number", record.ASN),
		zap.String("autonomous_system_organization", record.ASO),
	)

	// Check the IP against the allowed/denied ASNs and ASOs
	if !m.checkAllowed(record.ASN, strings.ToLower(record.ASO)) {
		m.logger.Debug("asn/aso not allowed",
			zap.Int("autonomous_system_number", record.ASN),
			zap.String("autonomous_system_organization", record.ASO))
		return false
	}

	return true
}
