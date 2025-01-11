package v2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestACParser(t *testing.T) {
	parser := &ACParser{}
	rawWhois := `Domain Name: git.ac
Registry Domain ID: 3f6e2c24c42c48be81d79ba4019c4c83-DONUTS
Registrar WHOIS Server: whois.porkbun.com
Registrar URL: http://porkbun.com
Updated Date: 2025-01-09T17:46:12Z
Creation Date: 2021-05-07T15:04:21Z
Registry Expiry Date: 2025-05-07T15:04:21Z
Registrar: Porkbun LLC
Name Server: vip1.alidns.com
Name Server: vip2.alidns.com
DNSSEC: unsigned`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:               "git.ac",
			ID:                   "3f6e2c24c42c48be81d79ba4019c4c83-DONUTS",
			WhoisServer:          "whois.porkbun.com",
			CreatedDate:          "2021-05-07T15:04:21Z",
			CreatedDateInTime:    parseDate(time.RFC3339, "2021-05-07T15:04:21Z"),
			UpdatedDate:          "2025-01-09T17:46:12Z",
			UpdatedDateInTime:    parseDate(time.RFC3339, "2025-01-09T17:46:12Z"),
			ExpirationDate:       "2025-05-07T15:04:21Z",
			ExpirationDateInTime: parseDate(time.RFC3339, "2025-05-07T15:04:21Z"),
			NameServers: []string{
				"vip1.alidns.com",
				"vip2.alidns.com",
			},
			DNSSec: false,
		},
		Registrar: &Contact{
			Name:        "Porkbun LLC",
			ReferralURL: "http://porkbun.com",
		},
	}

	result, err := parser.Parse(rawWhois, "git.ac")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
