package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
Registrar IANA ID: 1861
Registrar Abuse Contact Email: abuse@porkbun.com
Registrar Abuse Contact Phone: +1.5038508351
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization:
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province: Guangdong
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: CN
Registrant Phone: REDACTED FOR PRIVACY
Registrant Phone Ext: REDACTED FOR PRIVACY
Registrant Fax: REDACTED FOR PRIVACY
Registrant Fax Ext: REDACTED FOR PRIVACY
Registrant Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Admin ID: REDACTED FOR PRIVACY
Admin Name: REDACTED FOR PRIVACY
Admin Organization: REDACTED FOR PRIVACY
Admin Street: REDACTED FOR PRIVACY
Admin City: REDACTED FOR PRIVACY
Admin State/Province: REDACTED FOR PRIVACY
Admin Postal Code: REDACTED FOR PRIVACY
Admin Country: REDACTED FOR PRIVACY
Admin Phone: REDACTED FOR PRIVACY
Admin Phone Ext: REDACTED FOR PRIVACY
Admin Fax: REDACTED FOR PRIVACY
Admin Fax Ext: REDACTED FOR PRIVACY
Admin Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Tech ID: REDACTED FOR PRIVACY
Tech Name: REDACTED FOR PRIVACY
Tech Organization: REDACTED FOR PRIVACY
Tech Street: REDACTED FOR PRIVACY
Tech City: REDACTED FOR PRIVACY
Tech State/Province: REDACTED FOR PRIVACY
Tech Postal Code: REDACTED FOR PRIVACY
Tech Country: REDACTED FOR PRIVACY
Tech Phone: REDACTED FOR PRIVACY
Tech Phone Ext: REDACTED FOR PRIVACY
Tech Fax: REDACTED FOR PRIVACY
Tech Fax Ext: REDACTED FOR PRIVACY
Tech Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Name Server: vip1.alidns.com
Name Server: vip2.alidns.com
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2025-01-11T18:58:47Z <<<`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:               "git.ac",
			ID:                   "3f6e2c24c42c48be81d79ba4019c4c83-DONUTS",
			WhoisServer:          "whois.porkbun.com",
			UpdatedDate:          "2025-01-09T17:46:12Z",
			UpdatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2025-01-09T17:46:12Z"),
			CreatedDate:          "2021-05-07T15:04:21Z",
			CreatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2021-05-07T15:04:21Z"),
			ExpirationDate:       "2025-05-07T15:04:21Z",
			ExpirationDateInTime: parseDate("2006-01-02T15:04:05Z", "2025-05-07T15:04:21Z"),
			NameServers:          []string{"vip1.alidns.com", "vip2.alidns.com"},
			DNSSec:               false,
		},
		Registrar: &Contact{
			Name:        "Porkbun LLC",
			ID:          "1861",
			Email:       "abuse@porkbun.com",
			Phone:       "+1.5038508351",
			ReferralURL: "http://porkbun.com",
		},
		Registrant: &Contact{
			Name:    "REDACTED FOR PRIVACY",
			Country: "CN",
		},
		Administrative: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "REDACTED FOR PRIVACY",
			Country:      "REDACTED FOR PRIVACY",
		},
		Technical: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "REDACTED FOR PRIVACY",
			Country:      "REDACTED FOR PRIVACY",
		},
	}

	result, err := parser.Parse(rawWhois)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
