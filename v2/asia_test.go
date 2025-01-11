package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAsiaParser(t *testing.T) {
	parser := &AsiaParser{}
	rawWhois := `Domain Name: git.asia
Registry Domain ID: 04651b9f2701426cb14ff620badd408a-DONUTS
Registrar WHOIS Server: whois.namesilo.com
Registrar URL: http://www.namesilo.com
Updated Date: 2024-11-11T13:26:44Z
Creation Date: 2018-09-27T13:26:20Z
Registry Expiry Date: 2025-09-27T13:26:20Z
Registrar: NameSilo, LLC
Registrar IANA ID: 1479
Registrar Abuse Contact Email: abuse@namesilo.com
Registrar Abuse Contact Phone: +1.6024928198
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: See PrivacyGuardian.org
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province: AZ
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: US
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
Name Server: ns1.dnsowl.com
Name Server: ns2.dnsowl.com
Name Server: ns3.dnsowl.com
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2025-01-11T20:13:49Z <<<`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:               "git.asia",
			ID:                   "04651b9f2701426cb14ff620badd408a-DONUTS",
			WhoisServer:          "whois.namesilo.com",
			UpdatedDate:          "2024-11-11T13:26:44Z",
			UpdatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2024-11-11T13:26:44Z"),
			CreatedDate:          "2018-09-27T13:26:20Z",
			CreatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2018-09-27T13:26:20Z"),
			ExpirationDate:       "2025-09-27T13:26:20Z",
			ExpirationDateInTime: parseDate("2006-01-02T15:04:05Z", "2025-09-27T13:26:20Z"),
			NameServers: []string{
				"ns1.dnsowl.com",
				"ns2.dnsowl.com",
				"ns3.dnsowl.com",
			},
			DNSSec: false,
		},
		Registrar: &Contact{
			Name:        "NameSilo, LLC",
			ID:          "1479",
			Email:       "abuse@namesilo.com",
			Phone:       "+1.6024928198",
			ReferralURL: "http://www.namesilo.com",
		},
		Registrant: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "See PrivacyGuardian.org",
			Country:      "US",
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
