package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAcademyParser(t *testing.T) {
	parser := &AcademyParser{}
	rawWhois := `Domain Name: youcontrol.academy
Registry Domain ID: 654d3759f89f4c24bbb37bef977a6f3c-DONUTS
Registrar WHOIS Server: whois.imena.ua
Registrar URL: https://imena.ua
Updated Date: 2024-07-11T14:32:13Z
Creation Date: 2022-07-19T10:42:08Z
Registry Expiry Date: 2025-07-19T10:42:08Z
Registrar: Internet Invest, Ltd. dba Imena.ua
Registrar IANA ID: 1112
Registrar Abuse Contact Email: abuse@imena.ua
Registrar Abuse Contact Phone: +38.0442010102
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Whois privacy protection service
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province:
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: UA
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
Name Server: may.ns.cloudflare.com
Name Server: brad.ns.cloudflare.com
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2025-01-11T23:31:39Z <<<`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:               "youcontrol.academy",
			ID:                   "654d3759f89f4c24bbb37bef977a6f3c-DONUTS",
			WhoisServer:          "whois.imena.ua",
			UpdatedDate:          "2024-07-11T14:32:13Z",
			UpdatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2024-07-11T14:32:13Z"),
			CreatedDate:          "2022-07-19T10:42:08Z",
			CreatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2022-07-19T10:42:08Z"),
			ExpirationDate:       "2025-07-19T10:42:08Z",
			ExpirationDateInTime: parseDate("2006-01-02T15:04:05Z", "2025-07-19T10:42:08Z"),
			NameServers: []string{
				"may.ns.cloudflare.com",
				"brad.ns.cloudflare.com",
			},
			DNSSec: false,
		},
		Registrar: &Contact{
			Name:        "Internet Invest, Ltd. dba Imena.ua",
			ID:          "1112",
			Email:       "abuse@imena.ua",
			Phone:       "+38.0442010102",
			ReferralURL: "https://imena.ua",
		},
		Registrant: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "Whois privacy protection service",
			Country:      "UA",
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
