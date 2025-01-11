package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAeroParser(t *testing.T) {
	parser := &AeroParser{}
	rawWhois := `Domain Name: google.aero
Registry Domain ID: f4187e338903472486e954ec98b33136-DONUTS
Registrar WHOIS Server: whois.gandi.net
Registrar URL: https://www.gandi.net
Updated Date: 2024-02-09T10:14:55Z
Creation Date: 2023-02-10T10:07:32Z
Registry Expiry Date: 2025-02-10T10:07:32Z
Registrar: Gandi SAS
Registrar IANA ID: 81
Registrar Abuse Contact Email: abuse@support.gandi.net
Registrar Abuse Contact Phone: +33.170377661
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: Titanfly Service
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province: 93
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: FR
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
Name Server: ns-158-a.gandi.net
Name Server: ns-96-c.gandi.net
Name Server: ns-233-b.gandi.net
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2025-01-11T19:04:51Z <<<`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:               "google.aero",
			ID:                   "f4187e338903472486e954ec98b33136-DONUTS",
			WhoisServer:          "whois.gandi.net",
			UpdatedDate:          "2024-02-09T10:14:55Z",
			UpdatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2024-02-09T10:14:55Z"),
			CreatedDate:          "2023-02-10T10:07:32Z",
			CreatedDateInTime:    parseDate("2006-01-02T15:04:05Z", "2023-02-10T10:07:32Z"),
			ExpirationDate:       "2025-02-10T10:07:32Z",
			ExpirationDateInTime: parseDate("2006-01-02T15:04:05Z", "2025-02-10T10:07:32Z"),
			NameServers: []string{
				"ns-158-a.gandi.net",
				"ns-96-c.gandi.net",
				"ns-233-b.gandi.net",
			},
			DNSSec: false,
		},
		Registrar: &Contact{
			Name:        "Gandi SAS",
			ID:          "81",
			Email:       "abuse@support.gandi.net",
			Phone:       "+33.170377661",
			ReferralURL: "https://www.gandi.net",
		},
		Registrant: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "Titanfly Service",
			Country:      "FR",
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
