package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAUParser(t *testing.T) {
	parser := &AUParser{}
	rawWhois := `Domain Name: acma.gov.au
Registry Domain ID: 4ea811ec05044d1d8aaa55a5283c666d-AU
Registrar WHOIS Server: whois.auda.org.au
Registrar URL: http://whois.auda.org.au
Last Modified: 2025-01-06T00:01:22Z
Registrar Name: Department of Finance
Registrar Abuse Contact Email: registrar@domainname.gov.au
Registrar Abuse Contact Phone: +61.262152222
Reseller Name:
Status: clientDeleteProhibited https://identitydigital.au/get-au/whois-status-codes#clientDeleteProhibited
Status: clientUpdateProhibited https://identitydigital.au/get-au/whois-status-codes#clientUpdateProhibited
Registrant Contact ID: 90da4e9deed34485a319e185ab8d9447-AU
Registrant Contact Name: Nathan Penhaligon
Tech Contact ID: 555c85173df641beaf9457f05c593623-AU
Tech Contact Name: Nathan Penhaligon
Name Server: ns1-04.azure-dns.com
Name Server: ns2-04.azure-dns.net
Name Server: ns3-04.azure-dns.org
Name Server: ns4-04.azure-dns.info
DNSSEC: unsigned
Registrant: Australian Communications and Media Authority (ACMA)
Registrant ID: OTHER GOVAU-DESI1000
Eligibility Type: Other
>>> Last update of WHOIS database: 2025-01-11T20:18:47Z <<<`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:            "acma.gov.au",
			ID:                "4ea811ec05044d1d8aaa55a5283c666d-AU",
			WhoisServer:       "whois.auda.org.au",
			UpdatedDate:       "2025-01-06T00:01:22Z",
			UpdatedDateInTime: parseDate("2006-01-02T15:04:05Z", "2025-01-06T00:01:22Z"),
			NameServers: []string{
				"ns1-04.azure-dns.com",
				"ns2-04.azure-dns.net",
				"ns3-04.azure-dns.org",
				"ns4-04.azure-dns.info",
			},
			DNSSec: false,
			Status: []string{"Other"},
		},
		Registrar: &Contact{
			Name:        "Department of Finance",
			Email:       "registrar@domainname.gov.au",
			Phone:       "+61.262152222",
			ReferralURL: "http://whois.auda.org.au",
		},
		Registrant: &Contact{
			ID:           "90da4e9deed34485a319e185ab8d9447-AU",
			Name:         "Nathan Penhaligon",
			Organization: "Australian Communications and Media Authority (ACMA)",
			ReferralURL:  "OTHER GOVAU-DESI1000",
		},
		Technical: &Contact{
			ID:   "555c85173df641beaf9457f05c593623-AU",
			Name: "Nathan Penhaligon",
		},
	}

	result, err := parser.Parse(rawWhois)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
