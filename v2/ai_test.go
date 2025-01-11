package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAIParser(t *testing.T) {
	parser := &AIParser{}
	rawWhois := `Domain Name: git.ai
Registry Domain ID: 291858_nic_ai
Registrar WHOIS Server: whois.rrpproxy.net
Registrar: Key-Systems GmbH
Registrar Address: Im Oberen Werk 1
Registrar Country: DE
Registrar Phone: +49.68949396850
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization:
Registrant Country: JP
Admin Name: REDACTED FOR PRIVACY
Admin Organization:
Admin Country: JP
Tech Name: REDACTED FOR PRIVACY
Tech Organization:
Tech Country: JP
Name Server: ns1.onlydomains.com
Name Server: ns2.onlydomains.com
DNSSEC: unsigned`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:      "git.ai",
			ID:          "291858_nic_ai",
			WhoisServer: "whois.rrpproxy.net",
			NameServers: []string{"ns1.onlydomains.com", "ns2.onlydomains.com"},
			DNSSec:      false,
		},
		Registrar: &Contact{
			Name:    "Key-Systems GmbH",
			Street:  "Im Oberen Werk 1",
			Country: "DE",
			Phone:   "+49.68949396850",
		},
		Registrant: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "",
			Country:      "JP",
		},
		Administrative: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "",
			Country:      "JP",
		},
		Technical: &Contact{
			Name:         "REDACTED FOR PRIVACY",
			Organization: "",
			Country:      "JP",
		},
	}

	result, err := parser.Parse(rawWhois)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
