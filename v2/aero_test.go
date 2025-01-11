package v2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAeroParser(t *testing.T) {
	parser := &AeroParser{}
	rawWhois := `Domain Name: GOOGLE.AERO
Registry Domain ID: D4480451-AERO
Updated Date: 2019-10-04T05:05:04Z
Creation Date: 2019-08-04T11:35:07Z
Registry Expiry Date: 2020-08-04T11:35:07Z
Registrar: EPAG Domainservices GmbH
Registrar IANA ID: 85
Domain Status: ok https://icann.org/epp#ok
Name Server: NS2.HOSTING.REG.RU
Name Server: NS1.HOSTING.REG.RU
DNSSEC: unsigned`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:               "GOOGLE.AERO",
			ID:                   "D4480451-AERO",
			UpdatedDate:          "2019-10-04T05:05:04Z",
			UpdatedDateInTime:    parseTestDate("2006-01-02T15:04:05Z", "2019-10-04T05:05:04Z"),
			CreatedDate:          "2019-08-04T11:35:07Z",
			CreatedDateInTime:    parseTestDate("2006-01-02T15:04:05Z", "2019-08-04T11:35:07Z"),
			ExpirationDate:       "2020-08-04T11:35:07Z",
			ExpirationDateInTime: parseTestDate("2006-01-02T15:04:05Z", "2020-08-04T11:35:07Z"),
			NameServers: []string{
				"NS2.HOSTING.REG.RU",
				"NS1.HOSTING.REG.RU",
			},
			DNSSec: false,
		},
		Registrar: &Contact{
			Name: "EPAG Domainservices GmbH",
			ID:   "85",
		},
	}

	result, err := parser.Parse(rawWhois, "GOOGLE.AERO")
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func parseTestDate(format, dateStr string) *time.Time {
	t, _ := time.Parse(format, dateStr)
	return &t
}
