package v2

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMDParser(t *testing.T) {
	parser := &MDParser{}
	rawWhois := `Domain  name    automall.md
Domain state    OK

Registered on   2010-06-21
Expires    on   2026-06-21

Nameserver      dns1.namecheaphosting.com
Nameserver      dns1.namecheaphosting.com`

	expected := WhoisInfo{
		Domain: &Domain{
			Domain:               "automall.md",
			Status:               []string{"OK"},
			CreatedDate:          "2010-06-21",
			CreatedDateInTime:    parseDate("2006-01-02", "2010-06-21"),
			ExpirationDate:       "2026-06-21",
			ExpirationDateInTime: parseDate("2006-01-02", "2026-06-21"),
			NameServers: []string{
				"dns1.namecheaphosting.com",
				"dns1.namecheaphosting.com",
			},
		},
	}

	result, err := parser.Parse(rawWhois)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
