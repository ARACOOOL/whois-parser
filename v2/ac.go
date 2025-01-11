package v2

import (
	"errors"
	"strings"
	"time"
)

// ACParser handles parsing for the .ac zone WHOIS provider.
type ACParser struct{}

// Parse implements the Parser interface for .ac zone.
func (p *ACParser) Parse(whoisText string) (WhoisInfo, error) {
	lines := strings.Split(whoisText, "\n")
	whoisInfo := WhoisInfo{
		Domain:    &Domain{},
		Registrar: &Contact{},
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Domain Name:") {
			whoisInfo.Domain.Domain = cleanValue(line, "Domain Name:")
		} else if strings.HasPrefix(line, "Registry Domain ID:") {
			whoisInfo.Domain.ID = cleanValue(line, "Registry Domain ID:")
		} else if strings.HasPrefix(line, "Registrar WHOIS Server:") {
			whoisInfo.Domain.WhoisServer = cleanValue(line, "Registrar WHOIS Server:")
		} else if strings.HasPrefix(line, "Registrar:") {
			whoisInfo.Registrar.Name = cleanValue(line, "Registrar:")
		} else if strings.HasPrefix(line, "Registrar URL:") {
			whoisInfo.Registrar.ReferralURL = cleanValue(line, "Registrar URL:")
		} else if strings.HasPrefix(line, "Updated Date:") {
			dateStr := cleanValue(line, "Updated Date:")
			whoisInfo.Domain.UpdatedDate = dateStr
			whoisInfo.Domain.UpdatedDateInTime = parseDate(time.RFC3339, dateStr)
		} else if strings.HasPrefix(line, "Creation Date:") {
			dateStr := cleanValue(line, "Creation Date:")
			whoisInfo.Domain.CreatedDate = dateStr
			whoisInfo.Domain.CreatedDateInTime = parseDate(time.RFC3339, dateStr)
		} else if strings.HasPrefix(line, "Registry Expiry Date:") {
			dateStr := cleanValue(line, "Registry Expiry Date:")
			whoisInfo.Domain.ExpirationDate = dateStr
			whoisInfo.Domain.ExpirationDateInTime = parseDate(time.RFC3339, dateStr)
		} else if strings.HasPrefix(line, "Name Server:") {
			whoisInfo.Domain.NameServers = append(whoisInfo.Domain.NameServers, cleanValue(line, "Name Server:"))
		} else if strings.HasPrefix(line, "DNSSEC:") {
			whoisInfo.Domain.DNSSec = strings.ToLower(cleanValue(line, "DNSSEC:")) == "signed"
		}
	}

	if whoisInfo.Domain.Domain == "" {
		return WhoisInfo{}, errors.New("missing domain name")
	}

	return whoisInfo, nil
}
