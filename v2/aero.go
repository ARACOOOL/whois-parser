package v2

import (
	"errors"
	"strings"
)

// AeroParser handles parsing for the .aero zone WHOIS provider.
type AeroParser struct{}

// Parse implements the Parser interface for .aero zone.
func (p *AeroParser) Parse(whoisText string) (WhoisInfo, error) {
	lines := strings.Split(whoisText, "\n")
	whoisInfo := WhoisInfo{
		Domain:         &Domain{},
		Registrar:      &Contact{},
		Registrant:     &Contact{},
		Administrative: &Contact{},
		Technical:      &Contact{},
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Domain Name:"):
			whoisInfo.Domain.Domain = cleanValue(line, "Domain Name:")
		case strings.HasPrefix(line, "Registry Domain ID:"):
			whoisInfo.Domain.ID = cleanValue(line, "Registry Domain ID:")
		case strings.HasPrefix(line, "Registrar WHOIS Server:"):
			whoisInfo.Domain.WhoisServer = cleanValue(line, "Registrar WHOIS Server:")
		case strings.HasPrefix(line, "Registrar URL:"):
			whoisInfo.Registrar.ReferralURL = cleanValue(line, "Registrar URL:")
		case strings.HasPrefix(line, "Registrar:"):
			whoisInfo.Registrar.Name = cleanValue(line, "Registrar:")
		case strings.HasPrefix(line, "Registrar IANA ID:"):
			whoisInfo.Registrar.ID = cleanValue(line, "Registrar IANA ID:")
		case strings.HasPrefix(line, "Registrar Abuse Contact Email:"):
			whoisInfo.Registrar.Email = cleanValue(line, "Registrar Abuse Contact Email:")
		case strings.HasPrefix(line, "Registrar Abuse Contact Phone:"):
			whoisInfo.Registrar.Phone = cleanValue(line, "Registrar Abuse Contact Phone:")
		case strings.HasPrefix(line, "Registrant Name:"):
			whoisInfo.Registrant.Name = cleanValue(line, "Registrant Name:")
		case strings.HasPrefix(line, "Registrant Organization:"):
			whoisInfo.Registrant.Organization = cleanValue(line, "Registrant Organization:")
		case strings.HasPrefix(line, "Registrant Country:"):
			whoisInfo.Registrant.Country = cleanValue(line, "Registrant Country:")
		case strings.HasPrefix(line, "Admin Name:"):
			whoisInfo.Administrative.Name = cleanValue(line, "Admin Name:")
		case strings.HasPrefix(line, "Admin Organization:"):
			whoisInfo.Administrative.Organization = cleanValue(line, "Admin Organization:")
		case strings.HasPrefix(line, "Admin Country:"):
			whoisInfo.Administrative.Country = cleanValue(line, "Admin Country:")
		case strings.HasPrefix(line, "Tech Name:"):
			whoisInfo.Technical.Name = cleanValue(line, "Tech Name:")
		case strings.HasPrefix(line, "Tech Organization:"):
			whoisInfo.Technical.Organization = cleanValue(line, "Tech Organization:")
		case strings.HasPrefix(line, "Tech Country:"):
			whoisInfo.Technical.Country = cleanValue(line, "Tech Country:")
		case strings.HasPrefix(line, "Name Server:"):
			whoisInfo.Domain.NameServers = append(whoisInfo.Domain.NameServers, cleanValue(line, "Name Server:"))
		case strings.HasPrefix(line, "DNSSEC:"):
			whoisInfo.Domain.DNSSec = strings.ToLower(cleanValue(line, "DNSSEC:")) == "signed"
		case strings.HasPrefix(line, "Updated Date:"):
			whoisInfo.Domain.UpdatedDate = cleanValue(line, "Updated Date:")
			whoisInfo.Domain.UpdatedDateInTime = parseDate("2006-01-02T15:04:05Z", whoisInfo.Domain.UpdatedDate)
		case strings.HasPrefix(line, "Creation Date:"):
			whoisInfo.Domain.CreatedDate = cleanValue(line, "Creation Date:")
			whoisInfo.Domain.CreatedDateInTime = parseDate("2006-01-02T15:04:05Z", whoisInfo.Domain.CreatedDate)
		case strings.HasPrefix(line, "Registry Expiry Date:"):
			whoisInfo.Domain.ExpirationDate = cleanValue(line, "Registry Expiry Date:")
			whoisInfo.Domain.ExpirationDateInTime = parseDate("2006-01-02T15:04:05Z", whoisInfo.Domain.ExpirationDate)
		}
	}

	// Ensure optional fields (Administrative and Technical) are nil if empty
	if isEmptyContact(whoisInfo.Administrative) {
		whoisInfo.Administrative = nil
	}
	if isEmptyContact(whoisInfo.Technical) {
		whoisInfo.Technical = nil
	}

	if whoisInfo.Domain.Domain == "" {
		return WhoisInfo{}, errors.New("missing domain name")
	}

	return whoisInfo, nil
}
