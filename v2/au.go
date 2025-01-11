package v2

import (
	"errors"
	"strings"
)

// AUParser handles parsing for the .au zone WHOIS provider.
type AUParser struct{}

// Parse implements the Parser interface for .gov.au zone.
func (p *AUParser) Parse(whoisText string) (WhoisInfo, error) {
	lines := strings.Split(whoisText, "\n")
	whoisInfo := WhoisInfo{
		Domain:     &Domain{},
		Registrar:  &Contact{},
		Registrant: &Contact{},
		Technical:  &Contact{},
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
		case strings.HasPrefix(line, "Last Modified:"):
			whoisInfo.Domain.UpdatedDate = cleanValue(line, "Last Modified:")
			whoisInfo.Domain.UpdatedDateInTime = parseDate("2006-01-02T15:04:05Z", whoisInfo.Domain.UpdatedDate)
		case strings.HasPrefix(line, "Registrar Name:"):
			whoisInfo.Registrar.Name = cleanValue(line, "Registrar Name:")
		case strings.HasPrefix(line, "Registrar Abuse Contact Email:"):
			whoisInfo.Registrar.Email = cleanValue(line, "Registrar Abuse Contact Email:")
		case strings.HasPrefix(line, "Registrar Abuse Contact Phone:"):
			whoisInfo.Registrar.Phone = cleanValue(line, "Registrar Abuse Contact Phone:")
		case strings.HasPrefix(line, "Registrant Contact ID:"):
			whoisInfo.Registrant.ID = cleanValue(line, "Registrant Contact ID:")
		case strings.HasPrefix(line, "Registrant Contact Name:"):
			whoisInfo.Registrant.Name = cleanValue(line, "Registrant Contact Name:")
		case strings.HasPrefix(line, "Registrant:"):
			whoisInfo.Registrant.Organization = cleanValue(line, "Registrant:")
		case strings.HasPrefix(line, "Registrant ID:"):
			whoisInfo.Registrant.ReferralURL = cleanValue(line, "Registrant ID:")
		case strings.HasPrefix(line, "Eligibility Type:"):
			whoisInfo.Domain.Status = append(whoisInfo.Domain.Status, cleanValue(line, "Eligibility Type:"))
		case strings.HasPrefix(line, "Tech Contact ID:"):
			whoisInfo.Technical.ID = cleanValue(line, "Tech Contact ID:")
		case strings.HasPrefix(line, "Tech Contact Name:"):
			whoisInfo.Technical.Name = cleanValue(line, "Tech Contact Name:")
		case strings.HasPrefix(line, "Name Server:"):
			whoisInfo.Domain.NameServers = append(whoisInfo.Domain.NameServers, cleanValue(line, "Name Server:"))
		case strings.HasPrefix(line, "DNSSEC:"):
			whoisInfo.Domain.DNSSec = strings.ToLower(cleanValue(line, "DNSSEC:")) == "signed"
		}
	}

	if whoisInfo.Domain.Domain == "" {
		return WhoisInfo{}, errors.New("missing domain name")
	}

	return whoisInfo, nil
}
