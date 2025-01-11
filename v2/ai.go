package v2

import (
	"errors"

	"strings"
)

// AIParser handles parsing for the .ai zone WHOIS provider.
type AIParser struct{}

// Parse implements the Parser interface for the .ai zone.
func (p *AIParser) Parse(whoisText string) (WhoisInfo, error) {
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
		if strings.HasPrefix(line, "Domain Name:") {
			whoisInfo.Domain.Domain = cleanValue(line, "Domain Name:")
		} else if strings.HasPrefix(line, "Registry Domain ID:") {
			whoisInfo.Domain.ID = cleanValue(line, "Registry Domain ID:")
		} else if strings.HasPrefix(line, "Registrar WHOIS Server:") {
			whoisInfo.Domain.WhoisServer = cleanValue(line, "Registrar WHOIS Server:")
		} else if strings.HasPrefix(line, "Registrar:") {
			whoisInfo.Registrar.Name = cleanValue(line, "Registrar:")
		} else if strings.HasPrefix(line, "Registrar Address:") {
			whoisInfo.Registrar.Street = cleanValue(line, "Registrar Address:")
		} else if strings.HasPrefix(line, "Registrar Country:") {
			whoisInfo.Registrar.Country = cleanValue(line, "Registrar Country:")
		} else if strings.HasPrefix(line, "Registrar Phone:") {
			whoisInfo.Registrar.Phone = cleanValue(line, "Registrar Phone:")
		} else if strings.HasPrefix(line, "Registrant Name:") {
			whoisInfo.Registrant.Name = cleanValue(line, "Registrant Name:")
		} else if strings.HasPrefix(line, "Registrant Organization:") {
			whoisInfo.Registrant.Organization = cleanValue(line, "Registrant Organization:")
		} else if strings.HasPrefix(line, "Registrant Country:") {
			whoisInfo.Registrant.Country = cleanValue(line, "Registrant Country:")
		} else if strings.HasPrefix(line, "Admin Name:") {
			whoisInfo.Administrative.Name = cleanValue(line, "Admin Name:")
		} else if strings.HasPrefix(line, "Admin Organization:") {
			whoisInfo.Administrative.Organization = cleanValue(line, "Admin Organization:")
		} else if strings.HasPrefix(line, "Admin Country:") {
			whoisInfo.Administrative.Country = cleanValue(line, "Admin Country:")
		} else if strings.HasPrefix(line, "Tech Name:") {
			whoisInfo.Technical.Name = cleanValue(line, "Tech Name:")
		} else if strings.HasPrefix(line, "Tech Organization:") {
			whoisInfo.Technical.Organization = cleanValue(line, "Tech Organization:")
		} else if strings.HasPrefix(line, "Tech Country:") {
			whoisInfo.Technical.Country = cleanValue(line, "Tech Country:")
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
