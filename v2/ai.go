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
		} else if strings.HasPrefix(line, "Registrar Address:") {
			whoisInfo.Registrar.Street = cleanValue(line, "Registrar Address:")
		} else if strings.HasPrefix(line, "Registrar Country:") {
			whoisInfo.Registrar.Country = cleanValue(line, "Registrar Country:")
		} else if strings.HasPrefix(line, "Registrar Phone:") {
			whoisInfo.Registrar.Phone = cleanValue(line, "Registrar Phone:")
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
