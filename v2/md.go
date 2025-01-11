package v2

import (
	"errors"
	"strings"
)

type MDParser struct{}

// Parse implements the Parser interface for .md zones.
func (p *MDParser) Parse(whoisText string) (WhoisInfo, error) {
	lines := strings.Split(whoisText, "\n")
	whoisInfo := WhoisInfo{
		Domain: &Domain{},
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Domain  name") {
			whoisInfo.Domain.Domain = cleanValue(line, "Domain  name")
		} else if strings.HasPrefix(line, "Domain state") {
			whoisInfo.Domain.Status = []string{cleanValue(line, "Domain state")}
		} else if strings.HasPrefix(line, "Registered on") {
			dateStr := cleanValue(line, "Registered on")
			whoisInfo.Domain.CreatedDate = dateStr
			whoisInfo.Domain.CreatedDateInTime = parseDate("2006-01-02", dateStr)
		} else if strings.HasPrefix(line, "Expires    on") {
			dateStr := cleanValue(line, "Expires    on")
			whoisInfo.Domain.ExpirationDate = dateStr
			whoisInfo.Domain.ExpirationDateInTime = parseDate("2006-01-02", dateStr)
		} else if strings.HasPrefix(line, "Nameserver") {
			whoisInfo.Domain.NameServers = append(whoisInfo.Domain.NameServers, cleanValue(line, "Nameserver"))
		}
	}

	if whoisInfo.Domain.Domain == "" {
		return WhoisInfo{}, errors.New("missing domain name")
	}

	return whoisInfo, nil
}
