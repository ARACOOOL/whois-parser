/*
 * Copyright 2014-2022 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Go module for domain whois information parsing
 * https://www.likexian.com/
 */

package whoisparser

import (
	v2 "github.com/ARACOOOL/whois-parser/v2"
	"regexp"
	"strings"

	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xslice"
	"golang.org/x/net/idna"
)

// Version returns package version
func Version() string {
	return "1.3.2"
}

// Author returns package author
func Author() string {
	return "[Li Kexian](https://www.likexian.com/)"
}

// License returns package license
func License() string {
	return "Licensed under the Apache License 2.0"
}

// Parse returns parsed whois info
func Parse(text, domainName string) (whoisInfo v2.WhoisInfo, err error) { //nolint:cyclop
	err = getDomainErrorType(text)
	if err != nil {
		return
	}

	parts := strings.Split(strings.ToLower(strings.TrimSpace(domainName)), ".")
	extension := parts[len(parts)-1]

	if extension != "" && isExtNotFoundDomain(text, extension) {
		err = ErrNotFoundDomain
		return
	}

	parser := v2.NewParser(extension)
	if parser != nil {
		return parser.Parse(text)
	}

	domain := &v2.Domain{}
	registrar := &v2.Contact{}
	registrant := &v2.Contact{}
	administrative := &v2.Contact{}
	technical := &v2.Contact{}
	billing := &v2.Contact{}

	domain.Name, _ = idna.ToASCII(domainName)
	domain.Extension, _ = idna.ToASCII(extension)

	whoisText, _ := Prepare(text, domain.Extension)
	whoisLines := strings.Split(whoisText, "\n")

	if len(whoisLines) <= 3 {
		err = ErrDomainDataInvalid
		return
	}

	for i := 0; i < len(whoisLines); i++ {
		line := strings.TrimSpace(whoisLines[i])
		if len(line) < 5 || !strings.Contains(line, ":") {
			continue
		}

		fChar := line[:1]
		if assert.IsContains([]string{"-", "*", "%", ">", ";"}, fChar) {
			continue
		}

		if line[len(line)-1:] == ":" {
			i++
			for ; i < len(whoisLines); i++ {
				thisLine := strings.TrimSpace(whoisLines[i])
				if strings.Contains(thisLine, ":") {
					break
				}
				line += thisLine + ","
			}
			line = strings.Trim(line, ",")
			i--
		}

		lines := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(lines[0])
		value := strings.TrimSpace(lines[1])
		value = strings.TrimSpace(strings.Trim(value, ":"))

		if value == "" {
			continue
		}

		keyName := searchKeyName(name)
		switch keyName {
		case "domain_id":
			domain.ID = value
		case "domain_name":
			if domain.Domain == "" {
				domain.Domain = strings.ToLower(value)
				domain.Punycode, _ = idna.ToASCII(domain.Domain)
			}
		case "domain_status":
			domain.Status = append(domain.Status, strings.Split(value, ",")...)
		case "domain_dnssec":
			if !domain.DNSSec {
				domain.DNSSec = isDNSSecEnabled(value)
			}
		case "whois_server":
			if domain.WhoisServer == "" {
				domain.WhoisServer = value
			}
		case "name_servers":
			domain.NameServers = append(domain.NameServers, strings.Split(value, ",")...)
		case "created_date":
			if domain.CreatedDate == "" {
				domain.CreatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.CreatedDateInTime = &parsed
				}
			}
		case "updated_date":
			if domain.UpdatedDate == "" {
				domain.UpdatedDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.UpdatedDateInTime = &parsed
				}
			}
		case "expired_date":
			if domain.ExpirationDate == "" {
				domain.ExpirationDate = value
				if parsed, err := parseDateString(value); err == nil {
					domain.ExpirationDateInTime = &parsed
				}
			}
		case "referral_url":
			registrar.ReferralURL = value
		case "registrant_organization":
			registrant.Organization = value
		default:
			name = clearKeyName(name)
			if !strings.Contains(name, " ") {
				if name == "registrar" {
					name += " name"
				} else {
					name += " organization"
				}
			}

			ns := strings.SplitN(name, " ", 2)

			if ns[0] == "registrar" || ns[0] == "registration" {
				parseContact(registrar, name, value)
			} else if ns[0] == "registrant" || ns[0] == "holder" {
				parseContact(registrant, name, value)
			} else if ns[0] == "admin" || ns[0] == "administrative" {
				parseContact(administrative, name, value)
			} else if ns[0] == "tech" || ns[0] == "technical" {
				parseContact(technical, name, value)
			} else if ns[0] == "bill" || ns[0] == "billing" {
				parseContact(billing, name, value)
			}
		}
	}

	domain.NameServers = fixNameServers(domain.NameServers)
	domain.Status = fixDomainStatus(domain.Status)

	domain.NameServers = xslice.Unique(domain.NameServers).([]string)
	domain.Status = xslice.Unique(domain.Status).([]string)

	whoisInfo.Domain = domain
	if *registrar != (v2.Contact{}) {
		whoisInfo.Registrar = registrar
	}

	if *registrant != (v2.Contact{}) {
		whoisInfo.Registrant = registrant
	}

	if *administrative != (v2.Contact{}) {
		whoisInfo.Administrative = administrative
	}

	if *technical != (v2.Contact{}) {
		whoisInfo.Technical = technical
	}

	if *billing != (v2.Contact{}) {
		whoisInfo.Billing = billing
	}

	return
}

// parseContact do parse contact info
func parseContact(contact *v2.Contact, name, value string) {
	switch searchKeyName(name) {
	case "registrant_id":
		contact.ID = value
	case "registrant_name", "registrar_name":
		if contact.Name == "" {
			contact.Name = value
		}
	case "registrant_organization", "registrar_organization":
		if contact.Organization == "" {
			contact.Organization = value
		}
	case "registrant_street", "registrar_street":
		if contact.Street == "" {
			contact.Street = value
		} else {
			contact.Street += ", " + value
		}
	case "registrant_city", "registrar_city":
		contact.City = value
	case "registrant_state_province", "registrar_state_province":
		contact.Province = value
	case "registrant_postal_code", "registrar_postal_code":
		contact.PostalCode = value
	case "registrant_country", "registrar_country":
		contact.Country = value
	case "registrant_phone", "registrar_phone":
		contact.Phone = value
	case "registrant_phone_ext", "registrar_phone_ext":
		contact.PhoneExt = value
	case "registrant_fax", "registrar_fax":
		contact.Fax = value
	case "registrant_fax_ext", "registrar_fax_ext":
		contact.FaxExt = value
	case "registrant_email", "registrar_email":
		contact.Email = strings.ToLower(value)
	}
}

// searchDomain finds domain name and extension from whois information
func searchDomain(text string) (name, extension string) {
	r := regexp.MustCompile(`(?i)\[?domain\:?(\s*\_?name)?\]?[\s\.]*\:?\s*([^\s\,\;\(\)]+)\.([^\s\,\;\(\)\.]{2,})`)
	m := r.FindStringSubmatch(text)
	if len(m) > 0 {
		name = strings.TrimSpace(m[2])
		extension = strings.TrimSpace(m[3])
	}

	if name != "" {
		name = strings.ToLower(name)
		extension = strings.ToLower(extension)
	}

	return
}
