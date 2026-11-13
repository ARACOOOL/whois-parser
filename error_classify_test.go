package whoisparser

import (
	"os"
	"strings"
	"testing"
)

// registeredRecord is a synthetic thick gTLD record for a registered domain.
const registeredRecord = `Domain Name: EXAMPLE.COM
Registry Domain ID: 123456789_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.example
Updated Date: 2024-01-02T03:04:05Z
Creation Date: 2020-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Registrar: Example Registrar, Inc.
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned
`

// fixtures returns the raw sample files of a testdata directory keyed by queried domain.
func fixtures(t *testing.T, dir string) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	samples := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if name == "README.md" || strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".pre") {
			continue
		}
		raw, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		samples[strings.SplitN(name, "_", 2)[1]] = string(raw)
	}
	if len(samples) == 0 {
		t.Fatalf("no samples in %s", dir)
	}

	return samples
}

func TestCorpusRegisteredNeverClassified(t *testing.T) {
	for domain, raw := range fixtures(t, noterrorDir) {
		info, err := Parse(raw, domain)
		if err != nil {
			t.Errorf("%s: registered sample classified as error: %v", domain, err)
			continue
		}
		if info.Domain == nil || info.Domain.Domain == "" {
			t.Errorf("%s: registered sample produced no domain", domain)
		}
	}
}

func TestCorpusNotFoundStillClassified(t *testing.T) {
	// Before this change every sample in testdata/notfound returned ErrNotFoundDomain.
	for domain, raw := range fixtures(t, notfoundDir) {
		if _, err := Parse(raw, domain); err != ErrNotFoundDomain {
			t.Errorf("%s: got %v, want %v", domain, err, ErrNotFoundDomain)
		}
	}
}

func TestStatusAvailableIsNotFound(t *testing.T) {
	notFound := []struct{ name, domain, raw string }{
		{"be upper tab", "zzq-audit.be", "% .be Whois Server 6.1\n%\n% The WHOIS service is for information only.\n%\nDomain:\tzzq-audit.be\nStatus:\tAVAILABLE\n\n"},
		{"lt lower", "zzq-audit.lt", "% Hello, this is the DOMREG whois service.\n%\n% By submitting a query you agree to the terms.\n%\nDomain:\t\t\tzzq-audit.lt\nStatus:\t\t\tavailable\n"},
		{"lv free", "zzq-audit.lv", "[Domain]\nDomain: zzq-audit.lv\nStatus: free\n\n[Whois]\nUpdated: 2026-11-13T16:00:00+00:00\n\n[Disclaimer]\n% The WHOIS service is provided for information purposes.\n"},
		{"crlf", "zzq-audit.be", "Domain: zzq-audit.be\r\nStatus: AVAILABLE\r\n\r\nline\r\nline\r\n"},
		{"domain status no object", "zzq-audit.xyz", "Domain Name: zzq-audit.xyz\nDomain Status: No Object Found\nline\nline\nline\n"},
		{"not registered", "zzq-audit.xyz", "domain: zzq-audit.xyz\nstatus: Not Registered\nline\nline\nline\n"},
	}
	for _, tc := range notFound {
		if _, err := Parse(tc.raw, tc.domain); err != ErrNotFoundDomain {
			t.Errorf("%s: got %v, want %v", tc.name, err, ErrNotFoundDomain)
		}
	}

	registered := []string{
		"Status: connect",
		"Status: active",
		"Domain Status: ok https://icann.org/epp#ok",
		"Status: Available for transfer after lock period",
		"Registrant Organization: Free Software Foundation",
	}
	for _, line := range registered {
		info, err := Parse(registeredRecord+line+"\n", "example.com")
		if err != nil {
			t.Errorf("%q: unexpected error %v", line, err)
			continue
		}
		if info.Domain.Domain != "example.com" {
			t.Errorf("%q: domain = %q", line, info.Domain.Domain)
		}
	}
}

func TestTriggerPhrasesInsideRecord(t *testing.T) {
	lines := []string{
		"Registrant Name: Chris Freeman",
		"Registrant Organization: Lost Not Found Ltd",
		"Registrant Organization: No Match Dating LLC",
		"Registrant Street: Company not registered for VAT",
		"Registrant Organization: Reserved Domain Names Ltd",
		"Registrant Organization: Server Too Busy Hosting",
		"NOTICE: this output does not indicate that the name is available for registration.",
		"TERMS: access may be withdrawn if the daily query limit exceeded.",
		"URL of the ICANN form: report an invalid request at https://icann.example/wicf",
		">>> Last update of whois database: 2026-11-13T16:27:21Z <<<\nThe Registry database contains ONLY .COM domains. No match is implied by this notice.",
	}
	for _, line := range lines {
		info, err := Parse(registeredRecord+line+"\n", "example.com")
		if err != nil {
			t.Errorf("%q: registered record classified as %v", line, err)
			continue
		}
		if info.Domain.Domain != "example.com" || info.Domain.ID != "123456789_DOMAIN_COM-VRSN" {
			t.Errorf("%q: record not parsed: %+v", line, info.Domain)
		}
		if len(info.Domain.NameServers) != 2 {
			t.Errorf("%q: name servers = %v", line, info.Domain.NameServers)
		}
	}
}

func TestBannersAndEmptyExtraction(t *testing.T) {
	pad := "\n%\n% terms of use line one\n% terms of use line two\n% terms of use line three\n"
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"il no data", "% The data in the WHOIS database is provided for information." + pad + "% No data was found to match the request criteria.\n", ErrNotFoundDomain},
		{"does not exist", "Domain name example.com does not exist in database!" + pad, ErrNotFoundDomain},
		{"spanish", "% La informacion a la que estas accediendo se provee exclusivamente" + pad + "El dominio no se encuentra registrado en NIC Argentina\n", ErrNotFoundDomain},
		{"too many requests", "%% Too many requests..." + pad, ErrDomainLimitExceed},
		{"quota", "Quota exceeded" + pad, ErrDomainLimitExceed},
		{"rate limit", "Query rate limit reached. Please try again later." + pad, ErrDomainLimitExceed},
		{"allotted", "You have exceeded your allotted number of WHOIS queries" + pad, ErrDomainLimitExceed},
		{"not permitted short", "Requests of this client are not permitted. Please use https://www.nic.ch/whois/ for queries.\n\n", ErrDomainLimitExceed},
		{"access denied", "Access denied: your address has been restricted" + pad, ErrDomainLimitExceed},
		{"nothing extracted", "line one\nline two\nline three\nline four\nline five\n", ErrDomainDataInvalid},
		{"keys but no domain", "Registrar: Someone\nName Server: ns1.example.net\nName Server: ns2.example.net\nUpdated: today\nRemarks: none\n", ErrDomainDataInvalid},
	}
	for _, tc := range tests {
		info, err := Parse(tc.raw, "example.com")
		if err != tc.want {
			t.Errorf("%s: got err=%v domain=%+v, want %v", tc.name, err, info.Domain, tc.want)
		}
	}
}
