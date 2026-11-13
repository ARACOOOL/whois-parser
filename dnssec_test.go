package whoisparser

import "testing"

// Registries that publish key material instead of a "DNSSEC: signed" line.
// Samples are trimmed registry-owned records without contact data.
func TestParseDNSSECFromKeyMaterial(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		whois  string
		signed bool
	}{
		{
			name:   "de dnskey",
			domain: "denic.de",
			whois: "Domain: denic.de\n" +
				"Nserver: ns1.denic.de 77.67.63.106\n" +
				"Nserver: ns4.denic.net\n" +
				"Dnskey: 257 3 8 AwEAAb/xrM2MD+xm84YNYby6TxkMaC6PtzF2bB9WBB7ux7iqzhViob4GKvQ6L7Ck\n" +
				"Status: connect\n" +
				"Changed: 2024-12-19T13:33:43+01:00\n",
			signed: true,
		},
		{
			name:   "de without dnskey",
			domain: "example.de",
			whois: "Domain: example.de\n" +
				"Nserver: ns1.example.net\n" +
				"Nserver: ns2.example.net\n" +
				"Status: connect\n" +
				"Changed: 2024-12-19T13:33:43+01:00\n",
			signed: false,
		},
		{
			name:   "eu keys block",
			domain: "eurid.eu",
			whois: "Domain: eurid.eu\n" +
				"Script: LATIN\n" +
				"\n" +
				"Registrar:\n" +
				"        Name: EURid vzw\n" +
				"        Website: https://www.eurid.eu\n" +
				"\n" +
				"Name servers:\n" +
				"        nsp.netnod.se\n" +
				"        ns1.eurid.eu (185.36.4.252)\n" +
				"\n" +
				"Keys:\n" +
				"        flags:KSK protocol:3 algorithm:RSA_SHA256 pubKey:AwEAAcOQldGtC33GLx8s335UscKMPlWjDXCq\n" +
				"\n" +
				"Please visit www.eurid.eu for more info.\n",
			signed: true,
		},
		{
			name:   "eu without keys block",
			domain: "example.eu",
			whois: "Domain: example.eu\n" +
				"Script: LATIN\n" +
				"\n" +
				"Registrar:\n" +
				"        Name: EURid vzw\n" +
				"        Website: https://www.eurid.eu\n" +
				"\n" +
				"Name servers:\n" +
				"        ns1.example.net\n" +
				"\n" +
				"Please visit www.eurid.eu for more info.\n",
			signed: false,
		},
		{
			name:   "be keys block",
			domain: "dns.be",
			whois: "Domain:\tdns.be\n" +
				"Status:\tNOT AVAILABLE\n" +
				"Registered:\tMon Jan 1 1996\n" +
				"\n" +
				"Registrar:\n" +
				"\tName:\tDNS BE vzw/asbl\n" +
				"\tWebsite:\thttp://www.dns.be\n" +
				"\n" +
				"Nameservers:\n" +
				"\tns1.dns.be (52.213.12.197)\n" +
				"\tns2.dns.be (18.195.220.217)\n" +
				"\n" +
				"Keys:\n" +
				"\tkeyTag:60273 flags:KSK protocol:3 algorithm:ECDSAP256SHA256 pubKey:DCMdQ9Jw7ZYbXY7vJ/mIX9YSPpoQ\n" +
				"\n" +
				"Flags:\n" +
				"\tclientTransferProhibited\n",
			signed: true,
		},
		{
			name:   "jp signing key",
			domain: "jprs.jp",
			whois: "Domain Information:\n" +
				"[Domain Name]                   JPRS.JP\n" +
				"\n" +
				"[Registrant]                    Japan Registry Services Co.,Ltd.\n" +
				"\n" +
				"[Name Server]                   ns1.jprs.jp\n" +
				"[Name Server]                   ns2.jprs.jp\n" +
				"[Signing Key]                   7240 8 2 (\n" +
				"                                E147A85589E24FE0DBB5980C73501B5D\n" +
				"                                D656BE5550714F150BE574AE8777B77D )\n" +
				"\n" +
				"[Created on]                    2001/02/02\n" +
				"[Expires on]                    2027/02/28\n" +
				"[Status]                        Active\n",
			signed: true,
		},
		{
			name:   "jp empty signing key",
			domain: "example.jp",
			whois: "Domain Information:\n" +
				"[Domain Name]                   EXAMPLE.JP\n" +
				"\n" +
				"[Registrant]                    Example Co.,Ltd.\n" +
				"\n" +
				"[Name Server]                   ns1.example.net\n" +
				"[Signing Key]                   \n" +
				"\n" +
				"[Created on]                    2001/02/02\n" +
				"[Expires on]                    2027/02/28\n" +
				"[Status]                        Active\n",
			signed: false,
		},
		{
			name:   "cz keyset",
			domain: "nic.cz",
			whois: "domain:       nic.cz\n" +
				"registrant:   CZ-NIC\n" +
				"nsset:        CZ.NIC\n" +
				"keyset:       AUTO-ZHHWRIDCGH9F46ZDG2K2VC284\n" +
				"registrar:    REG-CZNIC\n" +
				"registered:   30.10.1997 01:00:00\n" +
				"expire:       15.03.2027\n" +
				"\n" +
				"nsset:        CZ.NIC\n" +
				"nserver:      a.ns.nic.cz (194.0.12.1, 2001:678:f::1)\n" +
				"nserver:      b.ns.nic.cz (194.0.13.1, 2001:678:10::1)\n",
			signed: true,
		},
		{
			name:   "br dsrecord",
			domain: "registro.br",
			whois: "domain:      registro.br\n" +
				"owner:       NIC.BR\n" +
				"country:     BR\n" +
				"nserver:     a.dns.br\n" +
				"nsstat:      20261111 AA\n" +
				"dsrecord:    59973 ECDSA-SHA-256 17A233B59FE51E6205205E0556343DB121AB5023663A1B5628133AFFEA95A5C9\n" +
				"dsstatus:    20261111 DSOK\n" +
				"created:     19990221 #142485\n" +
				"status:      published\n",
			signed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Parse(tt.whois, tt.domain)
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if info.Domain == nil {
				t.Fatal("Parse returned no domain")
			}
			if info.Domain.DNSSec != tt.signed {
				t.Errorf("DNSSec = %v, want %v", info.Domain.DNSSec, tt.signed)
			}
			if len(info.Domain.NameServers) == 0 {
				t.Error("name servers were lost")
			}
		})
	}
}
