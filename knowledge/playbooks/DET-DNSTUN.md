# K-PB-DET-DNSTUN: verifying a DNS-tunnelling finding

**What the detector saw.** One client sent many DNS queries under one registered domain with many
distinct, long or high-entropy subdomains, or mostly TXT/NULL queries. Tunnels encode data in the
query name, so unique-subdomain count, length and entropy rise. `nxdomain_rate` and
`name_bytes_total` show how much was asked and how often the name did not exist.

## Check in Zeek / Wireshark
- Filter the client's queries to the registered domain: `dns.qry.name contains "<domain>"`.
- Read a few query names in the slice: random-looking base32/hex labels of 30-60 characters under one
  domain are typical of tunnels; readable hostnames (`img12.cdn.example`) are not.
- Compare record types: heavy TXT or NULL queries are unusual for ordinary clients.
- Check which resolver was asked and whether the domain is authoritative for an unusual server.
- Look at the response sizes: tunnels often carry data back in TXT answers.

## Common benign explanations
- Content delivery networks and ad or analytics services generating many sub-hostnames.
- Antivirus, reputation and software-update lookups that encode a hash in the name.
- Telemetry agents and DNS-based blocklists.
- Mail anti-spam checks (DNSBL) that query encoded IP addresses.

## What would confirm it
- Random-looking labels under a domain nobody recognises, steady volume, high NXDOMAIN or TXT share,
  and no application on the host that explains it.

## What would refute it
- The domain is a known vendor (see the allowlist); labels are structured and human-readable; the
  host runs software documented to use encoded lookups.
