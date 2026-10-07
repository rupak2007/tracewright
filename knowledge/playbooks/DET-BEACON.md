# K-PB-DET-BEACON: verifying a periodic check-in finding

**What the detector saw.** Connections (or HTTP requests) from one internal host to one destination
that repeat at regular intervals with similar sizes. The score combines timing regularity, skew
symmetry, size regularity and how much of the capture the series covers. High regularity is the
signature of automated check-ins; it is not proof that the software is malicious.

## Check in Zeek / Wireshark
- List the connections in the slice and read the inter-arrival times: a steady interval (with or
  without small jitter) matches the finding's `median_interval_s`.
- Identify the destination: IP, port, TLS server name or HTTP Host. Is it a service the host is meant
  to use? An unfamiliar name or a bare IP on a non-standard port deserves more attention.
- Compare the sizes: constant small requests with small responses look like polling; growing
  transfers look like updates or uploads.
- For HTTP, inspect the User-Agent and URI pattern in `http.log`; for TLS, the certificate and
  JA3-style fingerprints if available.
- Check whether the host also shows other findings (see linked incidents) or an unusual process.

## Common benign explanations
- NTP and other time synchronisation, software update checks, license or telemetry agents.
- Monitoring and management agents (heartbeats), keep-alives, mail polling, chat presence.
- Cloud-sync clients checking for changes.

## What would confirm it
- A destination with no business justification, an unusual port or protocol for that host, a steady
  interval across the whole capture, and corroborating findings for the same host.

## What would refute it
- The destination belongs to a documented vendor or internal monitoring server and the interval
  matches that product's documented check-in period.
