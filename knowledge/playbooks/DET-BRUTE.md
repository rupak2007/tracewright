# K-PB-DET-BRUTE: verifying a repeated-login-attempt finding

**What the detector saw.** Repeated login attempts from one source to one destination service in a
five-minute window. For FTP (reply code 530) and HTTP (401/403 on the same URI) the failures were
*observed*; for SSH, RDP and Telnet the traffic is encrypted, so the finding is *inferred* from many
short connections of similar size. The `variant` metric says whether one target or several (spray).

## Check in Zeek / Wireshark
- FTP: filter `ftp.response.code == 530` for the source; many failures for one account or many accounts?
- HTTP: filter `http.response.code == 401 || http.response.code == 403` for the source and URI.
- SSH/RDP/Telnet: in `conn.log` list connections from the source to the service port; look at
  `duration` (a failed login ends within seconds) and `orig_bytes` (similar sizes repeat). In
  `ssh.log` check `auth_success` and `auth_attempts` where Zeek reports them.
- Check whether any attempt succeeded afterwards: a long SSH session or FTP `230` reply after the failures.
- For a spray finding, compare the target list: the same service on many hosts from one source.

## Common benign explanations
- Automation (backup or deployment tools) with an expired or wrong credential retrying.
- Health checks or monitoring that open and close a login prompt.
- Users behind a shared NAT address mistyping passwords.
- Misconfigured clients that retry aggressively after a timeout.

## What would confirm it
- Dozens of failures in minutes across many usernames or many hosts, followed by a success.
- Failures from an address with no legitimate relationship to the service.

## What would refute it
- One automation account failing at a fixed interval from a known management host; no success
  afterwards and the credential change explains it.
