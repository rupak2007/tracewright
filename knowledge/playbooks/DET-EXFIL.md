# K-PB-DET-EXFIL: verifying an unusual-outbound-volume finding

**What the detector saw.** An internal host sent much more data to one external destination than the
usual internal-to-external pair in this capture (a modified z-score of log outbound bytes), above a
byte floor, with far more outbound than inbound data. If the capture has fewer than 20 such pairs
there is no baseline: only the floor applies and the finding carries low confidence.

## Check in Zeek / Wireshark
- Open the slice and look at the conversation: one long upload, or many connections adding up?
- Identify the destination (IP, TLS server name, HTTP Host). Is it a cloud storage or backup
  provider the organisation uses, or an unfamiliar address?
- Check timing: a nightly backup window is expected; a transfer at an unusual hour is not.
- Inspect `conn.log` bytes and duration; the out/in ratio shows whether the transfer was one-way.
- See whether the host also beacons to the same destination (a linked incident), which would raise
  the concern.

## Common benign explanations
- Backups, cloud synchronisation, large file uploads, video calls or screen sharing.
- CI systems pushing build artifacts, software release uploads, log shipping.

## What would confirm it
- An unfamiliar destination, an unusual time, data volume with no ticket or schedule behind it, and
  a shared destination with periodic check-ins.

## What would refute it
- The destination is a configured backup server or sanctioned cloud service and the volume matches
  its schedule (known backup servers are suppressed by the network context).
