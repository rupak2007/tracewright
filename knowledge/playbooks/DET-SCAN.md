# K-PB-DET-SCAN: verifying a port or host scan finding

**What the detector saw.** One source contacted many distinct destination ports on one host
(vertical), many hosts on one port (horizontal), or many ports slowly over ten minutes (slow
vertical), and the share of connections that failed (no reply, reset, rejected) is recorded as
`failed_share`. It describes connection patterns only; it does not know the sender's intent.

## Check in Zeek / Wireshark
- Open the packet slice for the finding, or filter the capture by the primary entity as the source:
  `ip.src == <source> && tcp.flags.syn == 1 && tcp.flags.ack == 0`.
- Count the distinct destination ports (Statistics > Conversations > TCP): a scan shows many
  short conversations with no payload; a busy service shows few ports with many bytes.
- In `conn.log`, look at `conn_state`: `S0` (SYN, no answer), `REJ` (rejected) and `RSTO`/`RSTR` are
  typical of probing closed ports; `SF` conversations on many ports mean the ports were open.
- Check the timing: evenly paced probes suggest a tool; bursts to ports that applications really use
  (80, 443, 445, 3389) suggest discovery of services.

## Common benign explanations
- A vulnerability scanner or inventory tool run by the owner (see `known_hosts.scanners`).
- A monitoring system probing service health on several ports.
- A NAT gateway or proxy that multiplexes many clients behind one address.
- Peer-to-peer or discovery software that contacts many hosts on one port.

## What would confirm it
- No payload exchanged, many `S0`/`REJ` states, one source, and no business reason to sweep the range.
- The same source later authenticating or connecting to a service it found open.

## What would refute it
- The source is a documented scanner or monitoring host; the destination ports belong to one
  application's normal port range; most connections completed normally with data.
