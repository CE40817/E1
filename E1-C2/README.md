# E1-C2 Challenge: The Ground Truth Detective Hard Mode

## Scenario

A C2 server at `185.17.3.10` was observed. Network-based detection is noisy and ambiguous. Endpoint telemetry is partial, uses local time, and includes process injection. NAT and a local proxy break direct five tuple matching.

## What you get

* `netflow.csv` in UTC with edge IPs at the firewall
* `nat.csv` mapping inside to outside at the firewall
* `tls_ja3.csv` with two client fingerprints; only one is the C2 fingerprint
* `dhcp_leases.csv` mapping hostnames to IPs
* `proxy.log` mapping loopback to external flow
* `edr_events.jsonl` in local time with time_sync corrections and process GUIDs
* `security_4688.log` with a creation event not present in EDR
* `logon_sessions.json` to disambiguate interactive vs system ancestors

## Goal

Find the true root process and compute the flag exactly as:

```
sha256( root_name + "|" + root_pid + "|" + root_create_time_floor_to_minute_UTC )
```

The timestamp must be in the format `YYYY-MM-DDTHH:MM` after converting to UTC.

Output the lowercase hex digest to `flag.txt` and nothing else.

### Example shape only

```
sha256("notepad.exe|1234|2025-01-01T12:34")
```
