# E1-C3 Challenge

## Scenario

You are given several logs from the same time window. Identify the adversary-controlled service contacted by the host and determine the primary beacon period.

## Files

* `flows.csv`
* `dns.log`
* `dhcp_leases.csv`
* `tls_fingerprints.csv`
* `asn_map.csv`

## Deliverable

Write exactly one line to `flag.txt`:

```
sha256(domain + "|" + period_seconds + "|" + hostname)
```

All lowercase hex, newline terminated.
