# E1-C4 Challenge: 0-RTT Replay

## Scenario

A ticket-based fast reconnect mode accepts early data. The server processes a non-idempotent action in early data without replay protection. Replay the same early block with the same ticket to raise the balance and fetch the flag.

## What you get

* Running service at `x.y.z.w:2135`
* `server_source/server.py` describing the protocol and the flaw

## Goal

Exploit the 0-RTT replay weakness to obtain the flag from the live service.

## Deliverable

Write the exact flag value to `flag.txt` on a single line.
