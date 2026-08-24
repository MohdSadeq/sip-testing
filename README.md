# SIP trunk tester (IP-whitelisted trunks)

A dependency-free Python 3 toolkit to test a SIP trunk that authenticates by
**source IP** (no username/password). Copy the folder to the **server whose IP
the provider has whitelisted**, fill in `config.env`, and run.

> IP-whitelist trunks authorize your **egress IP**, not credentials. So every
> test here is really answering one question: *does a SIP message leave this
> server, reach the trunk, and get accepted?* Run it **on the whitelisted
> server** — running it anywhere else will fail even if everything is correct.

## Requirements

- Python 3.6+ (uses only the standard library — no `pip`, no `sudo`)
- Outbound UDP to the trunk's SIP port (default 5060) allowed by any firewall

## Setup

1. Copy `sip_test.py`, `config.env`, and `run.sh` to the whitelisted server.
2. Edit `config.env` — at minimum set `SIP_HOST`. For call tests also set
   `DIAL_TARGET` and `CALLER_ID`.
3. Run a test (below).

## The four tests

```bash
# 1. Diagnose: DNS + the exact source IP the trunk sees + a reachability probe.
#    Run this FIRST. The "OS will send from" IP must match the whitelist entry.
python3 sip_test.py diagnose

# 2. OPTIONS ping: the definitive whitelist + reachability check.
#    200 OK  = IP accepted, trunk reachable.  ✓
#    403     = reachable but rejected → IP not whitelisted (or caller not allowed).
#    401/407 = trunk wants credentials → not pure IP-auth (fill AUTH_* in config).
#    timeout = silent drop: IP not whitelisted, firewall, or wrong host/port.
python3 sip_test.py options

# 3. Outbound call: INVITE to DIAL_TARGET, follows 100/180/183/200, ACKs,
#    holds CALL_HOLD_SECONDS, then BYE. Proves outbound call signalling.
#    (No RTP/audio is sent — this validates signalling, not voice path.)
python3 sip_test.py call

# 4. Inbound DID: wait for the trunk to deliver a call, auto-answer 200 then BYE.
#    The provider must be pointing your DID at THIS server:LOCAL_PORT.
python3 sip_test.py listen
```

Add `-v` / `--verbose` to any command to print the raw SIP messages.
Use `--config /path/to/other.env` to point at a different config.

`run.sh` is a convenience wrapper: `./run.sh diagnose`, `./run.sh options`, etc.

## Reading the results

| Result | Meaning | Action |
|---|---|---|
| `200 OK` to OPTIONS | Whitelisted + reachable | You're good |
| `403 Forbidden` | Reached trunk, IP rejected | Confirm the whitelisted IP equals the "send from" IP exactly |
| `401` / `407` | Trunk wants digest auth | Not pure IP-auth; set `AUTH_USER`/`AUTH_PASS` |
| Timeout | Nothing came back | Wrong `SIP_HOST`/port, UDP blocked, or IP not whitelisted (many trunks silently drop) |
| `INVITE → 200` | Outbound call path works | — |
| `INVITE → 403` | Trunk reached but call denied | IP, caller-ID, or destination not permitted |
| `INVITE → 404` | Number format wrong for this trunk | Check `DIAL_TARGET` format (E.164 vs national) |

## Notes / gotchas

- **Source IP must be static.** If this server's egress IP can change (NAT
  pool, DHCP WAN), the whitelist will break. `diagnose` prints the current one.
- **Behind 1:1 NAT?** If the provider whitelisted your *public* IP but the
  server has a private IP, set `LOCAL_IP` in the config to the public IP so SIP
  headers/SDP advertise it correctly.
- **Inbound (`listen`) port.** Providers usually deliver to UDP 5060. Binding
  5060 needs root (`sudo python3 sip_test.py listen`) or set `LOCAL_PORT` to
  whatever the provider is configured to send to. The default `LOCAL_PORT=5062`
  avoids needing root for the outbound tests.
- **Voice/RTP.** The `call` test proves signalling only. To verify two-way
  audio you need a real softphone (baresip/pjsua/linphone) that sends RTP; this
  toolkit deliberately stays dependency-free.
- **Watch packets (optional):** `sudo apt install sngrep` then run `sngrep` in
  another terminal to see the live SIP dialog while you test.
