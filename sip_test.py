#!/usr/bin/env python3
"""
sip_test.py — Pure-Python tester for an IP-whitelisted SIP trunk.

No external dependencies, no pip, no sudo. UDP only.

Subcommands:
  diagnose   Resolve DNS, show the source IP the trunk will see,
             and probe UDP reachability with an OPTIONS.
  options    Send a SIP OPTIONS and interpret the response.
             (200 = whitelisted + reachable; 403 = not whitelisted;
              407/401 = trunk wants credentials; timeout = blocked/wrong host)
  call       Send an INVITE to DIAL_TARGET, follow the transaction
             (100/180/183/200), ACK on answer, hold, then BYE.
             Proves outbound signalling end-to-end. (Audio/RTP not sent.)
  listen     Bind and wait for an inbound INVITE (DID test). Auto-answers
             with 200 then BYE so you can confirm the trunk delivers calls.

Usage:
  python3 sip_test.py <subcommand> [--config config.env] [--verbose]
"""
import argparse
import hashlib
import os
import random
import select
import socket
import sys
import time
import uuid

# ── tiny ANSI helpers ───────────────────────────────────────────
def _c(code, s):
    return s if not sys.stdout.isatty() else f"\033[{code}m{s}\033[0m"
def ok(s):    return _c("32", s)
def bad(s):   return _c("31", s)
def warn(s):  return _c("33", s)
def dim(s):   return _c("2", s)
def bold(s):  return _c("1", s)


def load_config(path):
    cfg = {}
    if not os.path.exists(path):
        sys.exit(bad(f"Config file not found: {path}"))
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip()
    return cfg


def is_private_ip(ip):
    """True if ip is an RFC1918 / loopback / link-local IPv4 address."""
    try:
        octets = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(octets) != 4:
        return False
    a, b = octets[0], octets[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    return False


def detect_local_ip(dest_host, dest_port):
    """Find the source IP the OS would use to reach the trunk."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_host, dest_port))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def resolve(host):
    """Return sorted list of IPv4 addresses; raises socket.gaierror on failure."""
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    return sorted({i[4][0] for i in infos})


class SipTester:
    def __init__(self, cfg, verbose=False):
        self.cfg = cfg
        self.verbose = verbose
        self.host = cfg.get("SIP_HOST", "").strip()
        self.port = int(cfg.get("SIP_PORT", "5060"))
        self.from_user = cfg.get("FROM_USER", "").strip() or "test"
        self.caller_id = cfg.get("CALLER_ID", "").strip() or self.from_user
        self.dial_target = cfg.get("DIAL_TARGET", "").strip()
        self.auth_user = cfg.get("AUTH_USER", "").strip()
        self.auth_pass = cfg.get("AUTH_PASS", "").strip()
        self.timeout = float(cfg.get("TIMEOUT", "5"))
        self.hold = float(cfg.get("CALL_HOLD_SECONDS", "3"))
        self.local_port = int(cfg.get("LOCAL_PORT", "5062"))

        if not self.host or self.host == "sip.provider.example.com":
            sys.exit(bad("SIP_HOST is not set in the config file."))

        # resolve to first A record for the socket target
        try:
            addrs = resolve(self.host)
        except socket.gaierror as e:
            sys.exit(bad(f"DNS resolution failed for {self.host}: {e}"))
        self.server_ip = addrs[0]

        li = cfg.get("LOCAL_IP", "AUTO").strip()
        self.local_ip_is_auto = li in ("", "AUTO")
        self.local_ip = detect_local_ip(self.server_ip, self.port) if self.local_ip_is_auto else li

        # Media (RTP) address advertised in SDP. Trunks often separate signalling
        # and media; if you have a distinct media IP, set MEDIA_IP. AUTO = reuse LOCAL_IP.
        mi = cfg.get("MEDIA_IP", "AUTO").strip()
        self.media_ip = self.local_ip if mi in ("", "AUTO") else mi
        self.media_port = int(cfg.get("MEDIA_PORT", "40000"))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("0.0.0.0", self.local_port))
        except OSError as e:
            sys.exit(bad(f"Cannot bind local UDP port {self.local_port}: {e}"))

        self.call_id = uuid.uuid4().hex
        self.from_tag = uuid.uuid4().hex[:10]

    # ── low level ───────────────────────────────────────────────
    def _branch(self):
        return "z9hG4bK" + uuid.uuid4().hex[:16]

    def _log_send(self, msg):
        if self.verbose:
            print(dim("\n>>> SENT >>>"))
            print(dim(msg.rstrip()))

    def _log_recv(self, msg):
        if self.verbose:
            print(dim("\n<<< RECV <<<"))
            print(dim(msg.rstrip()))

    def send(self, msg):
        self._log_send(msg)
        self.sock.sendto(msg.encode(), (self.server_ip, self.port))

    def recv(self, timeout=None):
        timeout = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, None
            r, _, _ = select.select([self.sock], [], [], remaining)
            if not r:
                return None, None
            data, addr = self.sock.recvfrom(65535)
            text = data.decode(errors="replace")
            self._log_recv(text)
            return text, addr

    @staticmethod
    def status(msg):
        if not msg:
            return None
        first = msg.split("\r\n", 1)[0]
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[0].startswith("SIP/2.0"):
            try:
                return int(parts[1])
            except ValueError:
                return None
        return None

    def _print_diag_headers(self, msg):
        """Surface headers that carry the real rejection reason (RFC 3261 Warning, etc.)."""
        if not msg:
            return
        for name in ("Warning", "Reason", "P-Asserted-Identity", "Retry-After", "Error-Info"):
            val = self.header(msg, name)
            if val:
                print(dim(f"     {name}: {val}"))
        if not self.verbose:
            print(dim("     (re-run with -v to see the full raw SIP response)"))

    @staticmethod
    def header(msg, name):
        name_l = name.lower()
        for line in msg.split("\r\n"):
            if line.lower().startswith(name_l + ":"):
                return line.split(":", 1)[1].strip()
        return None

    # ── digest auth (only if trunk challenges AND creds provided) ─
    def _digest(self, msg, method, uri):
        chal = self.header(msg, "WWW-Authenticate") or self.header(msg, "Proxy-Authenticate")
        if not chal:
            return None
        d = {}
        for part in chal.replace("Digest ", "", 1).split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                d[k.strip()] = v.strip().strip('"')
        realm = d.get("realm", "")
        nonce = d.get("nonce", "")
        qop = d.get("qop")
        ha1 = hashlib.md5(f"{self.auth_user}:{realm}:{self.auth_pass}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        if qop:
            nc = "00000001"
            cnonce = uuid.uuid4().hex[:16]
            resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
            auth = (f'Digest username="{self.auth_user}", realm="{realm}", nonce="{nonce}", '
                    f'uri="{uri}", response="{resp}", qop={qop}, nc={nc}, cnonce="{cnonce}"')
        else:
            resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
            auth = (f'Digest username="{self.auth_user}", realm="{realm}", nonce="{nonce}", '
                    f'uri="{uri}", response="{resp}"')
        hdr = "Proxy-Authorization" if self.header(msg, "Proxy-Authenticate") else "Authorization"
        return hdr, auth

    # ── message builders ────────────────────────────────────────
    def _common_headers(self, method, cseq, branch, extra_auth=None):
        contact = f"<sip:{self.from_user}@{self.local_ip}:{self.local_port}>"
        to_uri = f"sip:{self.host}" if method == "OPTIONS" else f"sip:{self.dial_target}@{self.host}"
        lines = [
            f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};branch={branch};rport",
            f"Max-Forwards: 70",
            f"From: <sip:{self.caller_id}@{self.host}>;tag={self.from_tag}",
            f"To: <{to_uri}>",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} {method}",
            f"Contact: {contact}",
            f"User-Agent: sip-test/1.0",
        ]
        if extra_auth:
            lines.append(f"{extra_auth[0]}: {extra_auth[1]}")
        return lines

    def build_options(self, cseq, branch, extra_auth=None):
        req_uri = f"sip:{self.host}"
        lines = [f"OPTIONS {req_uri} SIP/2.0"] + self._common_headers("OPTIONS", cseq, branch, extra_auth)
        lines += ["Accept: application/sdp", "Content-Length: 0", "", ""]
        return "\r\n".join(lines)

    def build_invite(self, cseq, branch, extra_auth=None):
        req_uri = f"sip:{self.dial_target}@{self.host}"
        sdp = "\r\n".join([
            "v=0",
            f"o=- {random.randint(1,2**31)} {random.randint(1,2**31)} IN IP4 {self.media_ip}",
            "s=sip-test",
            f"c=IN IP4 {self.media_ip}",
            "t=0 0",
            f"m=audio {self.media_port} RTP/AVP 0 8 101",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000",
            "a=rtpmap:101 telephone-event/8000",
            "a=sendrecv",
            "",
        ])
        lines = [f"INVITE {req_uri} SIP/2.0"] + self._common_headers("INVITE", cseq, branch, extra_auth)
        lines += [
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp.encode())}",
            "",
            sdp,
        ]
        return "\r\n".join(lines)

    def build_ack(self, cseq, to_hdr, branch, req_uri):
        lines = [
            f"ACK {req_uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{self.caller_id}@{self.host}>;tag={self.from_tag}",
            f"To: {to_hdr}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} ACK",
            "Content-Length: 0",
            "", "",
        ]
        return "\r\n".join(lines)

    def build_bye(self, cseq, to_hdr, branch):
        req_uri = f"sip:{self.dial_target}@{self.host}"
        lines = [
            f"BYE {req_uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{self.caller_id}@{self.host}>;tag={self.from_tag}",
            f"To: {to_hdr}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} BYE",
            "Content-Length: 0",
            "", "",
        ]
        return "\r\n".join(lines)

    # ── high-level flows ────────────────────────────────────────
    def print_target(self):
        print(bold("Trunk target"))
        print(f"  SIP host      : {self.host}  ->  {self.server_ip}:{self.port}/udp")
        print(f"  Source IP     : {self.local_ip}:{self.local_port}  "
              + dim("(this is what the provider must have whitelisted)"))
        print(f"  From/Caller-ID: {self.caller_id}")
        media_note = " (= signalling IP)" if self.media_ip == self.local_ip else ""
        print(f"  Media (SDP)   : {self.media_ip}:{self.media_port}{media_note}")
        self._addressing_assessment(indent="  ")
        print()

    def _addressing_assessment(self, indent=""):
        """Judge whether advertising private IPs is a problem, based on the trunk's IP class."""
        trunk_private = is_private_ip(self.server_ip)
        local_priv = is_private_ip(self.local_ip)
        media_priv = is_private_ip(self.media_ip)
        if not (local_priv or media_priv):
            return  # both public, nothing to flag
        if trunk_private:
            # On-net / private-circuit trunk: private addressing is expected & correct.
            print(dim(f"{indent}ℹ Trunk IP {self.server_ip} is also private → this looks like a private"))
            print(dim(f"{indent}  circuit (MPLS/VPN/on-net). Advertising private IPs is EXPECTED here;"))
            print(dim(f"{indent}  no NAT rewrite needed. (If it's actually over the internet, this is wrong.)"))
            return
        # Trunk is public but we're advertising private IPs → real NAT problem.
        if local_priv:
            print(warn(f"{indent}⚠ NAT: signalling advertises PRIVATE {self.local_ip} but trunk {self.server_ip} is PUBLIC."))
            print(warn(f"{indent}  Set LOCAL_IP=<public IP> in config.env."))
        if media_priv:
            print(warn(f"{indent}⚠ NAT: SDP media advertises PRIVATE {self.media_ip} → audio will fail."))
            print(warn(f"{indent}  Set MEDIA_IP=<public media IP> in config.env."))

    def do_options(self):
        self.print_target()
        cseq = 1
        branch = self._branch()
        self.send(self.build_options(cseq, branch))
        msg, _ = self.recv()
        if msg is None:
            print(bad("✗ No response (timeout)."))
            print("  Likely causes: source IP not whitelisted (silent drop), UDP 5060")
            print("  blocked by a firewall in the path, or wrong SIP_HOST/port.")
            return 2
        st = self.status(msg)
        # handle auth challenge
        if st in (401, 407) and self.auth_user:
            auth = self._digest(msg, "OPTIONS", f"sip:{self.host}")
            if auth:
                cseq += 1
                branch = self._branch()
                self.send(self.build_options(cseq, branch, extra_auth=auth))
                msg, _ = self.recv()
                st = self.status(msg)
        return self._interpret(st, msg)

    def _interpret(self, st, msg):
        reason = msg.split("\r\n", 1)[0].split(" ", 2)[-1] if msg else ""
        server = self.header(msg, "Server") or self.header(msg, "User-Agent") or ""
        if st == 200:
            print(ok(f"✓ 200 OK — trunk reachable and your IP is accepted."))
            if server:
                print(dim(f"  Server: {server}"))
            return 0
        if st in (401, 407):
            print(warn(f"⚠ {st} {reason} — trunk is reachable but wants credentials."))
            print("  This trunk is NOT pure IP-auth for this request, or needs")
            print("  AUTH_USER/AUTH_PASS in the config. IP-whitelist alone is not enough here.")
            return 1
        if st == 403:
            print(bad(f"✗ 403 {reason} — reachable but rejected (IP likely NOT whitelisted)."))
            print(f"  Confirm the provider whitelisted {self.local_ip} exactly.")
            return 1
        if st == 404:
            print(warn(f"⚠ 404 {reason} — trunk answered; user/URI unknown (whitelist likely fine)."))
            return 0
        if st and 200 <= st < 300:
            print(ok(f"✓ {st} {reason} — trunk reachable and accepted."))
            return 0
        print(warn(f"⚠ {st} {reason} — trunk answered (any reply proves reachability + routing)."))
        if server:
            print(dim(f"  Server: {server}"))
        return 0

    def do_diagnose(self):
        print(bold("── DNS ──"))
        try:
            addrs = resolve(self.host)
            print(ok(f"✓ {self.host} resolves to: {', '.join(addrs)}"))
        except socket.gaierror as e:
            print(bad(f"✗ DNS failed: {e}"))
            return 2
        print()
        print(bold("── Routing / source IP ──"))
        print(f"  OS will send from : {ok(self.local_ip)}")
        print(f"  Trunk IP          : {self.server_ip} "
              + dim("(private → on-net/private circuit)" if is_private_ip(self.server_ip)
                    else "(public → trunk is over the internet)"))
        self._addressing_assessment(indent="  ")
        if not is_private_ip(self.local_ip) and not is_private_ip(self.media_ip):
            print(dim(f"  → The provider whitelist entry must equal the send-from IP exactly."))
        print()
        print(bold("── UDP reachability (OPTIONS probe) ──"))
        return self.do_options()

    def do_call(self):
        if not self.dial_target:
            sys.exit(bad("DIAL_TARGET is empty in config — set the number to dial."))
        self.print_target()
        print(bold(f"Placing test call to {self.dial_target} ...\n"))
        cseq = 1
        branch = self._branch()
        self.send(self.build_invite(cseq, branch))
        req_uri = f"sip:{self.dial_target}@{self.host}"
        answered_to = None
        got_provisional = False
        deadline = time.monotonic() + 30  # overall call-setup window
        while time.monotonic() < deadline:
            msg, _ = self.recv(timeout=deadline - time.monotonic())
            if msg is None:
                if not got_provisional:
                    print(bad("✗ No response to INVITE (timeout)."))
                    print("  IP not whitelisted (silent drop), firewall, or wrong host/port.")
                    return 2
                print(warn("⚠ No further response after provisional; giving up."))
                return 1
            st = self.status(msg)
            reason = msg.split("\r\n", 1)[0].split(" ", 2)[-1]
            # auth challenge on INVITE
            if st in (401, 407):
                to_hdr = self.header(msg, "To")
                self.send(self.build_ack(cseq, to_hdr, branch, req_uri))
                if self.auth_user:
                    auth = self._digest(msg, "INVITE", req_uri)
                    if auth:
                        cseq += 1
                        branch = self._branch()
                        print(dim(f"  {st} {reason} → answering digest challenge"))
                        self.send(self.build_invite(cseq, branch, extra_auth=auth))
                        continue
                print(warn(f"⚠ {st} {reason} — trunk wants credentials (not pure IP-auth for INVITE)."))
                return 1
            if st == 100:
                print(f"  {dim('100 Trying')}"); got_provisional = True; continue
            if st == 180:
                print(f"  {ok('180 Ringing')} — remote is ringing"); got_provisional = True; continue
            if st == 183:
                print(f"  {ok('183 Session Progress')} — early media"); got_provisional = True; continue
            if st and 200 <= st < 300:
                print(ok(f"  {st} {reason} — CALL ANSWERED"))
                answered_to = self.header(msg, "To")
                ack_branch = self._branch()
                self.send(self.build_ack(cseq, answered_to, ack_branch, req_uri))
                print(dim(f"  ACK sent. Holding {self.hold:g}s (no RTP audio sent)..."))
                if self.hold > 0:
                    time.sleep(self.hold)
                cseq += 1
                self.send(self.build_bye(cseq, answered_to, self._branch()))
                bye_resp, _ = self.recv(timeout=self.timeout)
                if self.status(bye_resp) == 200:
                    print(ok("  200 OK to BYE — call torn down cleanly. ✓ Outbound signalling works."))
                else:
                    print(warn("  BYE sent (no/other response) — call setup itself succeeded."))
                return 0
            if st and 300 <= st < 400:
                print(warn(f"  {st} {reason} — redirect")); return 1
            if st and st >= 400:
                to_hdr = self.header(msg, "To")
                self.send(self.build_ack(cseq, to_hdr, branch, req_uri))
                if st == 403:
                    print(bad(f"  ✗ 403 {reason} — rejected. IP likely not whitelisted, or"))
                    print("     the trunk disallows this destination/caller-ID.")
                elif st == 404:
                    print(bad(f"  ✗ 404 {reason} — number not found / bad format for this trunk."))
                elif st == 407 or st == 401:
                    print(warn(f"  ⚠ {st} {reason} — needs credentials."))
                elif st == 500:
                    print(bad(f"  ✗ 500 {reason} — signalling reached the trunk; its switch errored on THIS call."))
                    print("     IP whitelist is fine. Most common causes, in order:")
                    print("       1. Caller-ID (From) is not a number provisioned on your account")
                    print("       2. DIAL_TARGET is in a format the trunk won't route (try +E.164 / national / 00-prefix)")
                    print("       3. Behind NAT: SDP/Contact advertise a private IP — set LOCAL_IP to the public IP")
                    print("       4. Missing header the trunk requires (e.g. P-Asserted-Identity)")
                else:
                    print(bad(f"  ✗ {st} {reason} — call rejected (but signalling reached the trunk)."))
                self._print_diag_headers(msg)
                return 1
        print(warn("⚠ Call-setup window elapsed."))
        return 1

    def do_listen(self):
        # rebind to the standard SIP port for inbound if possible
        print(bold("Inbound DID test — waiting for an INVITE from the trunk"))
        print(dim(f"  Listening on {self.local_ip}:{self.local_port}/udp"))
        print(dim("  NOTE: the provider must be configured to deliver your DID to"))
        print(dim(f"        {self.local_ip}:{self.local_port}. Ctrl-C to stop.\n"))
        print(f"  Now place a call to your DID number...")
        while True:
            msg, addr = self.recv(timeout=3600)
            if msg is None:
                continue
            first = msg.split("\r\n", 1)[0]
            if first.startswith("OPTIONS"):
                # keepalive from provider — answer 200 so they keep us "up"
                self._reply_200(msg, addr, "OPTIONS")
                print(dim(f"  ← OPTIONS keepalive from {addr[0]} (answered 200)"))
                continue
            if first.startswith("INVITE"):
                print(ok(f"  ✓ Inbound INVITE received from {addr[0]}:{addr[1]}"))
                fu = self.header(msg, "From")
                to = self.header(msg, "To")
                print(f"    From: {fu}")
                print(f"    To  : {to}")
                # 180 then 200 then wait for ACK, hold, BYE
                self._reply(msg, addr, 100, "Trying")
                self._reply(msg, addr, 180, "Ringing")
                self._reply(msg, addr, 200, "OK", with_sdp=True)
                print(ok("    Answered (200 OK). ✓ Trunk delivers inbound calls to this host."))
                # wait briefly for ACK
                self.recv(timeout=3)
                return 0

    def _via_from(self, msg):
        return self.header(msg, "Via")

    def _reply(self, req, addr, code, reason, with_sdp=False):
        via = self.header(req, "Via")
        frm = self.header(req, "From")
        to = self.header(req, "To")
        callid = self.header(req, "Call-ID")
        cseq = self.header(req, "CSeq")
        if to and ";tag=" not in to:
            to = f"{to};tag={uuid.uuid4().hex[:8]}"
        body = ""
        extra = []
        if with_sdp:
            body = "\r\n".join([
                "v=0", f"o=- 1 1 IN IP4 {self.media_ip}", "s=sip-test",
                f"c=IN IP4 {self.media_ip}", "t=0 0",
                f"m=audio {self.media_port} RTP/AVP 0", "a=rtpmap:0 PCMU/8000", "a=sendrecv", "",
            ])
            extra = ["Content-Type: application/sdp"]
        lines = [
            f"SIP/2.0 {code} {reason}",
            f"Via: {via}",
            f"From: {frm}",
            f"To: {to}",
            f"Call-ID: {callid}",
            f"CSeq: {cseq}",
            f"Contact: <sip:{self.from_user}@{self.local_ip}:{self.local_port}>",
        ] + extra + [f"Content-Length: {len(body.encode())}", "", body]
        self.sock.sendto("\r\n".join(lines).encode(), addr)

    def _reply_200(self, req, addr, method):
        self._reply(req, addr, 200, "OK")


def main():
    ap = argparse.ArgumentParser(description="Pure-Python SIP trunk tester (IP-whitelist)")
    ap.add_argument("command", choices=["diagnose", "options", "call", "listen"])
    ap.add_argument("--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.env"))
    ap.add_argument("--verbose", "-v", action="store_true", help="print raw SIP messages")
    args = ap.parse_args()

    cfg = load_config(args.config)
    t = SipTester(cfg, verbose=args.verbose)
    try:
        if args.command == "options":
            rc = t.do_options()
        elif args.command == "diagnose":
            rc = t.do_diagnose()
        elif args.command == "call":
            rc = t.do_call()
        elif args.command == "listen":
            rc = t.do_listen()
        sys.exit(rc)
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
