"""
rtp_audio.py — minimal RTP audio for sip_test.py (stdlib only, no audioop).

Streams G.711 (PCMU/PCMA) at 8 kHz / 20 ms packets to the far end named in the
SDP answer, and records whatever RTP comes back to a WAV file. Enough to prove a
two-way audio path — not a media engine.
"""
import math
import random
import select
import socket
import struct
import threading
import time
import wave

PTIME_MS = 20
SAMPLES_PER_PKT = 160          # 8 kHz * 20 ms
RATE = 8000

# ── G.711 codecs (pure Python; audioop is gone in 3.13) ────────────────────
_EXP_LUT = [0, 0, 1, 1, 2, 2, 2, 2] + [3] * 8 + [4] * 16 + [5] * 32 + [6] * 64 + [7] * 128


def _ulaw_enc_sample(s):
    bias, clip = 0x84, 32635
    sign = (s >> 8) & 0x80
    if sign:
        s = -s
    if s > clip:
        s = clip
    s += bias
    exp = _EXP_LUT[(s >> 7) & 0xFF]
    mant = (s >> (exp + 3)) & 0x0F
    return ~(sign | (exp << 4) | mant) & 0xFF


def _ulaw_dec_sample(u):
    u = ~u & 0xFF
    sign, exp, mant = u & 0x80, (u >> 4) & 0x07, u & 0x0F
    s = (((mant << 3) + 0x84) << exp) - 0x84
    return -s if sign else s


_ALAW_SEG_END = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)


def _alaw_enc_sample(s):
    s >>= 3
    if s >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        s = -s - 1
    seg = next((i for i, end in enumerate(_ALAW_SEG_END) if s <= end), 8)
    if seg >= 8:
        return 0x7F ^ mask
    aval = seg << 4
    aval |= ((s >> 1) if seg < 2 else (s >> seg)) & 0x0F
    return aval ^ mask


def _alaw_dec_sample(a):
    a ^= 0x55
    t = (a & 0x0F) << 4
    seg = (a & 0x70) >> 4
    if seg == 0:
        t += 8
    elif seg == 1:
        t += 0x108
    else:
        t = (t + 0x108) << (seg - 1)
    return t if a & 0x80 else -t


ULAW_ENC = bytes(_ulaw_enc_sample(i) for i in range(-32768, 32768))   # index = sample + 32768
ULAW_DEC = [_ulaw_dec_sample(i) for i in range(256)]
ALAW_ENC = bytes(_alaw_enc_sample(i) for i in range(-32768, 32768))
ALAW_DEC = [_alaw_dec_sample(i) for i in range(256)]


def encode(pcm, pt):
    """pcm: list/array of int16 samples -> G.711 bytes for payload type 0 or 8."""
    table = ULAW_ENC if pt == 0 else ALAW_ENC
    return bytes(table[s + 32768] for s in pcm)


def decode(payload, pt):
    table = ULAW_DEC if pt == 0 else ALAW_DEC
    return [table[b] for b in payload]


# ── audio sources ───────────────────────────────────────────────────────────
def tone_pcm(hz=440.0, seconds=2.0, gap=0.5, amp=12000):
    """A repeating beep: `seconds` of tone then `gap` of silence — easy to recognise."""
    n_on, n_off = int(RATE * seconds), int(RATE * gap)
    on = [int(amp * math.sin(2 * math.pi * hz * i / RATE)) for i in range(n_on)]
    return on + [0] * n_off


def load_wav_pcm(path):
    """Read a WAV and return 8 kHz mono int16 samples (downmix / resample crudely)."""
    with wave.open(path, "rb") as w:
        ch, width, rate, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
        raw = w.readframes(n)
    if width == 1:
        samples = [(b - 128) << 8 for b in raw]
    elif width == 2:
        samples = list(struct.unpack("<%dh" % (len(raw) // 2), raw))
    else:
        raise ValueError(f"{path}: unsupported sample width {width * 8}-bit (use 8/16-bit PCM)")
    if ch > 1:
        samples = samples[::ch]
    if rate != RATE:
        step = rate / RATE
        samples = [samples[int(i * step)] for i in range(int(len(samples) / step))]
    return samples


def parse_sdp_media(sdp):
    """Return (ip, port, payload_type) from an SDP answer, preferring PCMU then PCMA."""
    ip, port, pts = None, None, []
    for line in sdp.replace("\r\n", "\n").split("\n"):
        if line.startswith("c=IN IP4 "):
            ip = line.split()[2]
        elif line.startswith("m=audio "):
            parts = line.split()
            port = int(parts[1])
            pts = [int(p) for p in parts[3:] if p.isdigit()]
    if not ip or port is None:
        return None
    pt = 0 if 0 in pts else (8 if 8 in pts else None)
    return ip, port, pt


class RtpSession:
    """Bind the advertised media port, receive from the start, send once armed."""

    def __init__(self, bind_ip, bind_port, source_pcm, record_path=None, fill_silence=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((bind_ip, bind_port))
            self.bound = (bind_ip, bind_port)
        except OSError:
            self.sock.bind(("0.0.0.0", bind_port))
            self.bound = ("0.0.0.0", bind_port)
        self.source_pcm = source_pcm
        self.record_path = record_path
        self.remote = None            # (ip, port)
        self.pt = 0
        self.ssrc = random.getrandbits(32)
        self.seq = random.getrandbits(16)
        self.ts = random.getrandbits(32)
        self.sent = 0
        self.recv_pkts = 0
        self.rtcp_pkts = 0
        self.recv_bytes = 0
        self.recv_from = {}           # addr -> count
        self.recv_pts = {}            # payload type -> count
        self.seq_gaps = 0
        self._last_seq = None
        self._rec_pcm = []
        self.forward_to = None        # another RtpSession: relay our incoming audio out of it
        self.forwarded = 0
        # Relay mode: keep a steady stream toward the remote even when nothing is being
        # forwarded. Relays (rtpengine) start unlatched and only learn where to send from the
        # first packet they get from us, and carrier SBCs drop calls on RTP inactivity.
        self.fill_silence = fill_silence
        self.filled = 0
        self._last_emit = 0.0
        self._emit_lock = threading.Lock()
        self._stop = threading.Event()
        self._send = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def set_remote(self, ip, port, pt):
        self.remote = (ip, port)
        self.pt = 0 if pt is None else pt

    def start_sending(self):
        if self.remote:
            self._send.set()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        try:
            self.sock.close()
        except OSError:
            pass
        if self.record_path and self._rec_pcm:
            with wave.open(self.record_path, "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(RATE)
                w.writeframes(struct.pack("<%dh" % len(self._rec_pcm), *self._rec_pcm))
            return len(self._rec_pcm) / RATE
        return 0.0

    def _run(self):
        payload = None
        offset = 0
        next_tx = None
        while not self._stop.is_set():
            now = time.monotonic()
            if self._send.is_set():
                if payload is None:
                    payload = encode(self.source_pcm, self.pt)
                    next_tx = now
                if now >= next_tx:
                    chunk = payload[offset:offset + SAMPLES_PER_PKT]
                    if len(chunk) < SAMPLES_PER_PKT:      # loop the source
                        offset = 0
                        chunk = payload[:SAMPLES_PER_PKT]
                    offset += SAMPLES_PER_PKT
                    self.emit(chunk)
                    next_tx += PTIME_MS / 1000.0
                wait = max(0.0, min(next_tx - time.monotonic(), 0.02))
            elif self.fill_silence and self.remote:
                if now - self._last_emit >= PTIME_MS / 1000.0:
                    self.emit(bytes([0xFF if self.pt == 0 else 0xD5]) * SAMPLES_PER_PKT)
                    self.filled += 1
                wait = 0.005
            else:
                wait = 0.02
            r, _, _ = select.select([self.sock], [], [], wait)
            if r:
                try:
                    data, addr = self.sock.recvfrom(2048)
                except OSError:
                    continue
                self._on_packet(data, addr)

    def _on_packet(self, data, addr):
        if len(data) < 12 or (data[0] >> 6) != 2:
            return
        pt = data[1] & 0x7F
        if 72 <= pt <= 76:                       # RTCP (SR/RR/SDES/BYE/APP) muxed on the RTP port
            self.rtcp_pkts += 1
            return
        seq = struct.unpack("!H", data[2:4])[0]
        cc = data[0] & 0x0F
        hdr_len = 12 + 4 * cc
        if data[0] & 0x10:                       # extension header
            if len(data) < hdr_len + 4:
                return
            ext_len = struct.unpack("!H", data[hdr_len + 2:hdr_len + 4])[0]
            hdr_len += 4 + 4 * ext_len
        payload = data[hdr_len:]
        if data[0] & 0x20 and payload:           # padding
            payload = payload[:-payload[-1]]
        self.recv_pkts += 1
        self.recv_bytes += len(data)
        self.recv_from[addr] = self.recv_from.get(addr, 0) + 1
        self.recv_pts[pt] = self.recv_pts.get(pt, 0) + 1
        if self._last_seq is not None and seq != ((self._last_seq + 1) & 0xFFFF):
            self.seq_gaps += 1
        self._last_seq = seq
        if pt not in (0, 8):
            return
        if self.record_path:
            self._rec_pcm.extend(decode(payload, pt))
        peer = self.forward_to
        if peer is not None and peer.remote:
            peer.emit(payload if pt == peer.pt else encode(decode(payload, pt), peer.pt))
            self.forwarded += 1

    def emit(self, payload):
        """Send one 20 ms G.711 frame to our remote as our own stream (relay use)."""
        with self._emit_lock:
            marker = 0x80 if self.sent == 0 else 0
            hdr = struct.pack("!BBHII", 0x80, marker | self.pt, self.seq, self.ts, self.ssrc)
            try:
                self.sock.sendto(hdr + payload, self.remote)
            except OSError:
                return
            self.sent += 1
            self.seq = (self.seq + 1) & 0xFFFF
            self.ts = (self.ts + len(payload)) & 0xFFFFFFFF
            self._last_emit = time.monotonic()
