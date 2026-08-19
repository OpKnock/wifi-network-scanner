from __future__ import annotations

import struct
from dataclasses import dataclass, field

RSN_CIPHERS = {0x000FAC04: "TKIP", 0x000FAC02: "WEP-40", 0x000FAC05: "CCMP", 0x000FAC01: "WEP-104", 0x000FAC06: "GCMP"}
AKM_SUITES = {0x000FAC02: "PSK", 0x000FAC01: "802.1X", 0x000FAC08: "FT-PSK", 0x000FAC03: "FT-802.1X", 0x000FAC06: "SAE"}

CHANNEL_FREQ = {1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432, 6: 2437, 7: 2442, 8: 2447, 9: 2452,
                10: 2457, 11: 2462, 12: 2467, 13: 2472, 14: 2484,
                36: 5180, 40: 5200, 44: 5220, 48: 5240, 52: 5260, 56: 5280, 60: 5300, 64: 5320,
                100: 5500, 104: 5520, 108: 5540, 112: 5560, 116: 5580, 120: 5600, 124: 5620,
                128: 5640, 132: 5660, 136: 5680, 140: 5700, 149: 5745, 153: 5765, 157: 5785, 161: 5805, 165: 5825}


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: int
    rssi: int
    security: list[str] = field(default_factory=list)
    frequency_mhz: int | None = None

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "frequency_mhz": self.frequency_mhz or frequency_from_channel(self.channel),
            "rssi": self.rssi,
            "security": list(self.security),
        }


def channel_from_frequency(freq: int) -> int | None:
    for ch, f in CHANNEL_FREQ.items():
        if f == freq:
            return ch
    return None


def frequency_from_channel(channel: int) -> int | None:
    return CHANNEL_FREQ.get(channel)


def parse_radiotap(raw: bytes):
    """Return (offset_after_radiotap, rssi_or_None) for a common radiotap header."""
    if len(raw) < 8:
        return 0, None
    version, _, length = struct.unpack_from("<BBH", raw, 0)
    if version != 0 or length < 8 or length > len(raw):
        return 0, None
    rssi = None
    if len(raw) >= length + 1:
        rssi = raw[length]  # first byte after radiotap is often the 802.11 frame control
    return length, rssi


def parse_beacon(frame: bytes, rssi: int = -60) -> AccessPoint | None:
    """Parse an 802.11 beacon management frame (no radiotap)."""
    if len(frame) < 34:
        return None
    fc = struct.unpack_from("<H", frame, 0)[0]
    frame_type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if frame_type != 0 or subtype != 8:
        return None
    bssid = ":".join(f"{b:02x}" for b in frame[14:20])
    fixed = frame[22:34]
    if len(fixed) < 12:
        return None
    capability = struct.unpack_from("<H", fixed, 0)[0]
    ssid = ""
    channel: int | None = None
    security: set[str] = set()
    if capability & 0x0001:
        security.add("ad-hoc")
    i = 34
    while i + 2 <= len(frame):
        eid = frame[i]
        elen = frame[i + 1]
        body = frame[i + 2 : i + 2 + elen]
        if i + 2 + elen > len(frame):
            break
        if eid == 0 and elen >= 1:
            ssid = body.decode("utf-8", errors="replace")
        elif eid == 3 and elen == 1:
            channel = body[0]
        elif eid == 48 and elen >= 6:
            security.update(parse_rsn(body))
        elif eid == 4 and elen >= 6:
            rates = elen
        i += 2 + elen
    if channel is None:
        return None
    if not security:
        security.add("open")
    if capability & 0x0010:
        security.add("privacy")
    return AccessPoint(
        ssid=ssid,
        bssid=bssid,
        channel=channel,
        rssi=rssi,
        security=sorted(security),
        frequency_mhz=frequency_from_channel(channel),
    )


def parse_rsn(body: bytes) -> set[str]:
    flags: set[str] = set()
    if len(body) < 8:
        return flags
    version = struct.unpack_from("<H", body, 0)[0]
    if version != 1:
        return flags
    group = struct.unpack_from(">I", body, 2)[0]
    if group in RSN_CIPHERS:
        flags.add(RSN_CIPHERS[group])
    if len(body) >= 8:
        off = 8  # pairwise count + first pairwise cipher
        count = struct.unpack_from("<H", body, 6)[0]
        for _ in range(min(count, 4)):
            if off + 4 > len(body):
                break
            suite = struct.unpack_from(">I", body, off)[0]
            if suite in RSN_CIPHERS:
                flags.add(RSN_CIPHERS[suite])
            off += 4
        if off + 2 <= len(body):
            akm_count = struct.unpack_from("<H", body, off)[0]
            off += 2
            for _ in range(min(akm_count, 4)):
                if off + 4 > len(body):
                    break
                suite = struct.unpack_from(">I", body, off)[0]
                if suite in AKM_SUITES:
                    flags.add(AKM_SUITES[suite])
                off += 4
    return flags


def classify(ap: AccessPoint) -> str:
    sec = " ".join(ap.security)
    if "SAE" in sec:
        return "wpa3"
    if "802.1X" in sec and ("CCMP" in sec or "GCMP" in sec):
        return "wpa2-enterprise"
    if "PSK" in sec and ("CCMP" in sec or "GCMP" in sec):
        return "wpa2-personal"
    if "TKIP" in sec:
        return "wpa1"
    if "WEP" in sec:
        return "wep"
    return "open"
