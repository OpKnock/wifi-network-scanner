import struct

from wifiscan import (
    AccessPoint,
    channel_from_frequency,
    classify,
    frequency_from_channel,
    parse_beacon,
    parse_rsn,
)


def build_beacon(ssid: bytes, bssid: bytes, channel: int, rsn: bytes | None = None) -> bytes:
    fc = 0x0080  # management frame, beacon subtype
    body = bytearray()
    body += b"\x00\x00\x00\x00\x00\x00\x00\x00"  # timestamp
    body += struct.pack("<H", 0x0100)  # beacon interval
    body += struct.pack("<H", 0x0001)  # capability
    body += b"\x00" + bytes([len(ssid)]) + ssid
    body += b"\x03\x01" + bytes([channel])
    body += b"\x04\x04" + b"\x02\x04\x0b\x16"
    if rsn:
        body += b"\x30" + bytes([len(rsn)]) + rsn
    frame = bytearray()
    frame += struct.pack("<H", fc)
    frame += b"\xff\xff\xff\xff\xff\xff"
    frame += bssid
    frame += bssid
    frame += b"\x00" * 2  # seq
    frame += body
    return bytes(frame)


RSN_PSK_CCMP = bytes.fromhex("0100000fac050100000fac050100000fac02")


def test_parse_open_beacon():
    bssid = bytes.fromhex("001122334455")
    frame = build_beacon(b"HomeNet", bssid, 6)
    ap = parse_beacon(frame, rssi=-55)
    assert ap is not None
    assert ap.ssid == "HomeNet"
    assert ap.bssid == "00:11:22:33:44:55"
    assert ap.channel == 6
    assert ap.rssi == -55
    assert classify(ap) == "open"


def test_parse_wpa2_beacon():
    bssid = bytes.fromhex("aabbccddeeff")
    frame = build_beacon(b"Secure", bssid, 11, rsn=RSN_PSK_CCMP)
    ap = parse_beacon(frame)
    assert ap is not None
    assert "CCMP" in ap.security
    assert "PSK" in ap.security
    assert classify(ap) == "wpa2-personal"


def test_parse_rsn_psk_ccmp():
    flags = parse_rsn(RSN_PSK_CCMP)
    assert "CCMP" in flags
    assert "PSK" in flags


def test_parse_non_beacon_returns_none():
    bssid = bytes.fromhex("001122334455")
    frame = build_beacon(b"X", bssid, 1)
    frame = bytearray(frame)
    frame[0] = 0x40  # data frame type
    assert parse_beacon(bytes(frame)) is None


def test_parse_short_frame_returns_none():
    assert parse_beacon(b"\x00" * 20) is None


def test_frequency_mapping():
    assert frequency_from_channel(6) == 2437
    assert channel_from_frequency(5180) == 36
    assert frequency_from_channel(99) is None


def test_classification_levels():
    def ap_with(*sec):
        return AccessPoint(ssid="x", bssid="00:00:00:00:00:00", channel=1, rssi=-60, security=list(sec))

    assert classify(ap_with("CCMP", "PSK")) == "wpa2-personal"
    assert classify(ap_with("CCMP", "SAE")) == "wpa3"
    assert classify(ap_with("TKIP", "PSK")) == "wpa1"
    assert classify(ap_with("WEP-40")) == "wep"
    assert classify(ap_with("open")) == "open"
    assert classify(ap_with("CCMP", "802.1X")) == "wpa2-enterprise"


def test_access_point_dict():
    ap = AccessPoint(ssid="Net", bssid="00:11:22:33:44:55", channel=6, rssi=-60, security=["open"])
    d = ap.to_dict()
    assert d["ssid"] == "Net"
    assert d["frequency_mhz"] == 2437
