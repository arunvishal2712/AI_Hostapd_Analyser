"""Line prefix / timestamp parsing and message templates. Every function here is O(length of the line)."""
from __future__ import annotations

import calendar
import re

MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov",
                                      "dec"), 1)}
TS_RX = re.compile(
    r"(?:\w{3} (?P<mon>\w{3}) +(?P<day>\d{1,2}) (?P<hms>\d\d:\d\d:\d\d) (?P<year>\d{4}) "        # logread
    r"|(?P<mon2>[A-Z][a-z]{2}) +(?P<day2>\d{1,2}) (?P<hms2>\d\d:\d\d:\d\d) "                       # syslog
    r"|(?P<iso>\d{4})-(?P<im>\d\d)-(?P<id>\d\d)[T ](?P<hms3>\d\d:\d\d:\d\d)(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)? "
    r"|(?P<ep>\d{9,10})\.\d+: )")
MAC_RX = re.compile(r"(?<![0-9a-fA-F:])[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}(?![0-9a-fA-F:])")
NUM_RX = re.compile(r"0x[0-9a-fA-F]+|(?<![\w.])-?\d+(?:\.\d+)?(?![\w])|\b\d+\b")
ANSI_RX = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[=>]")
LONG = 4000          # longer messages are cut (their template then matches every search, see StoreIndex)
_DAY_CACHE: dict = {}


def day_epoch(year: int, month: int, day: int) -> float:
    k = (year, month, day)
    v = _DAY_CACHE.get(k)
    if v is None:
        try:
            v = float(calendar.timegm((year, month, day, 0, 0, 0)))
        except (ValueError, OverflowError):
            v = 0.0
        _DAY_CACHE[k] = v
    return v


def parse_prefix(s: str, year: int = 2026):
    """-> (epoch | None, 'HH:MM:SS' | None, index where the message starts)."""
    m = TS_RX.match(s)
    if not m:
        return None, None, 0
    g = m.group
    if g("hms"):
        hms, mon, day, yr = g("hms"), MONTHS.get(g("mon").lower()), int(g("day")), int(g("year"))
    elif g("hms2"):
        hms, mon, day, yr = g("hms2"), MONTHS.get(g("mon2").lower()), int(g("day2")), year
    elif g("hms3"):
        hms, mon, day, yr = g("hms3"), int(g("im")), int(g("id")), int(g("iso"))
    else:
        ep = float(g("ep"))
        sec = int(ep) % 86400
        return ep, f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}", m.end()
    if not mon:
        return None, None, 0
    ep = day_epoch(yr, mon, day) + int(hms[:2]) * 3600 + int(hms[3:5]) * 60 + int(hms[6:8])
    return ep, hms, m.end()


def body_of(s: str, start: int) -> str:
    """Message after the syslog facility / program prefix ('daemon.debug hostapd: ')."""
    i = s.find("hostapd: ", start, start + 80)
    if i >= 0:
        return s[i + 9:]
    return s[start:]


def template(body: str) -> str:
    """Message shape: MAC -> <M>, numbers / hex -> #, hexdump payload dropped, very long lines cut."""
    h = body.find("hexdump")
    if h >= 0:
        body = body[:h + 7]
    elif len(body) > LONG:
        body = body[:LONG] + "~"
    if ":" in body:
        body = MAC_RX.sub("<M>", body)
    return NUM_RX.sub("#", body)


def mask_needle(needle: str) -> str:
    """The same masking for a search needle (lower-case), so a needle can be matched against templates."""
    return NUM_RX.sub("#", MAC_RX.sub("<m>", needle))
