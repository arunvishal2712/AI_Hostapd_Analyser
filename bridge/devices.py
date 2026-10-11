"""
Device identification from the management frames hostapd -dd logs as hexdumps.

Every client puts vendor-specific information elements (IE 221) into its probe / (re)association requests.
Their OUI names the chipset or brand (Apple, Broadcom, Qualcomm, MediaTek, Huawei ...), the WPS element can
carry the manufacturer and model name (e.g. D-Link "DCS-8000LH"), and a globally administered MAC address
gives the manufacturer through its OUI prefix. The result is a best guess with the evidence that led to it
(element + log line), never a certainty: the exact phone model is not in hostapd logs.
"""
from __future__ import annotations

import re

HEX_RX = re.compile(r"MLME event frame - hexdump\(len=(\d+)\):((?: [0-9a-f]{2})+)", re.I)
# frame control byte 0 (subtype << 4 | type << 2): assoc req 0x00, reassoc req 0x20, probe req 0x40
FIXED_LEN = {0x00: 4, 0x20: 10, 0x40: 0}

VENDOR_IE = {  # IE 221 OUI -> label (chipset / brand)
    "00:17:F2": "Apple", "00:10:18": "Broadcom", "00:90:4C": "Broadcom", "8C:FD:F0": "Qualcomm",
    "00:03:7F": "Qualcomm Atheros", "00:13:74": "Qualcomm Atheros", "00:0C:E7": "MediaTek", "00:0C:43": "MediaTek/Ralink",
    "AC:85:3D": "Huawei", "00:E0:4C": "Realtek", "00:A0:C6": "Qualcomm", "00:26:86": "Quantenna",
    "00:1A:11": "Google", "F0:9F:C2": "Ubiquiti", "00:40:96": "Cisco", "00:0B:86": "Aruba",
    "00:15:6D": "Ubiquiti", "00:50:43": "Marvell", "8C:59:C3": "Samsung", "00:00:F0": "Samsung",
    "00:12:FB": "Samsung", "00:16:32": "Samsung", "D0:22:BE": "Samsung", "48:3B:38": "Apple",
}
GENERIC_OUI = {"00:50:F2", "50:6F:9A", "00:0F:AC"}      # Microsoft WMM/WPS, Wi-Fi Alliance (MBO/OCE/P2P), IEEE
MAC_OUI = {  # small built-in table for globally administered client MACs (extend in cag/oui.txt)
    "B0:C5:54": "D-Link", "80:48:2C": "Wyze Labs", "F0:18:98": "Apple", "3C:22:FB": "Apple", "A4:83:E7": "Apple",
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "00:1A:11": "Google",
    "AC:BC:32": "Apple", "8C:85:90": "Apple", "60:F6:77": "Intel",
    "70:CF:49": "Intel", "AC:67:5D": "Intel", "34:13:E8": "Intel", "F8:E4:E3": "Intel", "00:E0:4C": "Realtek",
    "50:EB:F6": "ASUSTek", "2C:F0:5D": "Micro-Star", "04:D9:F5": "ASUSTek", "D8:3A:DD": "Raspberry Pi",
}


def _ies(data: bytes):
    i = 0
    while i + 2 <= len(data):
        eid, ln = data[i], data[i + 1]
        if i + 2 + ln > len(data):
            break
        yield eid, data[i + 2:i + 2 + ln]
        i += 2 + ln


def _wps_attrs(body: bytes) -> dict:
    out, i = {}, 0
    while i + 4 <= len(body):
        t, ln = int.from_bytes(body[i:i + 2], "big"), int.from_bytes(body[i + 2:i + 4], "big")
        val = body[i + 4:i + 4 + ln]
        if t == 0x1021:
            out["manufacturer"] = val.decode("utf-8", "ignore").strip()
        elif t == 0x1023:
            out["model"] = val.decode("utf-8", "ignore").strip()
        elif t == 0x1011:
            out["device_name"] = val.decode("utf-8", "ignore").strip()
        i += 4 + ln
    return out


MAX_BLOCKS_PER_CLIENT = 64


def _hexdump_lines(index, client_macs: dict) -> list[int]:
    """0-based indexes of frame hexdump lines. On the v4 engine store only the blocks where each client appears are
    read (its first MAX_BLOCKS_PER_CLIENT blocks - the identifying elements are in its first requests), so a 10 GB
    log is not scanned for hexdumps."""
    if not hasattr(index, "store"):
        return index.raw_candidates(["MLME event frame - hexdump"])
    st = index.store
    blocks = set()
    for m, links in client_macs.items():
        for x in [m] + list(links or []):
            bl = st.blocks_for_mac(x)[:MAX_BLOCKS_PER_CLIENT]
            blocks.update(bl)
            blocks.update(b + 1 for b in bl if b + 1 < len(st._bfirst))
    tids = [t for (t,) in st.q("SELECT id FROM templates WHERE instr(text, 'MLME event frame - hexdump') > 0")]
    return [n - 1 for n in st.lines_of_templates(tids, blocks)]


def identify(index, client_macs: dict) -> dict:
    """client_macs: {client_mac_upper: [link macs]} -> {client: {label, evidence:[...], wifi7, private}}"""
    alias = {}
    for m, links in client_macs.items():
        alias[m.lower()] = m
        for l in links or []:
            alias[l.lower()] = m
    found: dict = {}
    for i in _hexdump_lines(index, client_macs):
        line = index.lines[i]
        m = HEX_RX.search(line)
        if not m:
            continue
        hx = m.group(2)
        head = hx[:49].split()            # frame control + duration + addresses: decide before decoding the frame
        if len(head) < 16 or int(head[0], 16) not in FIXED_LEN:
            continue
        owner = alias.get(":".join(head[10:16]).lower())
        if not owner:
            continue
        try:
            data = bytes.fromhex(hx)
        except ValueError:
            continue
        if len(data) < 24:
            continue
        d = found.setdefault(owner, {"vendors": {}, "wps": {}, "wifi7": False, "lines": {}})
        for eid, body in _ies(data[24 + FIXED_LEN[data[0]]:]):
            if eid == 255 and body and body[0] in (106, 107, 108):    # EHT capabilities / ML element -> Wi-Fi 7
                d["wifi7"] = True
            if eid != 221 or len(body) < 4:
                continue
            oui = ":".join(f"{b:02X}" for b in body[:3])
            if oui == "00:50:F2" and body[3] == 4:                      # WPS element
                attrs = _wps_attrs(body[4:])
                if attrs:
                    d["wps"].update(attrs)
                    d["lines"].setdefault("wps", i + 1)
            elif oui in VENDOR_IE:
                d["vendors"].setdefault(VENDOR_IE[oui], (oui, i + 1))
            elif oui not in GENERIC_OUI:
                d["vendors"].setdefault(f"OUI {oui}", (oui, i + 1))
            if oui == "50:6F:9A" and body[3] == 0x16:
                d["mbo"] = True
    out = {}
    for mac in client_macs:
        d = found.get(mac, {"vendors": {}, "wps": {}, "wifi7": False, "lines": {}})
        private = bool(int(mac[:2], 16) & 0x02)
        ev, label = [], None
        if d["wps"].get("model") or d["wps"].get("manufacturer"):
            label = " ".join(x for x in (d["wps"].get("manufacturer"), d["wps"].get("model")) if x)
            ev.append(f"WPS element: manufacturer {d['wps'].get('manufacturer', '?')}, model {d['wps'].get('model', '?')} "
                      f"(line {d['lines'].get('wps')})")
        prefix = mac[:8]
        if not private and prefix in MAC_OUI and not label:
            label = MAC_OUI[prefix]
            ev.append(f"MAC vendor prefix {prefix} = {MAC_OUI[prefix]}")
        names = [k for k in d["vendors"] if not k.startswith("OUI ")]
        for k, (oui, ln) in d["vendors"].items():
            ev.append(f"vendor element {k} ({oui}) in a request frame (line {ln})")
        if not label and names:
            if "Apple" in names:
                label = "Apple device"
            elif "Huawei" in names:
                label = "Huawei device"
            elif "Samsung" in names:
                label = "Samsung device"
            elif "Qualcomm" in names and d.get("mbo"):
                label = "Android phone (Qualcomm)"
            elif "MediaTek" in names or "MediaTek/Ralink" in names:
                label = "MediaTek-based device"
            else:
                label = f"{names[0]}-based device"
        if d.get("wifi7"):
            ev.append("EHT / multi-link element -> Wi-Fi 7 client")
        if not label and d.get("wifi7"):
            label = "Unknown Wi-Fi 7 client"
        out[mac] = {"label": (label or "Unknown") + (" (Wi-Fi 7)" if d.get("wifi7") and "Wi-Fi 7" not in label else ""),
                    "evidence": ev or ["no identifying frames logged"], "wifi7": d.get("wifi7", False),
                    "private_mac": private}
    return out
