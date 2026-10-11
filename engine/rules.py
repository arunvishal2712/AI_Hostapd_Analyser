"""
Typed event and attribute extraction from one log line.

Which rules can apply is decided once per message template (rules_for_template), so a line whose template has no
rule costs only the template lookup. Events are written to the store with their line number and time; they are
the edges of the entity graph (client -> interface / BSS) and the input of rollups, sessions and the agent.
"""
from __future__ import annotations

import re

M = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
STA_RX = re.compile(r"(?:STA[ =]|sta[ =])" + M)
SA_RX = re.compile(r"\bsa=" + M, re.I)
DA_RX = re.compile(r"\bda=" + M, re.I)
BSSID_RX = re.compile(r"\bbssid=" + M, re.I)
A2_RX = re.compile(r"\bA2=" + M)
ANY_MAC_RX = re.compile(M)
REASON_RX = re.compile(r"reason(?:_code)?[= :]+(\d+)", re.I)
STATUS_RX = re.compile(r"status(?:_code)?[= :]+(\d+)", re.I)
FREQ_RX = re.compile(r"\bfreq=(\d+)")
SIG_RX = re.compile(r"ssi_signal=(-?\d+)")
IFACE_RX = re.compile(r"^((?:phy|wlan|wl\d|ath|rai?\d|apcli|mld|ap\d)[\w.\-]*)(?:\([^)]*\))?: ")
AKM_RX = re.compile(r"Invalid WPA key mgmt \((0x[0-9a-fA-F]+)\) from " + M)
CURAP_RX = re.compile(r"current_ap=" + M, re.I)
AID_RX = re.compile(r"\baid=(\d+)")
AUTHALG_RX = re.compile(r"auth_alg=(\w+)")
TRANS_RX = re.compile(r"auth_transaction=(\d+)")
STATE_RX = re.compile(r"interface state (\S+)")
USING_RX = re.compile(r"Using interface (\S+) with hwaddr " + M + r" and ssid \"(.*)\"")
CAC_RX = re.compile(r"freq=(\d+) chan=(\d+).*?cac_time=(\d+)")
CHAN_RX = re.compile(r"\bchan(?:nel)?=(\d+)")
FW_RX = re.compile(r"OpenWrt\s+([\w.\-]+),\s*([\d.]+)")
CONTEXT_STA_RX = re.compile(r"(?:STA=|WPA: )" + M, re.I)
BCAST = "FF:FF:FF:FF:FF:FF"
AKM_NAMES = {0x4000000: "SAE-EXT-KEY", 0x400: "SAE", 0x2: "PSK", 0x100: "PSK-SHA256", 0x10000: "OWE", 0x1: "802.1X"}

# canonical event types -> human label (also the vocabulary of the router / agent)
LABELS = {
    "connected": "connected (AP-STA-CONNECTED)", "disconnected": "disconnected (AP-STA-DISCONNECTED)",
    "auth_req": "authentication request", "sae_commit": "SAE commit", "auth_ok": "authenticated",
    "auth_no_ack": "auth response not ACKed", "assoc_req": "association request", "reassoc_req": "reassociation request",
    "assoc_ok": "associated", "mlo_link_ok": "MLO link accepted", "assoc_no_ack": "assoc response not ACKed", "eapol_start": "4-way handshake started (PTKSTART)",
    "eapol_rx": "EAPOL-Key received from client", "fourway_ok": "4-way handshake completed",
    "fourway_fail": "4-way handshake failed", "disconnect_req": "WPA authenticator requests disconnect",
    "deauth_rx": "deauth from client", "disassoc_rx": "disassoc from client", "deauth_tx": "deauth sent by AP",
    "disassoc_tx": "disassoc sent by AP", "deauth_local": "deauthenticated by AP (local / inactivity)",
    "inactivity": "inactivity timeout", "missing_acks": "excessive missing ACKs (link loss)",
    "unprot": "unprotected deauth/disassoc (PMF)", "akm_invalid": "invalid AKM offered", "mlo_reject": "MLO link rejected (status 43)",
    "sae_fail": "SAE failure", "eapol_noack": "EAPOL TX not ACKed", "dfs_cac_start": "DFS wait started",
    "dfs_cac_done": "DFS wait completed", "radar": "radar detected", "iface_state": "interface state change",
    "ap_enabled": "AP-ENABLED", "ap_disabled": "AP-DISABLED", "bss_terminating": "BSS terminating",
    "iface_removed": "interface removed", "config_load": "configuration (re)loaded", "bss_setup": "BSS set up",
    "drv_busy": "driver: resource busy", "drv_severed": "driver: link severed", "nft_error": "nftables error",
    "nl80211_error": "nl80211 command failed", "capture": "console capture start", "firmware": "firmware banner",
    "chan_switch": "channel switch", "btm": "BSS transition management", "eap_fail": "EAP / RADIUS failure",
    "status_fail": "request rejected with status code",
}
DISCONNECT_TYPES = {"disconnected", "deauth_rx", "disassoc_rx", "deauth_tx", "disassoc_tx", "deauth_local", "inactivity",
                    "missing_acks", "unprot", "disconnect_req", "fourway_fail"}
FAILURE_TYPES = {"auth_no_ack", "assoc_no_ack", "fourway_fail", "sae_fail", "mlo_reject", "akm_invalid", "eap_fail",
                 "status_fail", "eapol_noack"}
AP_TYPES = {"dfs_cac_start", "dfs_cac_done", "radar", "iface_state", "ap_enabled", "ap_disabled", "bss_terminating",
            "iface_removed", "config_load", "bss_setup", "chan_switch", "drv_busy", "drv_severed", "nft_error",
            "nl80211_error", "capture", "firmware"}


def _up(m):
    return m.group(1).upper() if m else None


class Ctx:
    """Per-chunk extraction state (small and bounded)."""
    __slots__ = ("events", "attrs", "last_sta", "last_sta_line", "last_akm", "line", "ep", "hms", "tpl")

    def __init__(self):
        self.events, self.attrs = [], []
        self.last_sta, self.last_sta_line, self.last_akm, self.line = None, -99, None, 0
        self.ep = self.hms = self.tpl = None

    def ev(self, typ, mac=None, peer=None, iface=None, reason=None, status=None, detail=None):
        self.events.append((self.line, self.ep, self.hms, typ, mac, peer, iface, reason, status, detail, self.tpl))

    def at(self, entity, key, value):
        self.attrs.append((self.line, self.ep, entity, key, str(value)))


def _sta(s):
    return _up(STA_RX.search(s))


def r_connected(s, low, body, iface, c):
    if "ap-sta-connected" in low:
        mac = _up(ANY_MAC_RX.search(s[low.find("ap-sta-connected"):]))
        aid, alg = AID_RX.search(s), AUTHALG_RX.search(s)
        c.ev("connected", mac, None, iface, detail=" ".join(x for x in (f"aid={aid.group(1)}" if aid else "",
                                                                        f"auth_alg={alg.group(1)}" if alg else "") if x))
        if mac and aid:
            c.at(mac, "aid", aid.group(1))
        ch = CHAN_RX.search(s)
        if ch and iface:
            c.at(iface, "connect_channel", ch.group(1))     # the (link) channel this client connected on
        if mac and alg:
            c.at(mac, "auth_alg", alg.group(1))
    elif "ap-sta-disconnected" in low:
        c.ev("disconnected", _up(ANY_MAC_RX.search(s[low.find("ap-sta-disconnected"):])), None, iface)


def r_auth(s, low, body, iface, c):
    if "authentication: sta=" in low and "deauthentication: sta=" not in low:
        mac = _sta(s)
        tr, alg = TRANS_RX.search(s), AUTHALG_RX.search(s)
        sae = alg and alg.group(1) == "3" and tr and tr.group(1) == "1"
        c.ev("sae_commit" if sae else "auth_req", mac, None, iface,
             detail=f"auth_alg={alg.group(1) if alg else '?'} transaction={tr.group(1) if tr else '?'}")
    elif "ieee 802.11: authenticated" in low:
        c.ev("auth_ok", _sta(s), None, iface)
    elif "did not acknowledge authentication response" in low:
        c.ev("auth_no_ack", _sta(s) or _up(ANY_MAC_RX.search(s)), None, iface)
    elif "did not acknowledge association response" in low:
        c.ev("assoc_no_ack", _sta(s) or _up(ANY_MAC_RX.search(s)), None, iface)
    elif "mld: link=" in low and "association ok" in low:
        c.ev("mlo_link_ok", c.last_sta if c.line - c.last_sta_line <= 20 else None, None, iface, detail=body[:80])
    elif "ieee 802.11: associated" in low or "association ok" in low:
        c.ev("assoc_ok", _sta(s), None, iface)


def r_frame(s, low, body, iface, c):
    """nl80211 RX frame / send_mlme lines: management frames with addresses, frequency and signal."""
    if "rx frame" in low:
        sa, bss = _up(SA_RX.search(s)), _up(BSSID_RX.search(s))
        sig = SIG_RX.search(s)
        if "stype_assoc_req" in low or "stype_reassoc_req" in low:
            fq = FREQ_RX.search(s)
            c.ev("reassoc_req" if "reassoc" in low else "assoc_req", sa, bss, iface,
                 detail=f"freq={fq.group(1)}" if fq else None)
            if fq and sa:
                c.at(sa, "freq", fq.group(1))
        elif "stype_deauth" in low or "stype_disassoc" in low:
            da = _up(DA_RX.search(s))
            if sa and sa != bss:   # client -> AP
                c.ev("deauth_rx" if "deauth" in low else "disassoc_rx", sa, bss, iface, reason=None, detail="frame received")
            elif da:
                c.ev("deauth_tx" if "deauth" in low else "disassoc_tx", da, bss, iface, detail="frame seen")
        if sig and sa:
            c.at(sa, "signal", sig.group(1))
    elif "send_mlme" in low and ("stype_deauth" in low or "stype_disassoc" in low):
        da, bss = _up(DA_RX.search(s)), _up(BSSID_RX.search(s))
        c.ev("deauth_tx" if "deauth" in low else "disassoc_tx", da, bss, iface, detail="sent by AP")


def r_reassoc(s, low, body, iface, c):
    if "reassociation request: sta=" in low or "association request: sta=" in low:
        mac, cur = _sta(s), _up(CURAP_RX.search(s))
        if cur:
            c.ev("reassoc_req", mac, cur, iface, detail=f"current_ap={cur}")
            if mac:
                c.at(mac, "current_ap", cur)


def r_wpa(s, low, body, iface, c):
    if "wpa_ptk entering state ptkstart" in low:
        c.ev("eapol_start", _up(ANY_MAC_RX.search(s)), None, iface)
    elif "received eapol-key from" in low:
        c.ev("eapol_rx", _up(ANY_MAC_RX.search(s[low.find("received eapol-key from"):])), None, iface)
    elif "eapol-4way-hs-completed" in low or "pairwise key handshake completed" in low:
        c.ev("fourway_ok", _up(ANY_MAC_RX.search(s)) or c.last_sta, None, iface)
    elif "wpa authenticator requests disconnect" in low:
        r = REASON_RX.search(s)
        c.ev("disconnect_req", _up(ANY_MAC_RX.search(s)), None, iface, reason=int(r.group(1)) if r else None)
        if r and r.group(1) in ("15", "16"):
            c.ev("fourway_fail", _up(ANY_MAC_RX.search(s)), None, iface, reason=int(r.group(1)),
                 detail="4-way handshake timeout")
    elif "retry limit" in low or ("4-way handshake" in low and ("fail" in low or "timeout" in low)):
        c.ev("fourway_fail", _up(ANY_MAC_RX.search(s)) or c.last_sta, None, iface, detail="retry limit / timeout")
    elif "eapol-key tx status" in low:
        if "ack=0" in low:
            c.ev("eapol_noack", _up(ANY_MAC_RX.search(s)), None, iface)


def r_disconnect(s, low, body, iface, c):
    r = REASON_RX.search(s)
    reason = int(r.group(1)) if r else None
    if "deauthentication: sta=" in low:
        c.ev("deauth_rx", _sta(s), None, iface, reason=reason, detail="client sent deauthentication")
    elif "disassociation: sta=" in low or "disassocation: sta=" in low:     # (sic) - hostapd's own spelling
        c.ev("disassoc_rx", _sta(s), None, iface, reason=reason, detail="client sent disassociation")
    elif "deauthenticated due to" in low:
        c.ev("deauth_local", _sta(s) or _up(ANY_MAC_RX.search(s)), None, iface, reason=reason,
             detail=s[low.find("deauthenticated due to"):][:80])
    elif "disassociated due to inactivity" in low or "timeout, sending deauthentication" in low \
            or "timeout, sending disassociation" in low:
        c.ev("inactivity", _sta(s) or _up(ANY_MAC_RX.search(s)), None, iface, reason=reason or 4)
    elif "excessive missing acks" in low:
        c.ev("missing_acks", _sta(s) or _up(ANY_MAC_RX.search(s)), None, iface, reason=reason or 34)
    elif "unprot_deauthenticate" in low or "unprot_disassociate" in low:
        c.ev("unprot", _up(A2_RX.search(s)), None, iface, detail="unprotected " + ("deauth" if "deauth" in low else "disassoc"))


def r_mlo(s, low, body, iface, c):
    if "invalid wpa key mgmt" in low:
        m = AKM_RX.search(s)
        if m:
            mac = m.group(2).upper()
            akm = AKM_NAMES.get(int(m.group(1), 16), m.group(1))
            c.last_akm = (mac, c.line, akm)
            c.ev("akm_invalid", mac, None, iface, detail=f"offered {akm}")
    elif "status=" in low and "mld" in low:
        st = STATUS_RX.search(s)
        if st and st.group(1) == "43":
            la = c.last_akm
            mac = la[0] if la and c.line - la[1] <= 4 else None
            c.ev("mlo_reject", mac, None, iface, status=43,
                 detail=f"link rejected, invalid AKM ({la[2]})" if la and mac else "link rejected, invalid AKM")


def r_sae(s, low, body, iface, c):
    if ("sae" in low and any(w in low for w in ("fail", "mismatch", "reject", "invalid"))) \
            or "sae-unknown-password" in low:
        c.ev("sae_fail", _sta(s) or _up(ANY_MAC_RX.search(s)) or c.last_sta, None, iface, detail=body[:100])
    elif "eap-failure" in low or "access-reject" in low or "eap authentication failed" in low:
        c.ev("eap_fail", _sta(s) or _up(ANY_MAC_RX.search(s)), None, iface)


def r_ap(s, low, body, iface, c):
    if "dfs-cac-start" in low:
        m = CAC_RX.search(s)
        c.ev("dfs_cac_start", None, None, iface, detail=f"freq={m.group(1)} chan={m.group(2)} cac_time={m.group(3)}s" if m else None)
        if m and iface:
            c.at(iface, "freq", m.group(1))
            c.at(iface, "channel", m.group(2))
            c.at(iface, "cac_time", m.group(3) + " s")
    elif "dfs-cac-completed" in low:
        c.ev("dfs_cac_done", None, None, iface, detail=body[:120])
    elif "dfs-radar-detected" in low or "radar detected" in low:
        c.ev("radar", None, None, iface, detail=body[:120])
    elif "interface state " in low:
        m = STATE_RX.search(s)
        c.ev("iface_state", None, None, iface, detail=m.group(1) if m else None)
        if m and iface:
            c.at(iface, "state", m.group(1).split("->")[-1])
    elif "ap-enabled" in low:
        c.ev("ap_enabled", None, None, iface)
    elif "ap-disabled" in low:
        c.ev("ap_disabled", None, None, iface)
    elif "ctrl-event-terminating" in low:
        c.ev("bss_terminating", None, None, iface)
    elif "removing interface" in low:
        c.ev("iface_removed", None, None, iface, detail=body[:80])
    elif "configuration file:" in low:
        c.ev("config_load", None, None, iface, detail=body[:120])
    elif "using interface " in low and "with hwaddr" in low:
        m = USING_RX.search(s)
        if m:
            c.ev("bss_setup", m.group(2).upper(), None, m.group(1), detail=f'ssid "{m.group(3)}"')
            c.at(m.group(1), "bssid", m.group(2).upper())
            c.at(m.group(1), "ssid", m.group(3))
            c.at(m.group(2).upper(), "ssid", m.group(3))
            c.at(m.group(2).upper(), "iface", m.group(1))
    elif "ch_switch" in low or "csa " in low or "channel switch" in low:
        c.ev("chan_switch", None, None, iface, detail=body[:120])


def r_driver(s, low, body, iface, c):
    if "resource busy" in low:
        c.ev("drv_busy", None, None, iface, detail=body[:140])
    elif "link has been severed" in low:
        c.ev("drv_severed", None, None, iface, detail=body[:140])
    elif "nft:" in low and any(w in low for w in ("fail", "error", "unable", "could not", "denied")):
        c.ev("nft_error", None, None, iface, detail=body[:140])
    elif "nl80211:" in low and ("failed" in low or "error -" in low) and "bridge fdb entry delete" not in low:
        c.ev("nl80211_error", _up(ANY_MAC_RX.search(s)), None, iface, detail=body[:140])


def r_misc(s, low, body, iface, c):
    if "putty log" in low or low.startswith("login as:"):
        c.ev("capture", None, None, None, detail=s[:120])
    elif "openwrt" in low:
        m = FW_RX.search(s)
        if m:
            c.ev("firmware", None, None, None, detail=f"OpenWrt {m.group(1)}, {m.group(2)}")
            c.at("system", "firmware", f"OpenWrt {m.group(1)}, {m.group(2)}")
    elif "bss-tm" in low or "bss transition" in low:
        c.ev("btm", _up(ANY_MAC_RX.search(s)), None, iface, detail=body[:120])
    elif ("status_code=" in low or "status code" in low) and ("reject" in low or "denied" in low or "fail" in low):
        st = STATUS_RX.search(s)
        c.ev("status_fail", _sta(s) or _up(ANY_MAC_RX.search(s)), None, iface,
             status=int(st.group(1)) if st else None, detail=body[:120])


# (needles on the lower-cased template, function). A template gets every rule one of whose needles it contains.
RULES = [
    (("ap-sta-connected", "ap-sta-disconnected"), r_connected),
    (("authentication: sta=", "ieee #: authenticated", "ieee 802.11: authenticated", "did not acknowledge",
      "ieee #: associated", "ieee 802.11: associated", "association ok"), r_auth),
    (("rx frame", "send_mlme"), r_frame),
    (("association request: sta=",), r_reassoc),
    (("wpa_ptk entering state ptkstart", "received eapol-key from", "eapol-4way-hs-completed",
      "pairwise key handshake completed", "wpa authenticator requests disconnect", "retry limit", "4-way handshake",
      "eapol-key tx status"), r_wpa),
    (("deauthentication: sta=", "disassociation: sta=", "disassocation: sta=", "deauthenticated due to", "disassociated due to inactivity",
      "timeout, sending", "excessive missing acks", "unprot_deauthenticate", "unprot_disassociate"), r_disconnect),
    (("invalid wpa key mgmt", "status="), r_mlo),
    (("sae", "eap-failure", "access-reject", "eap authentication failed"), r_sae),
    (("dfs-", "radar", "interface state ", "ap-enabled", "ap-disabled", "ctrl-event-terminating", "removing interface",
      "configuration file:", "using interface ", "ch_switch", "csa ", "channel switch"), r_ap),
    (("resource busy", "link has been severed", "nft:", "nl80211:"), r_driver),
    (("putty log", "login as:", "openwrt", "bss-tm", "bss transition", "status_code=", "status code"), r_misc),
]


def rules_for_template(tpl_low: str):
    fns = []
    for needles, fn in RULES:
        if any(n in tpl_low for n in needles):
            fns.append(fn)
    if fns == [r_driver] and "nl80211:" in tpl_low and not any(
            w in tpl_low for w in ("failed", "error -", "resource busy", "severed")):
        return ()       # the very frequent plain nl80211 debug lines need no rule
    if r_frame in fns and "rx frame" in tpl_low and not any(
            w in tpl_low for w in ("stype_assoc", "stype_reassoc", "stype_deauth", "stype_disassoc", "ssi_signal")):
        fns.remove(r_frame)
    return tuple(fns)


def iface_of(body: str):
    m = IFACE_RX.match(body)
    return m.group(1) if m else None
