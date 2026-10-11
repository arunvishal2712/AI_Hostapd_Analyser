"""Shared IEEE 802.11 reason-code lookup used by the parser, MAG and bridge.

Values follow IEEE Std 802.11-2020 Table 9-49 and hostapd's
src/common/ieee802_11_defs.h (WLAN_REASON_*).
"""

REASON_CODE_MEANINGS = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "STA is leaving (or has left) the BSS (deauth)",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "STA is leaving (or has left) the BSS (disassoc)",
    9: "STA requesting (re)association is not authenticated",
    10: "Power Capability element is unacceptable",
    11: "Supported Channels element is unacceptable",
    12: "Disassociated due to BSS Transition Management (802.11v)",
    13: "Invalid element",
    14: "Message integrity code (MIC) failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "Information element mismatch in 4-Way Handshake",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of security policy",
    25: "TDLS teardown: peer unreachable",
    26: "TDLS teardown: unspecified",
    27: "Disassociated: SSP requested",
    28: "Disassociated: no SSP roaming agreement",
    29: "Bad cipher or AKM (SSP)",
    30: "Not authorized in this location",
    31: "Service change precludes TS",
    32: "Unspecified QoS-related reason",
    33: "QoS AP lacks sufficient bandwidth for this STA",
    34: "Disassociated due to excessive frame loss / poor channel conditions (low ACK)",
    35: "STA transmitting outside the limits of its TXOPs",
    36: "Requesting STA is leaving the BSS (or resetting)",
    37: "Requesting STA no longer using the stream/session",
    38: "Requesting STA received frames requiring setup it has not done",
    39: "Requested from peer STA due to timeout",
    45: "Peer key mismatch",
    46: "Authorized access limit reached",
    47: "External service requirements",
    48: "Invalid FT Action frame count",
    49: "Invalid PMKID",
    50: "Invalid MDE",
    51: "Invalid FTE",
}

# Reason codes that normally indicate an ordinary, client-driven departure
# (user switched Wi-Fi off, roamed, went to sleep). A high count of these is
# not a defect by itself.
BENIGN_REASON_CODES = {3, 8, 36}

# Reason codes that point at the security / key-exchange layer.
SECURITY_REASON_CODES = {2, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 45, 49}


def reason_meaning(code):
    if code is None:
        return None
    return REASON_CODE_MEANINGS.get(int(code), "Reserved / vendor-specific reason code")


# Plain-language explanation of the reason codes seen most often in hostapd logs (Timeline view).
REASON_EXPLAIN = {
    1: "No specific reason was given by the sender.",
    2: "The earlier authentication is no longer valid, so the client has to authenticate again "
       "(often after an AP restart or a key change).",
    3: "The client is leaving the network: Wi-Fi switched off, roaming away or going to sleep. "
       "Normally not a fault.",
    4: "The client was idle longer than the AP's inactivity limit (ap_max_inactivity), so the AP removed it.",
    5: "The AP already serves as many clients as it can.",
    6: "The client sent a frame before authenticating; the AP no longer knows it (typical right after an AP restart).",
    7: "The client sent data while the AP had no association for it (typical after an AP restart or a roam).",
    8: "The client is leaving this BSS, usually roaming to another AP / band or switching Wi-Fi off. "
       "Normally not a fault.",
    9: "The client asked to (re)associate without being authenticated first.",
    12: "The client was moved away by BSS Transition Management (802.11v steering).",
    14: "Message integrity check failed: key mismatch or corrupted frames.",
    15: "The 4-way key handshake timed out: wrong passphrase, the client stopped answering EAPOL frames, "
        "or radio problems during the handshake.",
    16: "The group-key update timed out: the client did not answer the group-key message (often a sleeping device).",
    17: "The security information in the handshake did not match the association request (RSN element mismatch): "
        "a client / AP security configuration problem.",
    20: "The client offered an authentication key management (AKM) the AP does not accept.",
    23: "802.1X / RADIUS authentication failed: wrong credentials or a RADIUS server problem.",
    34: "Too many frames were lost: poor channel conditions or low signal.",
    36: "The client is leaving the network or resetting its Wi-Fi.",
}

# IEEE 802.11 status codes (association / authentication responses), hostapd WLAN_STATUS_*.
STATUS_CODE_MEANINGS = {
    0: "Success",
    1: "Unspecified failure",
    10: "Cannot support all requested capabilities",
    11: "Reassociation denied: no existing association",
    12: "Association denied for an unspecified reason",
    13: "Authentication algorithm not supported",
    14: "Authentication transaction sequence number out of order",
    15: "Authentication rejected: challenge failure",
    16: "Authentication rejected: timeout waiting for the next frame",
    17: "AP is unable to handle additional associated STAs",
    18: "Association denied: client does not support all basic rates",
    30: "Association rejected temporarily, try again later (PMF SA Query)",
    31: "Robust management frame policy violation (PMF required)",
    37: "Request declined",
    38: "Invalid parameters",
    40: "Invalid information element",
    41: "Invalid group cipher",
    42: "Invalid pairwise cipher",
    43: "Invalid AKMP (authentication key management not accepted)",
    44: "Unsupported RSN element version",
    45: "Invalid RSN element capabilities",
    46: "Cipher suite rejected because of security policy",
    53: "Invalid PMKID",
    76: "Anti-clogging token required (SAE)",
    77: "Finite cyclic group not supported (SAE)",
    82: "Rejected with a suggested BSS transition",
    123: "Unknown password identifier (SAE)",
    126: "SAE hash-to-element required",
    127: "SAE-PK required",
}


def explain_reason(code):
    """Formal meaning + plain-language explanation of a reason code (None when no code)."""
    if code is None:
        return None
    c = int(code)
    return {"code": c, "meaning": reason_meaning(c), "explain": REASON_EXPLAIN.get(c, ""),
            "benign": c in BENIGN_REASON_CODES, "security": c in SECURITY_REASON_CODES}


def status_meaning(code):
    if code is None:
        return None
    return STATUS_CODE_MEANINGS.get(int(code), "Reserved / vendor-specific status code")
