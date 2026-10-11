## Deauthentication, Disassociation, and Reason Codes

**Deauthentication** invalidates the authentication state (client must restart from authentication). **Disassociation** invalidates only the association (client may re-associate without re-authenticating, when supported). Either can be initiated by the client or the AP, and both carry a numeric reason code explaining why.

Common IEEE 802.11 reason codes:

| Code | Meaning |
|---|---|
| 1 | Unspecified reason |
| 2 | Previous authentication no longer valid |
| 3 | STA is leaving (or has left) the BSS -- normal client-initiated disconnect (e.g. user turned off Wi-Fi, roamed away) |
| 4 | Disassociated due to inactivity -- AP timed out an idle client |
| 5 | AP unable to handle all currently associated stations (capacity) |
| 6 | Class 2 frame received from nonauthenticated STA |
| 7 | Class 3 frame received from nonassociated STA |
| 8 | STA is leaving (or has left) the BSS (disassoc variant of reason 3) |
| 9 | STA requesting (re)association is not authenticated |
| 12 | Disassociated due to BSS Transition Management (802.11v steering) |
| 14 | MIC failure (TKIP countermeasures / corrupted frames) |
| 15 | 4-Way Handshake timeout |
| 16 | Group Key Handshake timeout |
| 17 | IE mismatch in 4-Way Handshake |
| 18 | Invalid group cipher |
| 19 | Invalid pairwise cipher |
| 20 | Invalid AKMP |
| 23 | IEEE 802.1X authentication failed |
| 34 | Disassociated due to excessive frame loss / poor channel conditions (AP-initiated, RF quality) |
| 39 | Requested from peer STA due to timeout (e.g. BA/TS/keep-alive timeout; often power-save or RF) |
| 49 | Invalid PMKID (PMKSA cache mismatch -- common after roaming or AP restart) |

**Interpretation guidance**: reason codes 3 and 8 are usually benign (normal disconnects, roaming, power-save). Reason 4 suggests idle timeout tuning. Reason 15/16/17 point back to the handshake/key-exchange layer, not the RF layer. Reason 34 is an AP-side RF-quality judgment call and correlates with weak signal or interference, not a security/config problem.

A high *count* of deauths is not itself a defect -- clients disconnect normally when users roam, sleep, or power off. What matters is the reason-code distribution and whether the same client repeats the same non-benign reason code.

**Who sent the deauth matters.** In hostapd logs, `wlan0: deauthentication: STA=<mac> reason_code=N` means the frame was *received from the client* (client-initiated). `IEEE 802.11: deauthenticated due to local deauth request` means *hostapd itself* kicked the client (AP-initiated). `Deauthentication callback for STA` is only the TX-status callback of an AP-sent deauth and is not a separate disconnect.
