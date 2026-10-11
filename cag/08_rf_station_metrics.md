## RF and Performance Metrics (iw station dump, ping, Wi-Fi 7 MLO)

`iw <if> station dump` fields and how to read them:

| Field | Meaning | Healthy guideline |
|---|---|---|
| signal / signal avg | RSSI of frames received from the client (dBm) | > -65 good, -65..-70 fair, < -70 poor for high MCS; on MLO the per-link value matters |
| avg ack signal | RSSI of the client's ACKs | close to signal avg; much lower means asymmetric link |
| tx packets / tx retries / tx failed | AP->client frames sent / retransmitted / dropped after all retries | tx failed should be a small fraction of tx packets; tx failed growing between dumps = ongoing loss |
| tx bitrate | AP->client rate chosen by rate control (MCS, NSS, width, EHT/HE/VHT) | 6.0 / 12 / 24 MBit/s with no MCS = legacy fallback (rate control collapsed or management/idle frames) |
| rx bitrate | client->AP rate | high rx with very low tx = downlink problem (AP TX path, client RX, interference at client) |
| inactive time | ms since last activity | large values while ping runs = client not responding |
| authorized / associated | 802.11 + 4-way state | yes/yes = fully connected |
| Link N (MLO) | per-link counters for multi-link clients | links with 0 packets are set up but idle |

**PHY mode from the bitrate string:** `EHT-MCS` = Wi-Fi 7 (802.11be), `HE-MCS` = Wi-Fi 6/6E (802.11ax), `VHT-MCS` = 802.11ac, `MCS` = 802.11n, no MCS = legacy OFDM/CCK. A HE client on a 320 MHz 6 GHz link can use at most 160 MHz.

**MLO (Multi-Link Operation):** `Station X (on wlan0 - link0, link1, link2)` = the client negotiated several links; `(on wlan0 - link1)` = single-link association. Traffic on only one link of an MLO client is common (TID-to-link mapping, power save, link selection) but removes MLO's redundancy; check TTLM and per-link RSSI.

**ping as a test signal:**
- `ping: sendto: Network unreachable` = no route on the AP itself (WAN/uplink not up yet), not a Wi-Fi problem.
- LAN ping to a Wi-Fi client should be a few ms; median > 20 ms, p95 > 100 ms or loss > 1 % points to airtime contention, power-save latency, retries/rate collapse, or interference.
- Very large maxima (seconds) with loss = client in power save or roaming/reconnecting; correlate with station-dump inactive time and tx failed growth.

**hostapd -dd frame debug:** `RX frame ... PROBE_REQ ... ssi_signal=-53` lines show clients scanning and their RSSI per band; `send_mlme ... PROBE_RESP` are the AP's replies; `on link_id=N` shows which MLO link handled the frame.

**Triage for a slow / lossy Wi-Fi client:** (1) signal and ack signal; (2) tx failed vs tx packets and its growth; (3) tx bitrate collapse or legacy fallback while rx stays high (downlink-only issue); (4) PHY mode and MLO links actually used; (5) ping loss/latency to the client vs to the WAN.
