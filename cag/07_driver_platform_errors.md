## Driver, Platform and OpenWrt-Specific hostapd Errors

These lines have no client MAC but often explain *every* client-level symptom in the same time window. Always check them before blaming clients.

| Log text | Meaning | Typical cause |
|---|---|---|
| `Failed to create interface wlanX: -23 (Too many open files in system)` | ENFILE: kernel file-descriptor table exhausted, VAP not created | fd leak in a daemon, too many VAPs/sockets, low `fs.file-max`; the BSS on that interface may not exist at all |
| `Failed to set beacon parameters (ret=-22)` | EINVAL from the driver when installing the beacon template | unsupported IE/rate/HE/EHT combination, channel/width not accepted, driver or firmware bug |
| `Failed to update beacons with MU-EDCA parameters` | 802.11ax MU-EDCA IE not applied | follows beacon-set failure, HE config the driver rejects |
| `Could not set STA to kernel driver` | driver refused to add the station after association | driver station-table limit, firmware busy, MLO link state mismatch; client authenticates but cannot pass data |
| `Could not set station <mac> flags for kernel driver (errno=11)` | EAGAIN: driver busy, could not set AUTHORIZED/ASSOC flags | firmware command queue congestion, often right after a burst of connects |
| `Failed to send ttlm params to driver` | Wi-Fi 7 MLO TID-to-Link-Mapping not accepted | EHT/MLO driver support incomplete or client TTLM request unsupported |
| `Could not determine operating frequency` / `Failed to fetch HW blocklist channels` | radio channel state unknown or blocked | channel/country/DFS configuration or radio not ready |
| `NFT: Failed to create chain 'wifi_qos_chain_*'` | OpenWrt nftables QoS helper failed | userspace QoS script, usually not a Wi-Fi link problem by itself |
| `nl80211: sta_remove -> DEL_STATION wlanX <mac>` | station entry removed from driver | normal cleanup after deauth/timeout; high counts mirror connect churn |

**`did not acknowledge authentication response`**: the AP sent the Authentication response frame but never received the 802.11 ACK. It is a Layer-1/2 delivery problem, not a credential problem. Common causes: client already left the channel (scanning / probing, MAC-randomised pre-association), client out of range or weak uplink, AP transmitting on a channel/width the client is no longer listening on, or AP beacon/TX path broken (look for beacon-set failures in the same window). Many different clients showing it at once points to the AP side; one client repeatedly showing it points to that client or its RF position.

**Triage order for a failing OpenWrt run**: (1) system/driver errors at startup (interface creation, beacon set, fd exhaustion) -- if the BSS itself is unhealthy, client failures are consequences; (2) auth-response ACK failures across many clients; (3) association to handshake completion ratio; (4) reason-code distribution and who initiated deauths; (5) per-client repetition across historical tests (MAG).
