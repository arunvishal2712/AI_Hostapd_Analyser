## AP bring-up (BSS / VAP start-up) and Wi-Fi 7 MLD on OpenWrt hostapd

**Normal bring-up sequence** for each BSS (VAP): hostapd reads the config -> creates the interface / AP MLD
("AP MLD phy00-mld0 created", "Link ID 0 assigned") -> "Using interface X with hwaddr <BSSID> and ssid ..." ->
driver sets keys and the beacon template ("set beacon") -> channel/DFS checks -> "interface state ...->ENABLED"
-> "AP-ENABLED". Only after AP-ENABLED does the AP transmit beacons and can clients send Authentication /
Association Requests. A log with bring-up lines but no AP-ENABLED means the BSS never started beaconing.

**Typical bring-up failures and what they mean:**
- `event=vap_up_fail` (HOSTAPD-LOG-TRIGGER): the vendor driver could not bring the VAP up; hostapd tears the
  BSS down again. Look at the lines just before it for the failing driver call.
- `Failed to set beacon parameters (ret=-22)`: the driver rejected the beacon template (EINVAL). Common causes:
  unsupported combination of mode/width/channel, MBSSID/EMA profile limits, invalid IEs, 6 GHz power mode.
- `iface enabled notify failed err=-22` / `Failed to notify iface enabled mode`: vendor nl80211 command not
  accepted by the driver - usually a hostapd/driver version mismatch or unsupported feature flag.
- `vendor command failed err=-22` (EINVAL) / `err=-16` (EBUSY): driver refused a vendor command; -16 often
  means the radio/interface is busy (previous instance not fully removed).
- `Could not determine operating frequency`, `get_sta_channel ret=-61` (ENODATA): no valid channel was
  resolved (ACS not finished, channel not allowed for the country/regulatory domain, DFS channel waiting).
- `AFC power event not received` / `Unable to get EIRP`: 6 GHz standard-power needs AFC; without it the AP
  must use low-power indoor mode or the 6 GHz BSS can fail to start.
- `Invalid interface name/radio identifier/link id` and repeated `removing phy00-mldN` / `CTRL-EVENT-TERMINATING`:
  netifd/ubus reconfiguration loops - the configuration is being applied again and again.
- `rmdir[ctrl_interface=...]: Permission denied`: harmless when "Using existing control interface directory"
  follows.
- A broadcast Deauthentication (da=ff:ff:ff:ff:ff:ff, sa=bssid) during teardown is the AP saying goodbye to all
  stations; it is not a client disconnection.

**Recommended debugging for an AP that does not come up:**
1. Find the first error line before each `vap_up_fail` / `Failed to set beacon` and note the errno.
2. Check the wireless config for that radio: channel, htmode/width (e.g. 320 MHz only on 6 GHz), country,
   band, MLO link set, MBSSID count, 6 GHz power mode / AFC settings; try a simpler config (one BSS, 80 MHz).
3. Confirm hostapd and the driver/firmware come from the same build (vendor nl80211 commands must match).
4. Check `logread -e ath12k` / `dmesg` for driver/firmware errors at the same timestamp.
5. Verify the interface actually reaches `AP-ENABLED` and beacons (`iw dev` shows type AP with a channel,
   a sniffer sees beacons with the BSSID) before testing clients.
