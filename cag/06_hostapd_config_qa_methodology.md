## Hostapd Configuration and Wi-Fi QA Methodology

**Hostapd** is the reference software AP/authenticator used in this test setup. Relevant config knobs when interpreting logs:
- `wpa=2` / `wpa_key_mgmt=SAE` / `ieee80211w=1|2` (PMF optional/required) directly change which handshake path and reason codes are possible.
- `max_num_sta` caps concurrent associations -- hitting it produces association failures (reason 5-style) under load.
- `ap_max_inactivity` controls the idle timeout before the AP disassociates a quiet client (reason 4).
- Log verbosity (`logger_syslog_level`, `-d`/`-dd` flags) affects how much detail (e.g. EAPOL frame-level messages) appears in the log; sparse logs may under-report the true failure mode.

**Wi-Fi QA methodology** for interpreting a failing test run:
1. Separate **transient** issues (isolated single-client, single-event) from **systemic** ones (many clients, same reason code, same AP/channel/time window).
2. Always check whether a failure repeats for the *same* client across *multiple* historical test runs (MAG) before calling it a one-off.
3. Prefer the deterministic parser's counts over any qualitative impression of "a lot of failures" -- state the actual number.
4. When recommending root cause, distinguish confirmed observation ("12 handshake timeouts occurred") from hypothesis ("this pattern is consistent with an interoperability issue") -- do not present a hypothesis as a confirmed cause.
5. Standard next-step debugging actions for handshake/auth issues: capture EAPOL frames (pcap), compare a known-good client against the failing one on the same AP/channel, check RF (RSSI/retry rate) during the failure window, verify PMF/cipher config matches on both ends.
