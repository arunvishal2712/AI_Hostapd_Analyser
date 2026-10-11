## 802.11 Client Lifecycle

A Wi-Fi client goes through a strict state machine before it can pass traffic:

1. **Scanning** - client discovers the AP/SSID via beacons or probe requests.
2. **Authentication** - Open System (WPA2/WPA3-Personal) or SAE (WPA3) exchange that establishes the client is allowed to proceed. This is NOT a password check in Open System mode.
3. **Association** - client requests to join the BSS; AP assigns an Association ID (AID). Capability/rate mismatches fail here.
4. **4-Way Handshake (EAPOL)** - only for WPA2/WPA3; derives the pairwise transient key (PTK) and group temporal key (GTK). This is where most "connects but no internet" issues originate.
5. **Connected / Data** - client can pass traffic.
6. **Disassociation / Deauthentication** - client or AP tears down the session, carrying a reason code.
7. **Reconnect** - client restarts from step 1 or 2.

A failure at any step blocks all later steps. A client that never reaches "Connected" but shows repeated authentication attempts is retrying from step 1, not stuck at 4.
