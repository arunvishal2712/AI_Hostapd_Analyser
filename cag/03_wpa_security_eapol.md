## WPA2 / WPA3 / SAE / EAPOL / 4-Way Handshake

- **WPA2**: uses CCMP (AES) or (legacy, insecure) TKIP for encryption, with a 4-way EAPOL handshake to derive session keys from the PSK or 802.1X (Enterprise) master key.
- **WPA3-Personal**: replaces the PSK exchange with SAE, adds forward secrecy, and typically enforces PMF (Protected Management Frames, 802.11w) so deauth/disassoc frames themselves are authenticated -- this prevents deauth-flood attacks but also means a misconfigured PMF mismatch between client and AP will hard-fail the connection.
- **WPA3-Enterprise / 802.1X**: authentication is delegated to a RADIUS server via EAP; failures show up as RADIUS Access-Reject or EAP-Failure events, not handshake timeouts.
- **4-Way Handshake (EAPOL-Key frames 1-4)**: after authentication/association, AP and client exchange 4 EAPOL frames to derive and confirm the Pairwise Transient Key (PTK) and install the Group Temporal Key (GTK).
  - **Msg 1/4** (AP->STA): ANonce
  - **Msg 2/4** (STA->AP): SNonce + MIC
  - **Msg 3/4** (AP->STA): GTK + MIC, install PTK
  - **Msg 4/4** (STA->AP): confirmation

**4-Way Handshake timeout/failure** is one of the most common real-world Wi-Fi QA symptoms. Root causes, roughly in order of frequency:
1. Client/AP interoperability bug (retransmission timing, EAPOL frame handling) -- especially common with new client chipsets against older AP firmware or vice versa.
2. Wrong PSK (WPA2) -- but note: WPA2 wrong-PSK usually fails at Msg 2->3 with a MIC failure, not a clean timeout.
3. RF issues / packet loss causing EAPOL frames to be dropped in transit.
4. PMF (802.11w) policy mismatch between client and AP.
5. Retransmission/timing race conditions under high channel utilization.

A single handshake failure is often transient. A *pattern* of repeated handshake failures for the same client, or for many different clients against the same AP/channel, points to a systemic interoperability or RF problem rather than one bad client.
