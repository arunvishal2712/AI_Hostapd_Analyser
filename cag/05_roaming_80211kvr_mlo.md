## Roaming: 802.11k/v/r and Wi-Fi 6/6E/7 MLO

- **802.11k (Radio Resource Management)**: AP provides a neighbor report so the client knows candidate APs to roam to, instead of blindly scanning.
- **802.11v (BSS Transition Management)**: AP can *request* a client roam to a specific BSS (e.g. for load balancing), via a BSS Transition Management (BTM) request/response.
- **802.11r (Fast BSS Transition, FT)**: pre-negotiates key material with neighboring APs so roaming re-authentication/re-handshake takes a few frames instead of a full 4-way handshake -- critical for voice/video roaming without a glitch.
- Repeated roam-then-drop patterns for one client, or BTM requests followed immediately by a failed handshake on the target AP, indicate a roaming/FT interoperability problem rather than a plain connectivity problem.

**Wi-Fi 6 / 6E**: adds OFDMA, TWT (Target Wake Time, power saving), BSS coloring (co-channel interference mitigation), and (6E) access to the 6GHz band.

**Wi-Fi 7 / MLO (Multi-Link Operation)**: a client can maintain simultaneous links across multiple bands/channels (e.g. 5GHz + 6GHz) as one logical connection, improving throughput and reliability. MLO interoperability issues can present as one link of the pair repeatedly failing its handshake or deauthenticating while the other link stays up -- worth checking per-link/per-band event patterns rather than only the aggregate client MAC.
