## Authentication and Association

**Authentication** (Open System): a two-frame exchange (request/response) with no security check itself in WPA2/WPA3-Personal networks -- real security happens later in the 4-way handshake. Failures here are almost always driver/timing/RF issues (client didn't hear the response, retried too fast) rather than credential problems.

**SAE (WPA3 "Simultaneous Authentication of Equals")** replaces Open System authentication in WPA3-Personal. It is a password-authenticated key exchange (dragonfly handshake) -- a wrong PSK *can* fail here, unlike WPA2's Open System auth.

**Association**: client sends supported rates, capabilities (HT/VHT/HE), and RSN information element (security capabilities). The AP accepts or rejects based on compatibility. Association failures commonly indicate:
- Rate/band mismatch (e.g. client only supports 2.4GHz, AP config forces 5GHz-only rates)
- RSN/cipher mismatch (client and AP don't agree on a common cipher suite)
- AP at `max_num_sta` capacity

A client stuck in an auth/assoc retry loop without ever reaching the handshake usually points to a Layer 1/2 (RF, driver, capability) problem, not a WPA key problem.
