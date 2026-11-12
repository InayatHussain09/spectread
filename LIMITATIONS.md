# Limitations

- Relay uses impacket-ntlmrelayx; poisoning is our own LLMNR/NBNS listener.
- Shadow Credentials and certificate requests delegate to certipy-ad.
- No EDR evasion, no beaconing, no SOCKS pivot beyond ntlmrelayx `-socks`.
- Single domain per run. No forest trust traversal.
- Kerberoast RC4 requires RC4 to be enabled on the account; AES hashes go to
  mode 19600/19700, which are slower.
