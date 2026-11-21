# From cleartext to TLS

Telnet, HTTP, SSH and TLS compared in Wireshark, with a TShark check for every observation.

Mohamed Reguigui and Firas Taktak.

## Run

On Kali Linux:

```bash
git clone https://github.com/ReguiguiMohamed/tls-lab.git
cd tls-lab
sudo bash setup.sh
sudo bash lab.sh
```

The last line reads `0 failure(s)`. Run one test with `sudo bash lab.sh tls13`.

## Tests

| Test | Port | Check |
| --- | --- | --- |
| `ping` | ICMP | 3 replies. |
| `telnet` | 2323 | Password and witness text readable. |
| `http` | 8080 | Request and witness text readable. |
| `ssh` | 2222 | Witness text absent. |
| `tls13` | 8443 | Text absent, readable with the key log only. |
| `tls12` | 8444 | Static RSA. The server key decrypts the session. |
| `fake` | 9443 | Fake certificate rejected. Accepted with `--insecure`. |
| `versions` | 8450-8453 | TLS 1.0 to 1.3 negotiated. |
| `bot` | 8460 | JA4 exposes curl and Python posing as Firefox. |
| `mitm` | 8470, 8471 | A trusted proxy rewrites the response. A pin stops it. |
| `mtls` | 8480 | Only a client certificate from the lab CA is accepted. |

## Output

| Path | Content |
| --- | --- |
| `out/results.txt` | One `PASS` or `FAIL` per check. |
| `out/captures/` | One capture per test. |
| `out/evidence/` | Tool versions and client outputs. |
| `out/secrets/` | Throwaway CA, keys and key log. |

To decrypt in Wireshark, set Preferences, Protocols, TLS, (Pre)-Master-Secret log filename to `out/secrets/tls13.keys`, or add `out/secrets/server.key` to the RSA keys list for `tls12-rsa.pcapng`.

## Built with

OpenSSL, OpenSSH, telnetd, Python, curl, TShark, testssl.sh and mitmproxy.
