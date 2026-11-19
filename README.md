# From cleartext to TLS

A reproducible lab that compares Telnet, HTTP, SSH and TLS in Wireshark, with an automatic check for every observation.

Cybersecurity project by Mohamed Reguigui and Firas Taktak. The full plan, method and sources are in [PLAN.md](PLAN.md).

Clients and servers exchange traffic in a Kali WSL lab on one machine. One command creates the certificates, starts each service, captures the session, then uses TShark to check what is readable and what is not.

Study the certificate and TLS tests with the [plain-English guide](docs/TLS-GUIDE.md) and its [editable Excalidraw board](docs/tls-explained.excalidraw). A [browser-readable SVG](docs/tls-explained.svg) is also available.

## Run it

The lab runs in [Kali under WSL](https://www.kali.org/docs/wsl/wsl-preparations/). Clone the repository on the Windows side, so Wireshark opens `out\` directly and the lab's test account can read the witness file.

1. Install Kali and Wireshark on Windows, once:

```bash
wsl --install -d kali-linux
```

```bash
winget install WiresharkFoundation.Wireshark
```

2. Clone the repository from Windows:

```bash
git clone https://github.com/ReguiguiMohamed/tls-lab.git
```

3. Open Kali in that folder. WSL starts in the current Windows directory:

```bash
cd tls-lab
```

```bash
wsl -d kali-linux
```

4. Install the tools and the `labuser` test account, once:

```bash
sudo bash setup.sh
```

5. Run every test. The last line must read `0 failure(s)`, after about 90 seconds:

```bash
sudo bash lab.sh
```

One or more tests by name:

```bash
sudo bash lab.sh tls13 tls12
```

## Tests

| Test | Port | What `lab.sh` checks |
| --- | --- | --- |
| `ping` | ICMP | 3 replies on `lo`. |
| `telnet` | 2323 | Username, password and witness text readable in the capture. |
| `http` | 8080 | `GET` request and witness text readable, received file identical. |
| `ssh` | 2222 | Host key verified, session opened, `SSH-2.0` banner visible, witness text absent. |
| `tls13` | 8443 | Certificate and name verified, TLS 1.3 negotiated, text absent without secrets and with the RSA key alone, present with the key log. |
| `tls12` | 8444 | Suite `TLS_RSA_WITH_AES_128_GCM_SHA256`, past session decrypted with the server's private key, testssl.sh reports no forward secrecy. |
| `fake` | 9443 | The verifying client rejects the fake certificate and sends nothing. With `--insecure`, the fake server receives the witness text. |
| `versions` | 8450-8453 | TLS 1.0, 1.1, 1.2 and 1.3 negotiated. The certificate is readable up to TLS 1.2 and encrypted in TLS 1.3. curl refuses TLS 1.0 by default. This OpenSSL has no SSL 3.0. |
| `bot` | 8460 | curl and Python keep their JA4 fingerprint when they claim a Firefox User-Agent. A detector that compares the two flags both fake browsers. |
| `mitm` | 8470, 8471 | A trusted TLS proxy changes the response. An untrusted proxy is rejected. Pinning the original server public key rejects the proxy even when its CA is trusted. Both legs use TLS 1.3. |
| `mtls` | 8480 | The server rejects a client with no certificate or an untrusted certificate. A client with a Lab CA certificate receives the file. |

The TLS 1.3 and TLS 1.2 servers share one RSA key. It decrypts the TLS 1.2 session and not the TLS 1.3 one, which isolates the effect of static RSA key exchange.

The [interception and pinning guide](docs/GUIDE-mitmproxy.md) explains the `mitm` test, manual commands, mitmweb and the two Wireshark views. Run it alone with `sudo bash lab.sh mitm`.

Run mutual TLS alone with `sudo bash lab.sh mtls`. The client verifies the server certificate and the server requires a client certificate signed by the Lab CA. Results and client errors are in `out/evidence/mtls-*.txt`, and the capture is `out/captures/mtls.pcapng`.

## Output

| File | Content |
| --- | --- |
| `out/results.txt` | One `PASS` or `FAIL` line per check. |
| `out/captures/*.pcapng` | One original capture per test, without embedded secrets. |
| `out/captures/tls13-with-keys.pcapng` | The TLS 1.3 session with its key log embedded, so it opens already decrypted. |
| `out/evidence/` | Tool versions, client outputs, fake server log, testssl.sh reports, JA4 per connection and the detector's verdicts. |
| `out/evidence/mitm.flows` | The completed intercepted HTTP flow, readable in mitmweb. |
| `out/secrets/` | The lab's throwaway CA, keys and key log, regenerated on every run. |

## Wireshark on Windows

These steps follow the [Wireshark TLS wiki](https://wiki.wireshark.org/TLS/).

1. **Telnet and HTTP.** Open the capture, right-click a packet, Follow, TCP Stream.
2. **TLS 1.3 without secrets.** Open `tls13.pcapng`: handshake visible, Application Data unreadable.
3. **TLS 1.3 with secrets.** Open `tls13-with-keys.pcapng`, or set Edit, Preferences, Protocols, TLS, (Pre)-Master-Secret log filename to `out\secrets\tls13.keys`.
4. **TLS 1.2 static RSA.** In Edit, Preferences, Protocols, TLS, RSA keys list, add `out\secrets\server.key`, then open `tls12-rsa.pcapng`.

Clear both TLS settings before the next observations, or use one Wireshark profile per test.

## Repository

| Path | Content |
| --- | --- |
| [`lab.sh`](lab.sh) | Setup, services, captures and checks, one function per test. |
| [`setup.sh`](setup.sh) | Packages and the `labuser` test account. |
| [`config/`](config/) | `inetd.conf` for Telnet, `sshd_config` for the lab's SSH instance. |
| [`config/modify_response.py`](config/modify_response.py) | mitmproxy addon that replaces the witness text in responses. |
| [`fixtures/www/`](fixtures/www/) | Witness file `PROJET_TLS_MOHAMED_FIRAS`. |
| [`.github/workflows/lab.yml`](.github/workflows/lab.yml) | Replays the lab in a Kali image on every push and keeps `out/` as an artifact. |
| [`AGENTS.md`](AGENTS.md) | Rules for AI assistants. |

## Built with

OpenSSL, OpenSSH, inetutils telnetd, Python `http.server`, curl, TShark and dumpcap, testssl.sh and mitmproxy, all from Kali packages. Each run records the exact versions in `out/evidence/versions.txt`.
