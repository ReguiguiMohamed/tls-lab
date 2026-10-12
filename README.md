# From cleartext to TLS

A reproducible lab that compares Telnet, HTTP, SSH and TLS in Wireshark, with an automatic check for every observation.

Cybersecurity project by Mohamed Reguigui and Firas Taktak, due 15 November 2026. The full plan, method and sources are in [PLAN.md](PLAN.md).

Clients, servers and captures share one loopback interface on Debian-family Linux. One command creates the certificates, starts each service, captures the session, then uses TShark to check what is readable and what is not.

## Run it

Pick one route. Both run the same `lab.sh` and print `0 failure(s)` on the last line.

**Docker (reference, also used by CI).** Needs [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/) running. The first run builds the image in a few minutes, later runs take about a minute.

```bash
git clone https://github.com/ReguiguiMohamed/tls-lab.git
```

```bash
cd tls-lab
```

```bash
docker compose run --rm lab
```

**Kali or Debian in [WSL](https://learn.microsoft.com/windows/wsl/install).** No Docker needed. `setup.sh` installs the tools and the `labuser` test account once, then the lab runs as root.

```bash
sudo bash setup.sh
```

```bash
sudo bash lab.sh
```

One or more tests by name:

```bash
docker compose run --rm lab bash lab.sh tls13 tls12
```

```bash
sudo bash lab.sh tls13 tls12
```

To open the captures on Windows, install Wireshark:

```bash
winget install WiresharkFoundation.Wireshark
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

The TLS 1.3 and TLS 1.2 servers share one RSA key. It decrypts the TLS 1.2 session and not the TLS 1.3 one, which isolates the effect of static RSA key exchange.

## Output

| File | Content |
| --- | --- |
| `out/results.txt` | One `PASS` or `FAIL` line per check. |
| `out/captures/*.pcapng` | One original capture per test, without embedded secrets. |
| `out/captures/tls13-with-keys.pcapng` | The TLS 1.3 session with its key log embedded, so it opens already decrypted. |
| `out/evidence/` | Tool versions, client outputs, fake server log, testssl.sh reports. |
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
| [`setup.sh`](setup.sh) | Packages and test account, shared by Docker and Kali. |
| [`Dockerfile`](Dockerfile), [`compose.yaml`](compose.yaml) | Debian 13 pinned by digest, run without a network. |
| [`config/`](config/) | `inetd.conf` for Telnet, `sshd_config` for the lab's SSH instance. |
| [`fixtures/www/`](fixtures/www/) | Witness file `PROJET_TLS_MOHAMED_FIRAS`. |
| [`.github/workflows/lab.yml`](.github/workflows/lab.yml) | Replays the lab on every push and keeps `out/` as an artifact. |
| [`AGENTS.md`](AGENTS.md) | Rules for AI assistants. |

## Built with

OpenSSL, OpenSSH, inetutils telnetd, Python `http.server`, curl, TShark and dumpcap, testssl.sh, all from Debian 13 or Kali packages. Each run records the exact versions in `out/evidence/versions.txt`.
