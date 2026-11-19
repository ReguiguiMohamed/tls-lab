# Own the TLS interception lab

This is a separate start-to-finish segment for `GUIDE-tls-lab.md`. It uses the same server, witness file, Kali terminals and Wireshark workflow. Commands below are Bash commands inside Kali, except where Windows is named.

Goal: read a real HTTPS exchange in mitmweb, edit its response before delivery, and explain why a public-key pin blocks that proxy.

## 1. The story

The original server sends `PROJET_TLS_MOHAMED_FIRAS`. A proxy sits between curl and that server. It opens two separate TLS connections:

```text
curl client <-- TLS 1.3 --> mitmproxy <-- TLS 1.3 --> OpenSSL server
                             |                       127.0.0.1:8470
                      listens on :8471
                      reads and edits HTTP
                             |
                      mitmweb on :8472
```

The proxy can read the messages because it is an endpoint of both connections. It decrypts a response received from the server, edits the readable text, then encrypts the edited response for curl. TLS protects each connection. It does not protect a message from an endpoint that handles it.

The client accepts the proxy certificate only when we supply the proxy CA. We then add another check: require the original server public key. That check rejects the proxy even though its CA is trusted.

Everything binds to `127.0.0.1`. This is explicit local reverse proxying. There is no network redirection, external target or global CA installation.

## 2. Install and run the automatic version

From Windows Terminal:

```powershell
wsl -d kali-linux
```

In Kali:

```bash
cd /mnt/c/Users/ahmed/Downloads/I2-class/Cours26-27/cybersec/Projet
sudo bash setup.sh
mitmdump --version
```

`setup.sh` installs the lab packages, including mitmproxy. The tested package was `12.2.3-0kali4`. Its runtime reported Python 3.14.7 and OpenSSL 3.6.3. No GitHub build or Python package installation is needed.

The following full run recreates `out/`, including its keys and captures. Save any previous output you want to keep before running it.

```bash
sudo bash lab.sh
```

The tested run on 26 October 2026 finished with 46 PASS entries and `0 failure(s)`. The last eight checks belong to `mitm`.

To rerun only this test with the prepared certificates:

```bash
sudo bash lab.sh mitm
cat out/evidence/mitm-status.txt
cat out/evidence/mitm-direct.txt
cat out/evidence/mitm-trusted.txt
```

Expected status file:

```text
untrusted=60
trusted=0
pinned=90
```

The direct file contains the original witness. The trusted-proxy file contains `MODIFIED_IN_TRANSIT`. curl checks certificates in all three proxy cases. No `--insecure` option is used.

| Saved file | Meaning |
| --- | --- |
| `out/captures/mitm.pcapng` | Both proxy legs, without embedded secrets. |
| `out/secrets/mitm.keys` | Proxy-exported TLS secrets for both legs. |
| `out/evidence/mitm.flows` | The completed HTTP flow, for mitmweb. This is not a packet capture. |
| `out/evidence/mitm-status.txt` | The three curl exit codes. |
| `out/evidence/mitm-*-client.txt` | Client diagnostics. |
| `out/evidence/mitm-server-public.pem` | The original server's public key, used as the pin. |
| `out/secrets/mitmproxy/` | The proxy's separate, disposable CA and private keys. |

## 3. Open the automatic result in mitmweb

This is the shortest visual replay. The automatic test has already stopped its server and proxy.

```bash
mitmweb --no-server -r out/evidence/mitm.flows \
  --web-host 127.0.0.1 --web-port 8472 \
  --set confdir="$PWD/out/secrets/mitmproxy" \
  --set web_open_browser=false
```

Open the `http://127.0.0.1:8472/?token=...` URL printed in that terminal in your Windows browser. Use the actual token from your run. `--no-server` starts a viewer without a listening interception proxy. `-r` loads saved HTTP flows.

Click the `/witness.txt` flow, then **Response**. Its body is `MODIFIED_IN_TRANSIT`. The **Request** tab shows the readable GET and headers. The **Connection** tab shows the client and server sides.

This reopens a recorded result. Follow the next sections to perform the edit live. Stop this viewer with **Ctrl+C** before starting another instance on port 8472.

## 4. Prepare the manual terminals

Open four Kali tabs. In each one:

```bash
cd /mnt/c/Users/ahmed/Downloads/I2-class/Cours26-27/cybersec/Projet
sudo -s
```

| Tab | Role |
| --- | --- |
| **S** | Original OpenSSL server. |
| **P** | Interception proxy and mitmweb. |
| **C** | Loopback packet capture. |
| **K** | curl client and evidence checks. |

In **K**:

```bash
mkdir -p out/manual-mitm
openssl x509 -in out/secrets/server.crt -pubkey -noout \
  > out/manual-mitm/server-public.pem
```

The certificate and CA come from the automatic run in section 2. `-pubkey -noout` extracts only the server's public key. This PEM file is the pin. It contains no private key.

Manual files stay in `out/manual-mitm/`. A later full `lab.sh` run replaces that directory along with the rest of `out/`.

## 5. Start the original server

In **S**:

```bash
cd fixtures/www
openssl s_server -quiet -accept 127.0.0.1:8470 \
  -tls1_3 -alpn http/1.1 -WWW \
  -cert ../../out/secrets/server.crt \
  -key ../../out/secrets/server.key
```

| Piece | Meaning |
| --- | --- |
| `-accept 127.0.0.1:8470` | Listen on this machine only, on port 8470. |
| `-tls1_3` | Use TLS 1.3 for this server. |
| `-alpn http/1.1` | Agree that the protected application is HTTP/1.1. This also helps Wireshark decode it. |
| `-WWW` | Serve files from the current folder. |
| `-cert`, `-key` | Present the original public certificate and use its matching private key. |

The server still serves the original `witness.txt`. The proxy will change a response in memory, not this file.

## 6. Start the live proxy

In **P**, from the repository root:

```bash
SSLKEYLOGFILE="$PWD/out/manual-mitm/session.keys" \
mitmweb --mode reverse:https://127.0.0.1:8470 \
  --listen-host 127.0.0.1 --listen-port 8471 \
  --web-host 127.0.0.1 --web-port 8472 \
  --set web_open_browser=false \
  --set confdir="$PWD/out/secrets/mitmproxy" \
  --set ssl_verify_upstream_trusted_ca="$PWD/out/secrets/ca.crt" \
  --set tls_version_client_min=TLS1_3 \
  --set tls_version_server_min=TLS1_3 \
  -w out/manual-mitm/flows.mitm
```

Open the token URL printed in **P** in your Windows browser. The page should say **mitmproxy is running** and show proxy address `127.0.0.1:8471`. Port 8472 is the control page. Port 8471 carries the client's intercepted HTTPS traffic.

| Piece | Meaning |
| --- | --- |
| `reverse:https://127.0.0.1:8470` | Forward requests to our fixed HTTPS server. |
| `--listen-host`, `--listen-port` | Bind the interception proxy to loopback. |
| `--web-host`, `--web-port` | Bind the browser interface to loopback on a separate port. |
| `confdir` | Keep this lab's proxy CA in the ignored secrets folder. |
| `ssl_verify_upstream_trusted_ca` | The proxy checks the original server against our Lab CA. |
| `tls_version_client_min`, `tls_version_server_min` | Require at least TLS 1.3 on both sides. |
| `SSLKEYLOGFILE` | Export the proxy's connection secrets for later Wireshark analysis. |
| `-w` | Log observed HTTP flows. Use **File, Save** below to export the final manual edit. |

The proxy CA and Lab CA have different jobs. The proxy trusts the Lab CA when it contacts the server. curl will decide separately whether to trust the proxy CA.

## 7. Start the capture and check the direct route

In **C**:

```bash
dumpcap -i lo -f 'tcp port 8470 or tcp port 8471' \
  -w out/manual-mitm/mitm.pcapng
```

This excludes the mitmweb control page on port 8472.

In **K**:

```bash
curl -4 --noproxy '*' --http1.1 --tlsv1.3 --tls-max 1.3 \
  --cacert out/secrets/ca.crt \
  --pinnedpubkey out/manual-mitm/server-public.pem \
  https://127.0.0.1:8470/witness.txt
echo $?
```

Expected: `PROJET_TLS_MOHAMED_FIRAS`, then exit code `0`. This proves that the extracted pin works with the real server before we try it against the proxy.

`--noproxy '*'` prevents an environment proxy setting from changing the route. `--http1.1` keeps the application exchange easy to compare. The two TLS options force TLS 1.3. `--pinnedpubkey` requires the server to present this public key as well as a valid certificate.

Run `echo $?` immediately after a curl command. It prints that command's exit code. Running another command first replaces the code.

## 8. Reject the untrusted proxy

In **K**:

```bash
curl -4 --noproxy '*' --http1.1 --tlsv1.3 --tls-max 1.3 \
  --cacert out/secrets/ca.crt \
  --resolve localhost:8471:127.0.0.1 \
  https://localhost:8471/witness.txt
echo $?
```

Expected: a certificate error and exit code **60**. The client asked for `localhost`, but the proxy's certificate is signed by an issuer outside the supplied Lab CA trust.

`--resolve` sends the connection to `127.0.0.1` while keeping `localhost` as the HTTPS name to check. Certificate verification stays enabled.

The proxy can already contact the original server to inspect its certificate. A failed client connection does not mean zero network traffic. It means curl did not submit its HTTP request through an authenticated TLS connection.

## 9. Trust the proxy and change the response live

In mitmweb, open **Flow List**. Find the **Intercept** field beside the pause icon. Enter `~s` and press **Enter**. `~s` means pause responses. The bottom bar should show `Intercept: ~s`.

In **K**:

```bash
curl -4 --noproxy '*' --http1.1 --tlsv1.3 --tls-max 1.3 \
  --max-time 300 \
  --cacert out/secrets/mitmproxy/mitmproxy-ca-cert.pem \
  --resolve localhost:8471:127.0.0.1 \
  -o out/manual-mitm/trusted.txt \
  https://localhost:8471/witness.txt
```

curl waits. The response is paused in the proxy. The five-minute limit gives you time to edit it.

In mitmweb:

1. Click the new `/witness.txt` row with the pause icon.
2. Select **Response**. The original body is `PROJET_TLS_MOHAMED_FIRAS`.
3. Click **Edit** beside the response body.
4. Click inside the body editor. Press **Ctrl+A** and type `MODIFIED_IN_TRANSIT`.
5. Click **Done**. The displayed body changes, and mitmweb sets the new `content-length`.
6. Click **Resume** in the top toolbar.

In **K**, after curl finishes:

```bash
echo $?
cat out/manual-mitm/trusted.txt
printf '\n'
```

Expected: exit code **0** and `MODIFIED_IN_TRANSIT`. The file may have no final newline. The `printf` only separates your shell prompt from the displayed text.

Take a screenshot of the response panel and the client output. The source file remains unchanged:

```bash
cat fixtures/www/witness.txt
```

It still contains `PROJET_TLS_MOHAMED_FIRAS`. `t_mitm()` checks original delivery through a direct connection and compares the original and modified responses in the captured proxy connections.

## 10. Keep that CA trusted, but pin the real server key

In **K**:

```bash
curl -4 --noproxy '*' --http1.1 --tlsv1.3 --tls-max 1.3 \
  --cacert out/secrets/mitmproxy/mitmproxy-ca-cert.pem \
  --pinnedpubkey out/manual-mitm/server-public.pem \
  --resolve localhost:8471:127.0.0.1 \
  https://localhost:8471/witness.txt
echo $?
```

Expected: `SSL: public key does not match pinned public key`, then exit code **90**. The trusted signature passes, but the key check fails. This request does not reach the response-editing stage, so it does not need **Resume**.

The proxy presented a certificate containing its own key. Trusting its CA did not give it the original server's private key. A pinned key adds a specific identity requirement to the broader CA check.

Before stopping the proxy, choose **File, Save** in mitmweb. It downloads a file named `flows`. Save or move that downloaded file to this Windows path, naming it `edited.flows`:

```text
C:\Users\ahmed\Downloads\I2-class\Cours26-27\cybersec\Projet\out\manual-mitm\edited.flows
```

This export contains the current edited response. The `-w` stream log can contain the response from before the pause and edit. The export is the file to reopen for your manual demonstration.

## 11. Stop and inspect the packets

Stop **C** with **Ctrl+C** first. Then stop **P** and **S** with **Ctrl+C**. This finishes the capture and closes the proxy's stream log. Return **S** to the repository root with `cd ../..`.

The manual capture is at this Windows path:

```text
C:\Users\ahmed\Downloads\I2-class\Cours26-27\cybersec\Projet\out\manual-mitm\mitm.pcapng
```

Open it in Wireshark. For each custom port, right-click a packet, **Decode As**, and choose **TLS** for ports **8470** and **8471**.

### View A. Without secrets

Use a Wireshark profile with no TLS key log or RSA key configured. Filter:

```text
tls.handshake.type == 2
```

Inspect a Server Hello from each source port. Expand **Supported Versions**. Both negotiated TLS 1.3, value `0x0304`. Filter `tcp.port == 8470` for the server leg or `tcp.port == 8471` for the client leg. The HTTP content is encrypted.

### View B. With the proxy's exported secrets

Open **Edit, Preferences, Protocols, TLS**. Set **(Pre)-Master-Secret log filename** to:

```text
C:\Users\ahmed\Downloads\I2-class\Cours26-27\cybersec\Projet\out\manual-mitm\session.keys
```

Find the successful server connection on port 8470. Right-click its application data and choose **Follow, TLS Stream**. Its response contains the original witness. Do the same for the successful client connection on port 8471. Its response contains the edited marker.

The manual capture also includes your direct control request and failed attempts. Choose a stream containing an HTTP GET and response. Use the stream selector if you opened a certificate-only failed connection.

To locate the response frames from **K**, these commands work from the repository root:

```bash
tshark -r out/manual-mitm/mitm.pcapng \
  -d tcp.port==8470,tls -d tcp.port==8471,tls \
  -o tls.keylog_file:out/manual-mitm/session.keys \
  -o http.desegment_body:FALSE \
  -Y 'tcp.srcport == 8470 && http.file_data contains "PROJET_TLS_MOHAMED_FIRAS"' \
  -T fields -e frame.number -e tcp.stream
```

```bash
tshark -r out/manual-mitm/mitm.pcapng \
  -d tcp.port==8470,tls -d tcp.port==8471,tls \
  -o tls.keylog_file:out/manual-mitm/session.keys \
  -o http.desegment_body:TRUE \
  -Y 'tcp.srcport == 8471 && http.file_data contains "MODIFIED_IN_TRANSIT"' \
  -T fields -e frame.number -e tcp.stream
```

The printed frame and stream numbers depend on your run. On the server leg, `http.desegment_body:FALSE` exposes body bytes directly because OpenSSL's HTTP/1.0 response has no Content-Length. On the manually edited client leg, `TRUE` joins the separate header and body records using the Content-Length set by mitmweb. Following the TLS stream displays either body without relying on HTTP body reassembly.

For the automatic capture, use `out/captures/mitm.pcapng` and `out/secrets/mitm.keys` instead. Clear the TLS key-log preference when finished so it does not affect later observations.

## 12. Reopen the manual flow without restarting the demo

```bash
mitmweb --no-server -r out/manual-mitm/edited.flows \
  --web-host 127.0.0.1 --web-port 8472 \
  --set confdir="$PWD/out/secrets/mitmproxy" \
  --set web_open_browser=false
```

Open its newly printed token URL. The flow file contains HTTP messages. The PCAPNG contains network packets. The key log contains secret material used to decrypt those packets. These three files have different purposes.

## 13. How `lab.sh` automates it

`t_mitm()` uses `mitmdump`, the command-line version of the same proxy. It loads the project's response addon:

```text
-s config/modify_response.py
```

The addon's `response` hook replaces the witness text in the response body. It performs the edit that you made with **Edit, Done, Resume**.

| Automatic check | What it establishes |
| --- | --- |
| Direct request succeeds with the original pin. | The expected key is correct and the original server delivers the file. |
| Untrusted proxy returns code 60. | The original Lab CA does not authorize the proxy's certificate. |
| Trusted proxy returns the edited marker with code 0. | Explicit proxy trust permits the edited response. |
| Pinned proxy request returns code 90 and no body. | The expected public key blocks that proxy. |
| Server Hello on both ports selects `0x0304`. | Both proxy legs negotiated TLS 1.3. |
| Neither marker occurs in the original capture bytes. | The saved wire capture does not expose either text in clear. |
| With the key log, port 8470 contains the original. | The original server sent the witness through TLS. |
| With the key log, port 8471 contains the replacement. | The proxy sent the modified response through another TLS connection. |

## 14. Questions to answer without notes

1. **Did the proxy break TLS encryption?** It terminated two connections and handled their readable messages. Each connection still used TLS.
2. **Why did the client accept a replacement certificate?** We explicitly supplied the proxy CA to that curl invocation. Its certificate then met the chosen trust policy.
3. **Why was no global CA installation needed?** `--cacert` supplies trust to one curl transfer. The operating system trust store stays unchanged.
4. **Why did pinning stop it?** The proxy certificate contains a different public key from the original server's key.
5. **Why did changing the text not trigger a TLS integrity failure?** The proxy changed readable data between two TLS connections. It encrypted a fresh, valid message for the client.
6. **Why does Wireshark need the key log when mitmweb does not?** The proxy owns both connection contexts. An outside packet reader needs exported secrets to reconstruct their content.
7. **How is this different from the earlier fake server?** Here the proxy forwards requests to the real server, receives its real response, edits it and forwards the replacement.

## 15. If something differs

| Symptom | Check |
| --- | --- |
| Port already in use. | Stop the earlier server or viewer in its own terminal before restarting. Use `ss -ltnp` to identify it. |
| Browser shows 403 Authentication Required. | Open the full token URL printed by the current mitmweb process. A restart can change it. |
| curl waits. | With `~s` active, this is expected until you press **Resume**. |
| curl returns code 28. | The editing timeout expired. Issue another trusted request and edit the new paused flow. |
| Trusted proxy request still returns code 60. | Use the public `mitmproxy-ca-cert.pem` from this run's `out/secrets/mitmproxy/` directory. |
| Proxy reports upstream verification failure. | Its upstream trust option must point to the current `out/secrets/ca.crt`. A full run regenerates the CA and server certificate. |
| Pin also fails on the direct server. | Re-extract the public key after regenerating certificates. Run the direct control again. |
| Reopened manual flow still contains the original text. | Export with **File, Save** after the edit and reopen `edited.flows`. The `-w` stream log can contain the response from before the edit. |
| Wireshark decrypts but shows no HTTP body. | Use **Follow TLS Stream**, or the TShark commands with HTTP body reassembly disabled. |

## Sources

The implementation uses mitmproxy's documented [reverse mode](https://docs.mitmproxy.org/stable/concepts/modes/#reverse-proxy), [body modification](https://docs.mitmproxy.org/stable/overview/features/#modify-body), and [certificate handling](https://docs.mitmproxy.org/stable/concepts/certificates/). curl documents [public-key pinning](https://curl.se/docs/manpage.html#--pinnedpubkey). Exact installed options and the packet fields were checked on this Kali installation.
