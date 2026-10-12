# From cleartext to TLS: a hands-on comparison of client-server traffic

**Team: Mohamed and Firas. Due: 15 November 2026.**

This document replaces the earlier SilentTrace plans. The project follows the professor's new brief: set up client-server communications, examine them in Wireshark, show what unencrypted protocols expose, and explain the protections, conditions of use and limits of TLS. Machine learning, padding and cover traffic are out of scope.

## 1. Scenario

Mohamed and Firas use a client to connect to a lab server and exchange an identifiable fake text, `PROJET_TLS_MOHAMED_FIRAS`. They first run a Telnet session and an HTTP request, and Wireshark recovers the data in clear. They then repeat the exchanges with SSH and with HTTPS over TLS 1.3, and look at what stays visible: addresses, ports, negotiation and volumes. The main part covers TLS: verified certificate, handshake, data encryption, authorized decryption with session secrets, and what follows from a bad configuration or from a key compromised under an old configuration.

We use existing implementations. Our work is a reproducible lab, commented configurations, the tests, and an explanation of the captures.

## 2. Protocols

| Communication | Practical goal | Expected observation |
| --- | --- | --- |
| Classic Telnet | Log in with a temporary lab account and send the witness text. | Credentials and commands can be rebuilt in clear from the stream. |
| HTTP | Download a small text file from a local server. | Method, path, headers and content readable. |
| SSH | Open a session with OpenSSH and print the same witness text. | Initial identification and negotiation visible, session content encrypted. |
| HTTPS / TLS 1.3 | Download the file over an authenticated, encrypted connection. | Handshake and TLS traffic visible, HTTP content out of reach for a plain observer without secrets. |

Telnet and SSH compare remote access. HTTP and HTTPS compare the same application use with and without TLS. TLS is a protection layer, not an application on par with Telnet. Modern SSH is a secure protocol too, and we will not present it as weak.

These four cases are enough. FTP, old SSL, VPNs and other protocols are not needed to finish the project.

## 3. Architecture

The lab runs on Debian-family Linux, through one of two routes that use the same scripts:

| Route | Command | When to use it |
| --- | --- | --- |
| Docker | `docker compose run --rm lab` | Reference. Same image for Mohamed, Firas and GitHub Actions, nothing installed on the system, no network. |
| Kali WSL | `sudo bash setup.sh` once, then `sudo bash lab.sh` | Already installed on Mohamed's PC, handy for exploring by hand during the defense. |

`setup.sh` holds the package list and the test account, and the `Dockerfile` runs it, so both routes install the same tools. Docker pins the Debian 13 base image and runs without a network. Kali is a rolling distro: its versions move ahead of Debian 13 and the system keeps the packages and the `labuser` account.

```text
Docker container or Kali WSL, loopback only

Telnet client -------- TCP/2323 -----> Telnet server
OpenSSH client ------- TCP/2222 -----> lab OpenSSH instance
curl client ---------- TCP/8080 -----> HTTP server
OpenSSL client ------- TCP/8443 -----> HTTPS / TLS 1.3 server
OpenSSL client ------- TCP/8444 -----> TLS 1.2 / static RSA server
Test client ---------- TCP/9443 -----> fake server with an untrusted certificate

                 Capture on the loopback interface
                               |
                         PCAPNG files
                               |
                    analysis in Wireshark
```

Services listen on `127.0.0.1` on high ports to avoid conflicts. The loopback capture observes real TCP exchanges on the same computer. The report must say so, and must not present this topology as interception on an external network.

dumpcap captures inside the Linux side. Files land in `out/captures/` and open in Wireshark on Windows, which cannot see the Linux loopback itself.

The `labuser` test account has no privileges and a fake password. The Telnet and SSH configurations belong to the lab. `lab.sh` starts each service for its test and stops it afterwards.

## 4. Tools and their exact role

| Tool | Use |
| --- | --- |
| Wireshark | Examine the protocols, follow streams and decrypt TLS when given the needed secrets. |
| dumpcap and TShark | Record the exchanges and check every observation automatically. |
| OpenSSL | Generate the test certificates and run TLS connections with `s_server` and `s_client`. |
| OpenSSH | Provide a real SSH session, with host key verification. |
| inetutils telnet and telnetd, started by inetd | Provide a real classic Telnet session rather than a bare TCP socket. |
| Python `http.server` | Serve the witness file over HTTP. |
| curl | Test HTTP and HTTPS with certificate verification. |
| testssl.sh | Check the versions and suites offered by our own TLS servers. It audits, it does not decrypt. |

We use the installed versions and record them. No home-made cryptographic code is needed.

## 5. Reading, decoding and decrypting

The report and the defense must keep these apart:

- **Classic Telnet and HTTP: reading in clear.** Wireshark rebuilds data that was never encrypted. This is not a cryptographic attack.
- **Base64: decoding.** If we show an HTTP Basic example, recovering `user:password` means decoding an encoding, not breaking encryption. The core does not need this example.
- **TLS with provided secrets: authorized decryption.** Wireshark is given secret data from a lab endpoint.
- **TLS with static RSA and a compromised private key: retrospective decryption.** This shows that configuration lacks forward secrecy.

We do not claim to break modern TLS or SSH from a capture alone. [1][2]

## 6. Tests

### Test 1 - Connectivity and capture

Run `ping 127.0.0.1`. Identify the loopback interface and record a first capture. Check that the file opens in Wireshark and that the packets are there. Ping proves local connectivity, not security.

### Test 2 - Telnet: recover the exposed data

Start a local Telnet instance, log in with the temporary account and print the witness text. Capture the whole connection. Use Follow TCP Stream to rebuild the exchange, including input split over several packets.

Deliver an annotated capture of the login and the witness text. Check that they are really there before concluding. A password hidden in the terminal is not necessarily protected on the network.

### Test 3 - HTTP: recover the request and the file

Start the HTTP server in a folder that holds only the demo file. Download it with curl. Show the GET method, the requested path, the response and the witness text.

Deliver a capture and a check that the received file matches the sent file.

### Test 4 - SSH: observe a protected session

Start an OpenSSH instance with the project's configuration file on port 2222. Compare its key fingerprint with the one presented to the client before accepting it. Open the session and print the witness text.

Show the protocol identification, the negotiation and the encrypted packets. Explain that TLS and SSH use different mechanisms. SSH can be secure without an X.509 certificate. We do not try to decrypt this SSH session. [2]

### Test 5 - TLS 1.3: the main case

Create a local certificate with a Subject Alternative Name for `localhost`, then declare it explicitly as the client's trusted certificate for the lab. Do not touch the global Windows trust store.

Serve the same file over HTTPS with OpenSSL. The client checks both the certificate's trust and the server name. With `s_client`, enable `-verify_return_error` and `-verify_hostname localhost` with the right trust file: without them, the diagnostic tool can carry on after a verification error. [3]

Capture the connection from its start. Show ClientHello, ServerHello, the negotiated version and cipher suite. In TLS 1.3 part of the handshake, including the server certificate, is encrypted. Do not promise to read that certificate in the passive capture: show it on the client side or after the authorized decryption of the next test. [4]

Check that the file arrives intact. With a Wireshark profile without keys and a capture without embedded secrets, the witness text is not readable in the application data.

### Test 6 - Wireshark decrypts TLS with the session secrets

Create a new TLS 1.3 session with the OpenSSL `-keylogfile` option. Load the secrets file in Wireshark's TLS settings and recover the request and the file content.

Show both views: without secrets, then with secrets. The conclusion is that security also depends on protecting the endpoints and the session secrets. This test does not show a weakness in TLS encryption. [1][3]

Keep the original capture without embedded secrets. Use separate Wireshark profiles so one test's keys do not skew the next observations. The demo keys stay clearly marked as throwaway lab secrets.

### Test 7 - Old TLS configuration: no forward secrecy

Start a dedicated TLS 1.2 server with an RSA certificate and **static RSA** key exchange, the OpenSSL suite `AES128-GCM-SHA256`, that is `TLS_RSA_WITH_AES_128_GCM_SHA256`. Force the same suite on the client and check the suite that gets negotiated. [1][3]

Capture a new complete connection, with no session resumption and no exported secrets. Then give Wireshark the server's RSA private key and recover the content of that past session.

The weakness shown is precise: if the server's private key is compromised, old recorded sessions can be decrypted under this configuration. This does not break AES, and it is not true of every TLS 1.2 configuration. A TLS 1.2 suite using ECDHE does not share this property. [1]

Repeat the comparison with our TLS 1.3 session, which uses an ephemeral exchange: the certificate's private key alone does not allow the same decryption. Use a session without a key log and a clean profile. Test 6 stays separate, because session secrets do allow decryption. [1][4]

OpenSSL 3.5 in the container negotiates suite `0x009c` without lowering its security level. The system-wide configuration is untouched. Cross-check: with the suite ECDHE-RSA-AES128-GCM-SHA256 on the same server, the same private key decrypts nothing.

### Test 8 - Bad certificate verification

Start a local fake server with another certificate outside the client's trust. A correctly configured client must refuse the connection before sending the witness data.

Repeat with verification deliberately turned off, `curl --insecure`, only against this lab server. Show that the fake server then receives the test text, even though the connection is encrypted. Then go back to the verifying client and show the refusal.

The conclusion is that encryption alone does not guarantee who the recipient is. This test shows the impersonation risk when verification is off. Without a transparent proxy or network redirection, we present it as a fake server test, not as a full MITM interception. [5]

## 7. What we will explain about TLS

**Strengths:** content confidentiality, data integrity, server authentication when the certificate and its name are verified correctly, and forward secrecy in our TLS 1.3 profile with ephemeral exchange. TLS 1.3 drops static RSA key exchange. [4]

**Conditions and limits:** an endpoint sees the data it handles, leaked session secrets allow decryption, disabled certificate verification removes an essential protection, and encryption does not hide all network metadata.

An RSA certificate does not imply static RSA key exchange. RSA can sign the handshake while ECDHE sets up the secrets. We must tell these two roles apart.

We do not call a correctly configured TLS 1.3 "weak". We show the differences between a cleartext protocol, an old cryptographic choice and the misuse of a modern protocol.

## 8. Split of work

| Mohamed | Firas |
| --- | --- |
| Prepare the OpenSSL profiles and local certificates. | Prepare the capture and the Wireshark profiles. |
| Set up TLS 1.3, TLS 1.2 static RSA and the fake server. | Set up Telnet, HTTP and the SSH instance with isolated configurations. |
| Check the clients, certificates and file delivery. | Annotate the captures and perform the Wireshark decryptions. |
| Write the architecture, how TLS works and the configuration notes. | Write the protocol comparison, results, screenshots and limits. |

Together: check every test, build the final table, prepare the slides and swap roles before the defense. Neither member should depend on the other to explain a test.

## 9. Evidence to keep

For each test: command, configuration, tool versions, full capture, a useful screenshot and the observed result. The "observed" columns stay empty until the test has been run.

| Test | Expected result | Evidence |
| --- | --- | --- |
| Ping | Local reply. | Terminal screenshot. |
| Telnet | Lab data readable. | Rebuilt TCP stream. |
| HTTP | Request and file readable. | Annotated HTTP capture. |
| SSH | Working session, encrypted content. | Terminal and SSH capture. |
| Verified TLS 1.3 | Connection accepted, file correct. | Client verification and capture without secrets. |
| TLS 1.3 + key log | Content decrypted with provided secrets. | Same session before and after loading the secrets. |
| TLS 1.2 static RSA | Old session decrypted with the server's private key. | Negotiated suite, capture and Wireshark result. |
| Fake certificate, verification on | Connection refused. | Client error and no witness text received. |
| Fake certificate, verification off | Data received by the fake server. | Client output and server-side reception. |

A text missing from a capture does not by itself prove the encryption is sound. We tie it to the negotiated configuration and to the documented behavior of the protocol.

## 10. Files

| Path | Content |
| --- | --- |
| `setup.sh` | Packages and test account, used by the `Dockerfile` and by Kali. |
| `Dockerfile`, `compose.yaml` | Container route. |
| `lab.sh` | Setup, services, captures and checks. |
| `config/` | The lab's `inetd.conf` and `sshd_config`. |
| `fixtures/www/` | Witness file served over HTTP and HTTPS. |
| `out/` | Generated by each run, kept out of the repository: `secrets/`, `captures/`, `evidence/`, `results.txt`. |

`lab.sh` regenerates the demo keys and certificates on each full run. Do not publish personal passwords, existing SSH keys or other projects' secrets. The only targets are the local services prepared for this work.

## 11. Schedule

| Dates | Work and exit criterion |
| --- | --- |
| 12-18 October | Check the tools, prepare the capture, run Ping, HTTP and TLS 1.3. The same file arrives in both modes. |
| 19-25 October | Add Telnet and SSH. All four communications work and have captures. |
| 26 October-1 November | Run the key log, static RSA and fake certificate tests. Document the conditions of each result. |
| 2-8 November | Finish the report, the comparison table and the slides. Freeze the configurations. |
| 9-14 November | Replay from a clean start, prepare backup captures and rehearse the questions. |
| 15 November | Submission and defense. |

If a tool demands a disproportionate setup, keep the test's goal and use the documented alternative. Do not add new protocol families.

## 12. Report and defense

The report follows the demo: goal, architecture, configurations, Telnet/HTTP, SSH, TLS 1.3, decryptions, fake certificate, conclusion and sources. It includes the requested Ping and Wireshark screenshots. TLS takes about half of the talk.

Talk outline: show data in clear, show the protected communication, explain the TLS handshake, decrypt with known secrets, compare static RSA with ephemeral exchange, and end with the fake certificate being refused or accepted depending on the client configuration.

Questions to master: encryption versus encoding, confidentiality versus authentication, certificate versus private key, TLS versus HTTPS, TLS versus SSH, session key versus certificate key, forward secrecy, passive reading versus fake server, and Wireshark's exact role.

The four grading items are covered: documented report, clear presentation, working services and tests, understanding of the concepts. Any external capture used as a backup must be announced as such.

## 13. Status on 12 October 2026

The lab runs in the container and `lab.sh` checks 27 observations, all passing in 57 seconds on Mohamed's PC. Versions recorded in `out/evidence/versions.txt`: OpenSSL 3.5.7, OpenSSH 10.0p1, inetutils-telnetd 2.6, curl 8.14.1, TShark 4.4.19, Python 3.13.5, testssl.sh 3.2.1.

The same checkout passes the same 27 checks natively in Kali 2026.2 under WSL, in 73 seconds, with OpenSSL 3.6.3, TShark 4.6.6, inetutils-telnetd 2.8 and testssl.sh 3.2.4.

Our TLS 1.3 server negotiates `TLS_AES_256_GCM_SHA384` with the post-quantum hybrid group `X25519MLKEM768`, OpenSSL 3.5's default. Wireshark decrypts this session with the key log like the others.

What remains is human work: annotated Wireshark screenshots, report, slides and rehearsal.

## 14. Technical sources

[1] [Wireshark: TLS and decryption conditions](https://wiki.wireshark.org/TLS/). Key logs, static RSA, ECDHE limits, TLS 1.3 and session resumption. Also provides teaching captures.

[2] [Wireshark: SSH](https://wiki.wireshark.org/SSH). Observable parts and encrypted content of an SSH session.

[3] [OpenSSL s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/) and [s_server](https://docs.openssl.org/3.0/man1/openssl-s_server/). Negotiation profiles, certificate verification and secret export.

[4] [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html). Handshake, data protection and cryptographic changes from older versions.

[5] [curl documentation](https://curl.se/docs/manpage.html). TLS verification, trust file and the effect of `--insecure`.

[6] [testssl.sh](https://github.com/testssl/testssl.sh). Audit of our servers' versions and suites. A scanner's results must be explained and do not replace the captures.

[7] [Wireshark user guide](https://www.wireshark.org/docs/wsug_html/). Capture, filters, stream following and TLS secrets.

[8] [OpenSSH](https://www.openssh.com/manual.html). Client and server configuration, host key verification.
