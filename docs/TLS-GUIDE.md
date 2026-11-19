# TLS, explained through this lab

Open [the editable board](tls-explained.excalidraw) in Excalidraw with **Open** or drag the file onto its canvas. Read panels 01 to 12, left to right. The [SVG copy](tls-explained.svg) opens in a browser without importing anything. This guide follows the same numbers and adds the explanations behind the drawings.

This is a study guide for the existing lab. The experiment results below come from the saved `out/results.txt` and the checks in [lab.sh](../lab.sh). They are not a new run. General explanations and analogies describe how the protocols work. They do not claim additional experiments.

## 01. What was connected to what?

A **client** asks for something. A **server** listens and answers. In the HTTP tests, curl is the client. The Python or OpenSSL process is the server. Both run inside the same Kali WSL machine.

`127.0.0.1` means this machine. **Loopback**, named `lo` in Kali, is the local path between its programs. A **port** is a numbered door that lets the machine deliver a message to the right program. Port 8443 leads to our TLS 1.3 server. Port 8444 leads to our TLS 1.2 server. Nothing has to cross your Wi-Fi or reach an external server.

A **packet** is a piece of a network conversation. dumpcap records those pieces. Wireshark can join them and display the conversation. Recording packets does not automatically reveal encrypted content.

HTTP and Telnet send readable data, like postcards. TLS stands for **Transport Layer Security**. It protects the messages exchanged by two programs. HTTPS is HTTP carried through that protection. SSL is TLS's older predecessor. Some tool labels still say SSL.

Picture a delivery box whose contents are locked, whose seal reveals changes, and whose recipient's ID has been checked. These correspond to **confidentiality** (outsiders cannot read the contents), **integrity** (changes are detected), and **authentication** (checking who the other end is). A box can still be delivered to a thief if you skip the ID check.

TLS protects a connection. The client and server still handle readable data. A valid certificate also does not promise that a website's content or owner is honest.

## 02. What are a key, RSA and a signature?

**Encryption** turns readable bytes into unreadable bytes using a key. **Decryption** reverses that with the appropriate key. A key is numerical data. It is not the account password you type.

**Symmetric encryption** uses shared secret key material. Think of two people with copies of a box key. It is fast enough for the HTTP request and the downloaded file. Our TLS tests use AES-GCM. AES encrypts. GCM also supplies a check, called an **authentication tag**, that lets the receiver detect changes. Actual TLS has separate traffic keys for the two directions. The single box key in the picture is a simplification.

**Asymmetric cryptography** uses a mathematically related public and private pair. Share the public part. Keep the private part secret. RSA is one such method, named after Rivest, Shamir and Adleman. `rsa:2048` asks OpenSSL to generate a 2048-bit RSA key pair.

One mathematical ingredient is easy to picture: `61 x 53 = 3233` is easy to calculate. Starting with a very large product and recovering its two secret prime factors is much harder. A **prime** is a whole number greater than one that divides only by one and itself. The tiny example is easy to solve and offers no security. Real RSA uses much larger numbers, suitable padding rules and more arithmetic. **Padding** is a prescribed way to format the input, including randomness for RSA encryption, before applying the mathematics. The example explains the idea, not the complete algorithm.

RSA has different uses. For encryption, picture a public open padlock that anyone can close, with an opening key only its owner keeps. For a **digital signature**, picture a seal that only the private-key holder can make but anyone with the public key can check. A digital signature is bound to the exact signed data. Copying one onto different data fails verification. Signing does not hide the data.

In our TLS 1.3 connection, the RSA server key proves identity by signing. A different mechanism establishes temporary secrets. In our deliberately chosen TLS 1.2 configuration, RSA instead encrypts the starting secret sent to the server. AES protects the application data in both cases.

## 03. What did certificate creation do?

This preparation creates files. It does not open a client-server connection. These commands are the certificate steps from `setup()` in `lab.sh`, with its path variables expanded. Read them as an explanation of that function. The script runs them from the repository root after creating `out/secrets/`.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=Lab CA TLS" \
  -keyout out/secrets/ca.key -out out/secrets/ca.crt
```

This makes our certificate office's private key, `ca.key`, and public certificate, `ca.crt`. A **certificate authority**, or **CA**, signs certificates for others. `-x509` makes a finished certificate in the common **X.509** certificate format. Here it signs its own certificate. `-days 30` sets its lifetime. `-nodes` leaves the private-key file without password encryption. That is a convenience for this disposable lab.

```bash
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout out/secrets/server.key -out out/secrets/server.csr
```

This makes a separate server key pair. The **certificate signing request**, or **CSR**, contains the requested name and public key, plus a signature proving possession of the matching private key. It asks the CA to issue a certificate. It is not yet a CA-issued certificate and contains no private key.

```bash
openssl x509 -req -in out/secrets/server.csr \
  -CA out/secrets/ca.crt -CAkey out/secrets/ca.key -days 30 \
  -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1') \
  -out out/secrets/server.crt
```

The CA signs the server certificate with `ca.key`. `server.crt` contains the server public key and permitted names. **SAN**, Subject Alternative Name, is that name list. **CN**, Common Name, is the older name field set by `-subj`. Our certificate explicitly includes SANs for both `localhost` and `127.0.0.1`.

The `<(...)` part is Bash syntax. It gives OpenSSL the extension text as file input. It does not contact a CA on the internet. The lab operator acts as the CA and chooses the names directly.

| File | Meaning | Who needs it? |
| --- | --- | --- |
| `ca.key` | Private CA signing key. | Certificate issuer. The running web server does not need it. |
| `ca.crt` | Public CA certificate, including its public key. | Client uses it as a trust anchor. |
| `server.key` | Server's private identity key. | Server. |
| `server.csr` | Public request for a server certificate. | Certificate issuer. |
| `server.crt` | Public server ID, including names, public key, dates and issuer signature. | Server presents it to the client. |
| `rogue.key`, `rogue.crt` | Separate private key and self-signed certificate for the fake server. | Fake server. |
| `tls13.keys` | Exported secrets for recorded TLS 1.3 connections. | Lab analysis only. Keep secret. |

The public key is contained in the public certificate. We do not create a separate `server.pub` file here. Public means safe to disclose, not necessarily readable in every passive capture. TLS 1.3 encrypts the certificate message on the wire.

## 04. Why does the client trust a certificate?

A certificate is a signed statement: "this public key belongs to these names, for these dates." The CA's signature binds the fields together. Changing the name or key invalidates that signature.

There are two different signatures to keep apart. At issuance, the CA signs the certificate with `ca.key`. During the TLS 1.3 connection, the server signs the negotiation with `server.key`. The first vouches for a name-to-key link. The second proves the live server holds that key. Copying someone else's public certificate does not give you their private key.

A **trust store** is the client's chosen list of trusted certificate authorities. A root CA can sign an intermediate CA, which can sign a server certificate. An **intermediate** is a delegated certificate issuer. This ladder is the **certificate chain**. The client checks signatures and certificate constraints along a path to a root it already trusts. It also checks the requested server name and validity dates.

Our lab has a shorter chain: `Lab CA TLS -> localhost`. There is no intermediate. `--cacert out/secrets/ca.crt` gives curl our CA certificate for this transfer. `-CAfile` supplies it to OpenSSL. We do not install the CA in Windows's global trust store.

A root's own signature does not make it trustworthy. Trust starts because the client operator selected that root. A stranger can make a self-signed certificate just as easily. The passport-office analogy describes a trusted name-to-key check. A typical public web certificate is about control of a domain name, not a full investigation of a person's honesty. See [curl's certificate verification documentation](https://curl.se/docs/sslcerts.html).

The CA does not join each connection or receive the session's encryption keys in this lab. The client verifies signatures locally using public certificates.

## 05. What happens during TLS 1.3?

The **handshake** is the setup conversation before our HTTP request. Its job is to choose compatible methods, establish secrets and check the server. The following is a simplified full certificate-based exchange for our case. Some steps are computed locally and do not appear as separate packets.

1. **ClientHello.** The client sends supported choices and public information for establishing a fresh secret. A **key share** is that public information, not the secret key.
2. **ServerHello.** The server selects the methods and replies with its public contribution. Both sides can calculate matching secret material using their own private temporary information. A passive recorder sees the public exchange without obtaining those private inputs.
3. Both derive keys for protecting the rest of the handshake. **Derive** means calculate new keys from secret material and the conversation so far.
4. The server sends its **Certificate**, **CertificateVerify** and **Finished** messages under that encryption. CertificateVerify is the server's live signature over the negotiation. Finished is a secret-based check that the negotiation has stayed consistent.
5. The client checks the certificate chain, name, dates, signature and Finished. It returns its own Finished. Both sides derive application traffic keys. Our lab does not use a client certificate.
6. curl sends `GET /witness.txt`. The server returns the file. Both messages travel encrypted and checked for alteration.

The public exchange happens before the client finishes authenticating the server. That is why encryption becoming available is not itself proof of the recipient's identity. The handshake then authenticates the exchange. See the [TLS 1.3 protocol overview](https://www.rfc-editor.org/rfc/rfc8446.html#section-2).

**Diffie-Hellman** is a family of methods for arriving at a shared secret through public contributions. **ECDHE** uses elliptic-curve mathematics with fresh temporary keys. **Ephemeral** means temporary, for this connection. Picture each person adding a private paint color to public paint, exchanging mixtures and arriving at the same final mixture. The picture explains public contributions and private inputs. Real security depends on mathematical problems, not paint.

Our saved OpenSSL diagnostic probe reports `X25519MLKEM768`. This combines an X25519 exchange with ML-KEM, another way to establish a shared secret using public information and private inputs. The combined output feeds key derivation. The paint picture only illustrates the X25519 side. This label comes from `out/evidence/tls13-s_client.txt`, a separate probe before the curl capture. It is not an assertion that the captured curl connection chose the same group. No additional topic or experiment is needed to understand this lab result.

## 06. When is it public, and who can read it?

| Item | Ordinary observer of our TLS 1.3 connection | Endpoints |
| --- | --- | --- |
| Addresses, ports, packet sizes and timing | Visible. | Visible. |
| ClientHello and ServerHello | Visible. | Visible. |
| Server certificate and later handshake messages | Encrypted after ServerHello. | Decrypted and checked by the client. |
| HTTP path, headers and witness file | Encrypted. | Readable to the programs handling them. |
| Private keys and traffic secrets | Not sent as plaintext network fields. | Held where each is needed. |

In an ordinary TLS ClientHello without extra protection, the requested hostname can also be visible. Encryption does not make a connection anonymous. This guide does not claim a new hostname-visibility measurement.

There are two meanings of "private" here. A **private key** is secret cryptographic material. A **private connection** keeps message content from outside observers. Neither means the server cannot read the request addressed to it. A TLS connection to the fake server can be encrypted while exposing every submitted byte to that fake server.

## 07. Why could the RSA key decrypt TLS 1.2?

The experiment deliberately chooses `AES128-GCM-SHA256`, the OpenSSL name for `TLS_RSA_WITH_AES_128_GCM_SHA256`, suite number `0x009c`. A **cipher suite** names a set of cryptographic choices.

Here, RSA means **static RSA key exchange**. The client creates a random starting secret, called the **premaster secret**, and encrypts it with the certificate's RSA public key. The server decrypts it with `server.key`. Both derive the data keys from it and the handshake values. The HTTP data uses AES-128-GCM. SHA-256 is used in this suite's key derivation and handshake checks.

Someone can record the complete connection today and obtain the matching server private key later. The recording includes the RSA-encrypted starting secret. That key can open it, allowing the data keys to be reconstructed. That is how Wireshark reads our old recording. AES itself was not broken. See [RSA key exchange in TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.7.1).

**Forward secrecy** means that later theft of a long-term identity key does not by itself reveal past sessions' data keys, assuming temporary secrets were erased. Think of a permanent ID stamp and fresh disposable box keys. Stealing the stamp later does not recreate yesterday's box keys.

The same property is often called **perfect forward secrecy**, or **PFS**. It does not protect a session whose own secrets were exported or stolen.

Our TLS 1.3 exchange uses separate temporary secret establishment, so `server.key` alone cannot reconstruct its traffic secrets. Our deliberately selected TLS 1.2 static RSA configuration lacks that separation. The same RSA certificate key is used by both servers. The difference comes from how secrets are established.

TLS 1.2 can also use ECDHE and provide forward secrecy. The script here tests the static RSA profile only. An RSA certificate can be used for signatures alongside ECDHE. The presence of "RSA" in a certificate does not tell you which key exchange was negotiated.

## 08. What did Wireshark need?

| Recording | Extra input to Wireshark | Existing lab check |
| --- | --- | --- |
| TLS 1.3 | None. | Witness text unreadable. |
| TLS 1.3 | `server.key` only. | Still unreadable. |
| TLS 1.3 | Matching `tls13.keys`. | Witness text recovered. |
| TLS 1.3 copy with embedded secrets | Secrets already inside `tls13-with-keys.pcapng`. | Opens decrypted. |
| TLS 1.2 static RSA | None. | Witness text unreadable. |
| TLS 1.2 static RSA | Matching `server.key`. | Recorded session decrypted. |

For TLS 1.3, our **server** writes the key log through `-keylogfile`. It exports connection-specific secrets that Wireshark uses to derive the needed keys. The original `tls13.pcapng` has no embedded secrets. `editcap` creates a second file containing them. Opening that second file decrypted is expected. It is not evidence that TLS can be broken from ordinary packets alone.

For the static RSA case, Wireshark needs the matching key and a complete, suitable handshake. A resumed session can lack the required starting exchange. Keep this condition when explaining the result. These requirements are documented in [Wireshark's TLS decryption guide](https://wiki.wireshark.org/TLS#tls-decryption).

The exact Windows clicks are in [README.md](../README.md#wireshark-on-windows). Clear configured secrets between observations, or use separate profiles. A **profile** is a saved set of Wireshark settings. A secret-loaded profile can make an otherwise encrypted capture appear readable.

Recovering a file with secrets supplied by a lab endpoint is authorized decryption. A missing witness string alone is not a mathematical proof of security. The lab combines that observation with negotiated settings, successful file delivery and decryption controls.

## 09. Why did the fake server fail, then receive data?

The fake server listens on `127.0.0.1:9443`. Its certificate contains the correct name, `localhost`, but is signed by itself. The client trusts our Lab CA. The fake certificate has no signature path to that CA.

With verification enabled, curl reports **error 60** and aborts before sending the HTTP POST containing the witness text. **POST** is an HTTP request that submits data. The fake server can receive TLS setup messages during this attempt. "Receives nothing" in the existing check means it receives none of our witness text, not zero network bytes. This refusal is the expected protection working.

`--insecure` tells curl to skip certificate verification. The client can then establish encrypted traffic with the fake server and send the POST. The fake server decrypts it because it is the endpoint. It does not need to break anyone else's encryption.

The second curl command uses a two-second timeout. This fake server logs incoming data but sends no normal HTTP response. A timeout therefore does not tell you whether the POST arrived. The existing check reads the server log and confirms the witness text was received.

This is a direct fake-server experiment. It does not redirect a real connection through a transparent attacker. A full **man-in-the-middle** scenario would require additional interception or redirection that this script does not implement. See [curl's description of verification and `--insecure`](https://curl.se/docs/sslcerts.html#skip-verification).

## 10. What do the commands mean during a connection?

| Part from `lab.sh` | Plain meaning |
| --- | --- |
| `s_server -accept 127.0.0.1:8443 -tls1_3` | Start a local TLS server and allow TLS 1.3 for this test. |
| `-cert .../server.crt -key .../server.key` | Present this public ID and use its matching private key. |
| `-WWW` | Serve files from the server's working directory. |
| `-keylogfile .../tls13.keys` | Save this server's connection secrets for analysis. |
| `--resolve localhost:8443:127.0.0.1` | Send the connection to loopback while keeping `localhost` as the HTTPS name to check. |
| `--cacert out/secrets/ca.crt` | Supply the trusted CA certificate for curl's verification. |
| `https://localhost:8443/witness.txt` | Ask for the witness file through TLS. |
| `-servername localhost` | Tell the OpenSSL server which hostname the client wants. This alone does not verify it. |
| `-verify_hostname localhost` | Make OpenSSL check the certificate against that hostname. |
| `-verify_return_error` | Make OpenSSL stop when certificate verification fails. |
| `-tls1_2 -cipher AES128-GCM-SHA256` | Restrict the test server to our selected TLS 1.2 static RSA configuration. |

The OpenSSL probe and the curl download are separate connections. The probe reports its negotiated settings and verification result. The download gives us the file and captured session. testssl.sh performs additional connections to audit the local server's offered choices. The script runs that audit before starting the experiment's capture.

`TLS_AES_256_GCM_SHA384` in the saved TLS 1.3 probe means AES with 256-bit keys, GCM data protection, and SHA-384 for key derivation and handshake hashing. In TLS 1.3, this suite label does not specify the key exchange or certificate signature method. The probe reports those separately as `X25519MLKEM768` and `rsa_pss_rsae_sha256`.

A **hash**, also called a **digest**, is a fixed-length check value calculated from bytes. Changing the input should change that value. It is not encryption that someone later reverses with a key. SHA-256 and SHA-384 name hashing methods. A plain hash alone does not prove who sent a message. Here, hashes are used within signatures, secret-based checks and key derivation.

## 11. How does SSH fit?

SSH protects remote command sessions. It is a separate secure protocol, with its own negotiation. It does not put the shell session inside TLS.

Our server has an Ed25519 **host key**. Ed25519 names another method for making and checking digital signatures. The client already has the correct public host key in a local `known_hosts` file. `StrictHostKeyChecking=yes` makes it require that known identity. A **fingerprint** is a compact hash value used to identify a public key. The lab saves the host key fingerprint as evidence.

There is a separate client key pair. Its public key is installed in `labuser`'s `authorized_keys`. The client proves it holds the matching private key to log in. These are two checks: the client checks the server's identity, then the server checks the client's permission to log in. Password login is disabled in this SSH configuration.

The lab runs a command that prints the witness file. You can read its output in the client terminal. The saved checks confirm that the `SSH-2.0` identification is visible in the capture while the witness text is absent. A visible protocol banner does not mean the shell commands are readable.

SSH's preloaded host key and TLS's CA-signed certificate solve a similar identity problem through different trust arrangements. Neither relies on blindly accepting an unknown key in this lab.

## 12. Explaining it to the teacher

Practice each answer, then explain why it is true without using the technical term itself.

**What is TLS?** "It lets two programs exchange messages privately, detects changes to those messages, and checks the server's identity when certificate verification is enabled. HTTPS uses it to protect HTTP."

**Why make certificates before connecting?** "We first prepare the server's ID and the key it will use to prove that ID. The connection later uses them to check who is answering."

**Why can everyone see the certificate?** "It contains public information used to check identity. The secret is the matching private key. A copied ID card alone cannot make the live proof."

**What did the CA do?** "It signed a statement connecting localhost to the server's public key. Our client trusted that issuer because we supplied its certificate."

**Why did the fake certificate fail even with the right name?** "Anyone can print the name localhost. Its signature also has to lead to an issuer the client trusts. This one did not."

**Why did encryption still leak to the fake server?** "We skipped the identity check. We encrypted the message for the fake recipient, which could read the message addressed to it."

**Why does TLS 1.3 resist decryption with `server.key`?** "That key proves identity. Separate temporary secrets established the data keys, and the recording plus the identity key does not recreate them."

**Why does the key log work?** "The endpoint deliberately exported the connection secrets. Wireshark was given what an ordinary observer is missing."

**Is TLS 1.2 always weak?** "Our chosen static RSA setup loses past-session privacy if its server key is stolen later. TLS 1.2 also supports temporary exchanges such as ECDHE. The chosen configuration matters."

**Did we test every protection?** "The saved checks cover file delivery, visibility, verification, secret-assisted decryption and fake-server rejection or acceptance. We did not run a separate packet-tampering experiment. Integrity is a protocol property explained here."

**What must stay secret?** "The CA private key, server private key, SSH private keys and connection key logs. Public certificates can be shared. The capture with embedded secrets needs protection too."

For rehearsal, cover the answers and explain these three events in order: preparing the certificate files, opening a verified TLS 1.3 connection, and giving Wireshark the matching connection secrets. Then change only one condition, certificate verification or the selected key exchange, and explain why the outcome changes.

## Evidence map

These are existing automated observations. No service configuration or test scope was changed for this guide. All 27 saved `PASS` entries were inspected. The checks below are the relevant subset.

| Teaching point | Function in `lab.sh` | Existing check or saved evidence |
| --- | --- | --- |
| HTTP and Telnet expose lab content. | `t_http`, `t_telnet` | Readable GET, witness text and Telnet credentials. |
| SSH delivers the file without exposing its text. | `t_ssh` | Output contains witness, banner visible, witness absent from capture. |
| Verified TLS 1.3 delivers the file. | `t_tls13` | Certificate verified, TLS 1.3 negotiated, received file identical. |
| Certificate private key alone does not decrypt TLS 1.3. | `t_tls13` | `unreadable with the RSA private key alone`. |
| Exported secrets decrypt TLS 1.3. | `t_tls13` | `decrypted with the key log`, embedded-secrets copy opens decrypted. |
| Static RSA permits past-session decryption with the server key. | `t_tls12` | Suite `0x009c`, no forward secrecy reported, RSA decryption succeeds. |
| Fake certificate is refused before witness submission. | `t_fake` | curl code 60, zero witness occurrences before verification was disabled. |
| Disabling verification sends the witness to the fake server. | `t_fake` | Witness found in `fake-server.log`. |
| Probe's suite, group and signature labels. | `t_tls13` diagnostic probe | `out/evidence/tls13-s_client.txt`. Labels are context, not new assertions about curl's capture. |

Certificate field meanings, the general chain with an intermediate, key derivation, metadata visibility and the analogies are explanations. They are not additional measured results. The existing script does not separately test wrong-name, expiry or altered-packet rejection. None is presented as a completed experiment here.
