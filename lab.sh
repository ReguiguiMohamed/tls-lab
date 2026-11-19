#!/usr/bin/env bash
# Runs the lab tests, saves one capture per test in out/captures and checks each expected
# observation with tshark. Run setup.sh once first, then as root:
#   sudo bash lab.sh [ping|telnet|http|ssh|tls13|tls12|fake|versions|bot|mitm|mtls ...]
# With no argument it starts from scratch and runs every test.
set -u
cd "$(dirname "$0")"

W=PROJET_TLS_MOHAMED_FIRAS
OUT=out
S=$OUT/secrets
C=$OUT/captures
E=$OUT/evidence
WWW=fixtures/www
# Absolute path, read by labuser inside the Telnet and SSH sessions.
WITNESS="$PWD/$WWW/witness.txt"
FAILS=0

check() {
  local r=PASS
  eval "$2" || { r=FAIL; FAILS=$((FAILS + 1)); }
  echo "$r  $1" | tee -a $OUT/results.txt
}

capture_start() {
  dumpcap -q -i lo -f "$2" -w "$C/$1.pcapng" 2>/dev/null &
  CAP=$!
  sleep 1
}

capture_stop() {
  sleep 0.5
  kill -INT $CAP
  wait $CAP
}

# Text of one direction of a TCP stream, segments joined.
# Telnet often sends one character per packet, so a grep on the raw file is not enough.
# Telnet also sends CR NUL for Enter, and bash cannot hold NUL bytes.
tcp_text() {
  tshark -r "$1" -Y "$2 && tcp.len > 0" -T fields -e tcp.payload 2>/dev/null |
    python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().replace("\n", "")).replace(b"\0", b""))'
}

# TLS application data as tshark sees it with the given options.
tls_text() {
  local pcap=$1
  shift
  tshark -r "$pcap" "$@" -q -z follow,tls,ascii,0 2>/dev/null
}

on_wire() { grep -aq "$2" "$C/$1.pcapng"; }

# Version and forward secrecy audit, run before the capture so it stays out of it.
audit() { testssl --quiet --color 0 --warnings off -p -f 127.0.0.1:$1 > $E/testssl-$1.txt 2>&1; }

setup() {
  rm -rf $OUT
  mkdir -p $S $C $E
  : > $OUT/results.txt
  dpkg-query -W openssl openssh-server inetutils-telnetd curl tshark python3 testssl.sh mitmproxy > $E/versions.txt

  # Lab CA, trusted only through --cacert / -CAfile. Python 3.13 and later reject a CA without key usage.
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Lab CA TLS" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout $S/ca.key -out $S/ca.crt 2>/dev/null

  # One RSA server key for TLS 1.3 and TLS 1.2: the same key decrypts one and not the other.
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout $S/server.key -out $S/server.csr 2>/dev/null
  openssl x509 -req -in $S/server.csr -CA $S/ca.crt -CAkey $S/ca.key -days 30 \
    -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1') -out $S/server.crt 2>/dev/null

  # Fake server: self-signed certificate for the same name, outside the client's trust.
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout $S/rogue.key -out $S/rogue.crt 2>/dev/null
}

t_ping() {
  capture_start ping icmp
  ping -c 3 127.0.0.1 > $E/ping.txt
  capture_stop
  check "ping: 3 ICMP replies" '[ "$(tshark -r $C/ping.pcapng -Y "icmp.type == 0" 2>/dev/null | wc -l)" -eq 3 ]'
}

t_telnet() {
  inetutils-inetd -d config/inetd.conf > /dev/null 2>&1 &
  local srv=$!
  sleep 1
  capture_start telnet "tcp port 2323"
  # The prompt ends in "$ ", with a color reset in between on Kali.
  WITNESS=$WITNESS expect -c '
    set timeout 10
    set prompt {\$(\x1b\[[0-9;]*m)? $}
    spawn telnet 127.0.0.1 2323
    expect "login: " { send "labuser\r" }
    expect "assword: " { send "labpass\r" }
    expect -re $prompt { send "cat \"$env(WITNESS)\"\r" }
    expect -re $prompt { send "exit\r" }
    expect eof' > $E/telnet-session.txt
  capture_stop
  kill $srv
  local up
  up=$(tcp_text $C/telnet.pcapng "tcp.dstport == 2323")
  check "telnet: username readable in the capture" '[[ $up == *labuser* ]]'
  check "telnet: password readable in the capture" '[[ $up == *labpass* ]]'
  check "telnet: witness text readable in the capture" 'on_wire telnet $W'
}

t_http() {
  python3 -m http.server 8080 --bind 127.0.0.1 --directory $WWW > /dev/null 2>&1 &
  local srv=$!
  sleep 1
  capture_start http "tcp port 8080"
  curl -4 -s -o $E/http-witness.txt http://127.0.0.1:8080/witness.txt
  capture_stop
  kill $srv
  check "http: received file is identical" 'cmp -s $E/http-witness.txt $WWW/witness.txt'
  check "http: GET request readable" 'on_wire http "GET /witness.txt"'
  check "http: witness text readable" 'on_wire http $W'
}

t_ssh() {
  local d=/tmp/lab-ssh
  rm -rf $d && mkdir -p $d /run/sshd
  ssh-keygen -q -t ed25519 -N "" -f $d/ssh_host_ed25519_key
  ssh-keygen -q -t ed25519 -N "" -f $d/client_key
  install -d -m 700 -o labuser /home/labuser/.ssh
  install -m 600 -o labuser $d/client_key.pub /home/labuser/.ssh/authorized_keys
  # known_hosts is built from the real host public key, so the check is strict.
  echo "[127.0.0.1]:2222 $(cat $d/ssh_host_ed25519_key.pub)" > $d/known_hosts
  ssh-keygen -lf $d/ssh_host_ed25519_key.pub > $E/ssh-host-fingerprint.txt
  /usr/sbin/sshd -f config/sshd_config
  sleep 1
  capture_start ssh "tcp port 2222"
  ssh -p 2222 -i $d/client_key -o UserKnownHostsFile=$d/known_hosts -o StrictHostKeyChecking=yes \
    labuser@127.0.0.1 "cat '$WITNESS'" > $E/ssh-output.txt
  capture_stop
  kill "$(cat $d/sshd.pid)"
  check "ssh: session opened and text shown" 'grep -q $W $E/ssh-output.txt'
  check "ssh: SSH-2.0 banner visible" 'on_wire ssh SSH-2.0'
  check "ssh: witness text absent from the capture" '! on_wire ssh $W'
}

t_tls13() {
  # -WWW serves files from the current directory, hence the cd.
  (cd $WWW && exec openssl s_server -quiet -accept 127.0.0.1:8443 -tls1_3 -WWW \
    -cert ../../$S/server.crt -key ../../$S/server.key -keylogfile ../../$S/tls13.keys) &
  local srv=$!
  sleep 1
  openssl s_client -connect 127.0.0.1:8443 -servername localhost -CAfile $S/ca.crt \
    -verify_return_error -verify_hostname localhost -brief < /dev/null > $E/tls13-s_client.txt 2>&1
  audit 8443
  : > $S/tls13.keys
  capture_start tls13 "tcp port 8443"
  curl -4 -s --cacert $S/ca.crt --resolve localhost:8443:127.0.0.1 -o $E/tls13-witness.txt \
    https://localhost:8443/witness.txt
  capture_stop
  kill $srv
  editcap --inject-secrets tls,$S/tls13.keys $C/tls13.pcapng $C/tls13-with-keys.pcapng
  local dec="-d tcp.port==8443,tls"
  check "tls13: certificate verified by s_client" 'grep -q "Verification: OK" $E/tls13-s_client.txt'
  check "tls13: TLSv1.3 negotiated" 'grep -q "Protocol version: TLSv1.3" $E/tls13-s_client.txt'
  check "tls13: testssl sees TLS 1.3 with forward secrecy" 'grep -q "TLS 1.3    offered" $E/testssl-8443.txt && ! grep -q "No ciphers supporting Forward Secrecy" $E/testssl-8443.txt'
  check "tls13: received file is identical" 'cmp -s $E/tls13-witness.txt $WWW/witness.txt'
  check "tls13: witness text absent from the capture" '! on_wire tls13 $W'
  check "tls13: unreadable without secrets" '! tls_text $C/tls13.pcapng $dec | grep -q $W'
  check "tls13: unreadable with the RSA private key alone" \
    '! tls_text $C/tls13.pcapng $dec -o "uat:rsa_keys:\"$S/server.key\",\"\"" | grep -q $W'
  check "tls13: decrypted with the key log" \
    'tls_text $C/tls13.pcapng $dec -o tls.keylog_file:$S/tls13.keys | grep -q $W'
  check "tls13: tls13-with-keys.pcapng opens decrypted" 'tls_text $C/tls13-with-keys.pcapng $dec | grep -q $W'
}

t_tls12() {
  (cd $WWW && exec openssl s_server -quiet -accept 127.0.0.1:8444 -tls1_2 -cipher AES128-GCM-SHA256 -WWW \
    -cert ../../$S/server.crt -key ../../$S/server.key) &
  local srv=$!
  sleep 1
  audit 8444
  capture_start tls12-rsa "tcp port 8444"
  curl -4 -s --cacert $S/ca.crt --resolve localhost:8444:127.0.0.1 --tls-max 1.2 --ciphers AES128-GCM-SHA256 \
    -o $E/tls12-witness.txt https://localhost:8444/witness.txt
  capture_stop
  kill $srv
  local dec="-d tcp.port==8444,tls"
  local suite
  suite=$(tshark -r $C/tls12-rsa.pcapng $dec -Y "tls.handshake.type == 2" -T fields -e tls.handshake.ciphersuite 2>/dev/null)
  echo "$suite" > $E/tls12-ciphersuite.txt
  check "tls12: received file is identical" 'cmp -s $E/tls12-witness.txt $WWW/witness.txt'
  check "tls12: suite TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c) negotiated" '[ "$suite" = 0x009c ]'
  check "tls12: testssl reports no forward secrecy" 'grep -q "No ciphers supporting Forward Secrecy" $E/testssl-8444.txt'
  check "tls12: unreadable without the key" '! tls_text $C/tls12-rsa.pcapng $dec | grep -q $W'
  check "tls12: past session decrypted with the RSA private key" \
    'tls_text $C/tls12-rsa.pcapng $dec -o "uat:rsa_keys:\"$S/server.key\",\"\"" | grep -q $W'
}

t_mtls() {
  openssl req -newkey rsa:2048 -nodes -subj '/CN=Authorized client' \
    -keyout $S/mtls-client.key -out $S/mtls-client.csr 2> $E/mtls-cert.log
  openssl x509 -req -in $S/mtls-client.csr -CA $S/ca.crt -CAkey $S/ca.key -days 30 \
    -extfile <(printf 'extendedKeyUsage=clientAuth') -out $S/mtls-client.crt >> $E/mtls-cert.log 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=Untrusted client' \
    -addext 'extendedKeyUsage=clientAuth' -keyout $S/mtls-untrusted.key \
    -out $S/mtls-untrusted.crt >> $E/mtls-cert.log 2>&1
  (cd $WWW && exec openssl s_server -quiet -accept 127.0.0.1:8480 -tls1_3 -WWW \
    -cert ../../$S/server.crt -key ../../$S/server.key -CAfile ../../$S/ca.crt \
    -Verify 1 -verify_return_error) > $E/mtls-server.log 2>&1 &
  local srv=$! missing untrusted authorized
  local -a get=(curl -4 -sS --noproxy '*' --http1.1 --tlsv1.3 --tls-max 1.3 --max-time 5 \
    --cacert "$S/ca.crt" --resolve localhost:8480:127.0.0.1)
  rm -f $E/mtls-missing.txt $E/mtls-untrusted.txt $E/mtls-authorized.txt
  sleep 1
  capture_start mtls 'tcp port 8480'
  "${get[@]}" -o $E/mtls-missing.txt https://localhost:8480/witness.txt 2> $E/mtls-missing-error.txt
  missing=$?
  "${get[@]}" --cert $S/mtls-untrusted.crt --key $S/mtls-untrusted.key \
    -o $E/mtls-untrusted.txt https://localhost:8480/witness.txt 2> $E/mtls-untrusted-error.txt
  untrusted=$?
  "${get[@]}" --cert $S/mtls-client.crt --key $S/mtls-client.key \
    -o $E/mtls-authorized.txt https://localhost:8480/witness.txt 2> $E/mtls-authorized-error.txt
  authorized=$?
  capture_stop
  kill "$srv"
  wait "$srv" 2>/dev/null
  check 'mtls: client without a certificate is rejected' '[ "$missing" -ne 0 ] && [ ! -s $E/mtls-missing.txt ] && grep -qi "certificate required" $E/mtls-missing-error.txt'
  check 'mtls: client with an untrusted certificate is rejected' '[ "$untrusted" -ne 0 ] && [ ! -s $E/mtls-untrusted.txt ] && grep -qi "unknown ca" $E/mtls-untrusted-error.txt'
  check 'mtls: authorized client receives the original file' '[ "$authorized" -eq 0 ] && cmp -s $E/mtls-authorized.txt $WWW/witness.txt'
  check 'mtls: witness text is absent from the capture' '! on_wire mtls $W'
}

t_fake() {
  # Without -WWW, s_server prints what it receives: that is the fake server's log.
  sleep 60 | openssl s_server -quiet -accept 127.0.0.1:9443 -cert $S/rogue.crt -key $S/rogue.key \
    > $E/fake-server.log 2>&1 &
  sleep 1
  capture_start fake "tcp port 9443"
  curl -4 -sS --cacert $S/ca.crt --resolve localhost:9443:127.0.0.1 -d "secret=$W" https://localhost:9443/ \
    2> $E/fake-verified-client.txt
  local verified=$?
  local leak_verified
  leak_verified=$(grep -c $W $E/fake-server.log)
  curl -4 -s --insecure --max-time 2 --resolve localhost:9443:127.0.0.1 -d "secret=$W" https://localhost:9443/
  capture_stop
  pkill -f "accept 127.0.0.1:9443"
  check "fake: verifying client rejects the certificate (curl code 60)" '[ $verified -eq 60 ]'
  check "fake: fake server receives nothing when the client verifies" '[ $leak_verified -eq 0 ]'
  check "fake: fake server receives the text with --insecure" 'grep -q $W $E/fake-server.log'
}

t_versions() {
  # Stock OpenSSL 3 refuses TLS 1.0 and 1.1 above security level 0. Kali's openssl.cnf already
  # allows them, the flag keeps the test independent of that file.
  local old="-cipher DEFAULT@SECLEVEL=0" port=8450 v curl_tls1
  for v in tls1 tls1_1 tls1_2 tls1_3; do
    openssl s_server -quiet -accept 127.0.0.1:$port -$v $old -www -cert $S/server.crt -key $S/server.key \
      > /dev/null 2>&1 &
    local srv=$!
    sleep 1
    capture_start versions-$v "tcp port $port"
    openssl s_client -connect 127.0.0.1:$port -$v $old -servername localhost -CAfile $S/ca.crt \
      -verify_return_error -verify_hostname localhost -brief < /dev/null > $E/versions-$v.txt 2>&1
    capture_stop
    if [ $v = tls1 ]; then
      curl -4 -sS --cacert $S/ca.crt --resolve localhost:$port:127.0.0.1 https://localhost:$port/ \
        > /dev/null 2> $E/versions-curl-tls1.txt
      curl_tls1=$?
    fi
    kill $srv
    port=$((port + 1))
  done
  check "versions: TLSv1 negotiated" 'grep -q "Protocol version: TLSv1$" $E/versions-tls1.txt'
  check "versions: TLSv1.1 negotiated" 'grep -q "Protocol version: TLSv1.1" $E/versions-tls1_1.txt'
  check "versions: TLSv1.2 negotiated" 'grep -q "Protocol version: TLSv1.2" $E/versions-tls1_2.txt'
  check "versions: TLSv1.3 negotiated" 'grep -q "Protocol version: TLSv1.3" $E/versions-tls1_3.txt'
  # The CA name sits inside the server certificate, so it is on the wire only when the certificate is.
  check "versions: certificate readable in TLS 1.0, 1.1 and 1.2" \
    'on_wire versions-tls1 "Lab CA TLS" && on_wire versions-tls1_1 "Lab CA TLS" && on_wire versions-tls1_2 "Lab CA TLS"'
  check "versions: certificate encrypted in TLS 1.3" '! on_wire versions-tls1_3 "Lab CA TLS"'
  check "versions: curl refuses a TLS 1.0 server by default (curl code 35)" '[ $curl_tls1 -eq 35 ]'
  check "versions: this OpenSSL has no SSL 3.0 option" '! openssl s_client -help 2>&1 | grep -q -- -ssl3'
}

t_bot() {
  # Without -WWW, s_server prints each request with its User-Agent: that is the site's access log.
  sleep 60 | openssl s_server -quiet -accept 127.0.0.1:8460 -cert $S/server.crt -key $S/server.key \
    > $E/bot-server.log 2>&1 &
  sleep 1
  local url=https://localhost:8460
  local ff="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"
  local get="curl -4 -s --max-time 1 --cacert $S/ca.crt --resolve localhost:8460:127.0.0.1"
  local py='import sys, ssl, urllib.request as u
h = {"User-Agent": sys.argv[3]} if len(sys.argv) > 3 else {}
u.urlopen(u.Request(sys.argv[1], headers=h), timeout=1, context=ssl.create_default_context(cafile=sys.argv[2]))'
  capture_start bot "tcp port 8460"
  $get $url/honest-curl
  $get -A "$ff" $url/bot-curl
  python3 -c "$py" $url/honest-python $S/ca.crt 2> /dev/null
  python3 -c "$py" $url/bot-python $S/ca.crt "$ff" 2> /dev/null
  capture_stop
  pkill -f "accept 127.0.0.1:8460"
  # One line per connection, in order: JA4 seen on the wire, then the User-Agent the client claimed.
  paste <(tshark -r $C/bot.pcapng -d tcp.port==8460,tls -Y "tls.handshake.type == 1" -T fields \
    -e tls.handshake.ja4 2>/dev/null) <(grep "^User-Agent: " $E/bot-server.log | cut -d" " -f2-) > $E/bot-ja4.txt
  # Detector: a client that claims a browser but has the JA4 of a tool seen earlier is flagged.
  awk -F'\t' '$2 !~ /^Mozilla/ { tool[$1] = $2 }
    $2 ~ /^Mozilla/ && ($1 in tool) { print "BOT " $1 " claims a browser, TLS of " tool[$1] }' \
    $E/bot-ja4.txt > $E/bot-flagged.txt
  local ja4
  mapfile -t ja4 < <(cut -f1 $E/bot-ja4.txt)
  check "bot: curl and Python have different JA4 fingerprints" '[ ${#ja4[@]} -eq 4 ] && [ "${ja4[0]}" != "${ja4[2]}" ]'
  check "bot: a fake User-Agent leaves the JA4 unchanged" '[ "${ja4[0]}" = "${ja4[1]}" ] && [ "${ja4[2]}" = "${ja4[3]}" ]'
  check "bot: detector flags the 2 fake browsers and no honest client" '[ $(wc -l < $E/bot-flagged.txt) -eq 2 ]'
}

t_mitm() {
  local conf="$PWD/$S/mitmproxy" changed=MODIFIED_IN_TRANSIT
  local dec="-d tcp.port==8470,tls -d tcp.port==8471,tls"
  local -a get=(curl -4 -sS --noproxy '*' --http1.1 --tlsv1.3 --tls-max 1.3 --max-time 5)
  local direct untrusted trusted pinned srv proxy ready=0
  openssl x509 -in $S/server.crt -pubkey -noout > $E/mitm-server-public.pem
  (cd $WWW && exec openssl s_server -quiet -accept 127.0.0.1:8470 -tls1_3 -alpn http/1.1 -WWW \
    -cert ../../$S/server.crt -key ../../$S/server.key) > $E/mitm-server.log 2>&1 &
  srv=$!
  SSLKEYLOGFILE="$PWD/$S/mitm.keys" mitmdump --mode reverse:https://127.0.0.1:8470 \
    --listen-host 127.0.0.1 --listen-port 8471 --set confdir="$conf" \
    --set ssl_verify_upstream_trusted_ca="$PWD/$S/ca.crt" \
    --set tls_version_client_min=TLS1_3 --set tls_version_server_min=TLS1_3 \
    -s config/modify_response.py -w $E/mitm.flows > $E/mitm-proxy.log 2>&1 &
  proxy=$!
  for _ in {1..100}; do
    if (: > /dev/tcp/127.0.0.1/8471) 2>/dev/null; then ready=1; break; fi
    kill -0 "$proxy" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$ready" -eq 0 ]; then
    check "mitm: proxy starts" false
    kill "$srv" "$proxy" 2>/dev/null
    wait "$srv" "$proxy" 2>/dev/null
    return
  fi
  "${get[@]}" --cacert $S/ca.crt --pinnedpubkey $E/mitm-server-public.pem \
    https://127.0.0.1:8470/witness.txt > $E/mitm-direct.txt 2> $E/mitm-direct-client.txt
  direct=$?
  capture_start mitm "tcp port 8470 or tcp port 8471"
  "${get[@]}" --cacert $S/ca.crt --resolve localhost:8471:127.0.0.1 \
    https://localhost:8471/witness.txt > $E/mitm-untrusted.txt 2> $E/mitm-untrusted-client.txt
  untrusted=$?
  "${get[@]}" --cacert "$conf/mitmproxy-ca-cert.pem" --resolve localhost:8471:127.0.0.1 \
    https://localhost:8471/witness.txt > $E/mitm-trusted.txt 2> $E/mitm-trusted-client.txt
  trusted=$?
  "${get[@]}" --cacert "$conf/mitmproxy-ca-cert.pem" --pinnedpubkey $E/mitm-server-public.pem \
    --resolve localhost:8471:127.0.0.1 https://localhost:8471/witness.txt \
    > $E/mitm-pinned.txt 2> $E/mitm-pinned-client.txt
  pinned=$?
  capture_stop
  kill "$proxy" "$srv"
  wait "$proxy" "$srv" 2>/dev/null
  printf 'untrusted=%s\ntrusted=%s\npinned=%s\n' "$untrusted" "$trusted" "$pinned" > $E/mitm-status.txt
  check "mitm: direct request with the original public-key pin returns the original file" \
    '[ "$direct" -eq 0 ] && cmp -s $E/mitm-direct.txt $WWW/witness.txt'
  check "mitm: original CA rejects the proxy certificate (curl code 60)" '[ "$untrusted" -eq 60 ]'
  check "mitm: trusting the proxy CA delivers the modified response" \
    '[ "$trusted" -eq 0 ] && [ "$(cat $E/mitm-trusted.txt)" = "$changed" ]'
  check "mitm: original public-key pin rejects the trusted proxy (curl code 90)" \
    '[ "$pinned" -eq 90 ] && [ ! -s $E/mitm-pinned.txt ]'
  check "mitm: TLS 1.3 negotiated on both proxy legs" \
    'tshark -r $C/mitm.pcapng $dec -Y "tls.handshake.type == 2" -T fields -e tcp.srcport -e tls.handshake.extensions.supported_version 2>/dev/null | awk '\''$1 == 8470 && $2 == "0x0304" {a=1} $1 == 8471 && $2 == "0x0304" {b=1} END {exit !(a && b)}'\'''
  check "mitm: original and modified text absent from the capture without secrets" \
    '! on_wire mitm $W && ! on_wire mitm $changed'
  # OpenSSL's HTTP/1.0 reply has no Content-Length. Inspect its body without waiting for HTTP reassembly.
  check "mitm: key log reveals the original response on the server leg" \
    'tshark -r $C/mitm.pcapng $dec -o tls.keylog_file:$S/mitm.keys -o http.desegment_body:FALSE -Y "tcp.srcport == 8470 && http.file_data contains \"$W\"" -T fields -e frame.number 2>/dev/null | grep -q .'
  check "mitm: key log reveals the modified response on the client leg" \
    'tshark -r $C/mitm.pcapng $dec -o tls.keylog_file:$S/mitm.keys -o http.desegment_body:FALSE -Y "tcp.srcport == 8471 && http.file_data contains \"$changed\"" -T fields -e frame.number 2>/dev/null | grep -q .'
}

if [ $# -eq 0 ]; then
  setup
  set -- ping telnet http ssh tls13 tls12 fake versions bot mitm mtls
else
  [ -d $OUT ] || setup
fi
for t in "$@"; do "t_$t"; done
# lab.sh runs as root, and out/ must stay readable and removable without sudo.
chmod -R a+rwX $OUT
echo "$FAILS failure(s)"
exit $((FAILS > 0))
