#!/usr/bin/env bash
# Lance les tests du laboratoire, enregistre une capture par test dans out/captures
# et vérifie chaque observation attendue avec tshark.
# Usage dans le conteneur : bash lab.sh [ping|telnet|http|ssh|tls13|tls12|fake ...]
# Sans argument : repart de zéro et joue tous les tests.
set -u
cd "$(dirname "$0")"

W=PROJET_TLS_MOHAMED_FIRAS
OUT=out
S=$OUT/secrets
C=$OUT/captures
E=$OUT/evidence
WWW=fixtures/www
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

# Texte d'un flux TCP dans un seul sens, segments recollés.
# Telnet envoie souvent un caractère par paquet : un grep sur le fichier brut ne suffit pas.
tcp_text() {
  tshark -r "$1" -Y "$2 && tcp.len > 0" -T fields -e tcp.payload 2>/dev/null |
    python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().replace("\n", "")))'
}

# Données applicatives TLS telles que tshark les voit avec les options données.
tls_text() {
  local pcap=$1
  shift
  tshark -r "$pcap" "$@" -q -z follow,tls,ascii,0 2>/dev/null
}

on_wire() { grep -aq "$2" "$C/$1.pcapng"; }

# Audit des versions et de la forward secrecy, avant la capture pour ne pas la polluer.
audit() { testssl --quiet --color 0 --warnings off -p -f 127.0.0.1:$1 > $E/testssl-$1.txt 2>&1; }

setup() {
  rm -rf $OUT
  mkdir -p $S $C $E
  : > $OUT/results.txt
  dpkg-query -W openssl openssh-server inetutils-telnetd curl tshark python3 testssl.sh > $E/versions.txt

  # CA du laboratoire, déclarée de confiance uniquement via --cacert / -CAfile.
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Lab CA TLS" \
    -keyout $S/ca.key -out $S/ca.crt 2>/dev/null

  # Une seule clé RSA serveur pour TLS 1.3 et TLS 1.2 : la même clé déchiffre l'un et pas l'autre.
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout $S/server.key -out $S/server.csr 2>/dev/null
  openssl x509 -req -in $S/server.csr -CA $S/ca.crt -CAkey $S/ca.key -days 30 \
    -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1') -out $S/server.crt 2>/dev/null

  # Faux serveur : certificat autosigné pour le même nom, hors de la confiance du client.
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout $S/rogue.key -out $S/rogue.crt 2>/dev/null
}

t_ping() {
  capture_start ping icmp
  ping -c 3 127.0.0.1 > $E/ping.txt
  capture_stop
  check "ping : 3 réponses ICMP sur lo" '[ "$(tshark -r $C/ping.pcapng -Y "icmp.type == 0" 2>/dev/null | wc -l)" -eq 3 ]'
}

t_telnet() {
  inetutils-inetd -d config/inetd.conf > /dev/null 2>&1 &
  local srv=$!
  sleep 1
  capture_start telnet "tcp port 2323"
  expect -c "
    set timeout 10
    spawn telnet 127.0.0.1 2323
    expect login: { send labuser\r }
    expect assword: { send labpass\r }
    expect {\$ } { send \"cat /lab/$WWW/witness.txt\r\" }
    expect {\$ } { send exit\r }
    expect eof" > $E/telnet-session.txt
  capture_stop
  kill $srv
  local up
  up=$(tcp_text $C/telnet.pcapng "tcp.dstport == 2323")
  check "telnet : identifiant lisible dans la capture" '[[ $up == *labuser* ]]'
  check "telnet : mot de passe lisible dans la capture" '[[ $up == *labpass* ]]'
  check "telnet : texte témoin lisible dans la capture" 'on_wire telnet $W'
}

t_http() {
  python3 -m http.server 8080 --bind 127.0.0.1 --directory $WWW > /dev/null 2>&1 &
  local srv=$!
  sleep 1
  capture_start http "tcp port 8080"
  curl -4 -s -o $E/http-witness.txt http://127.0.0.1:8080/witness.txt
  capture_stop
  kill $srv
  check "http : fichier reçu identique" 'cmp -s $E/http-witness.txt $WWW/witness.txt'
  check "http : requête GET lisible" 'on_wire http "GET /witness.txt"'
  check "http : texte témoin lisible" 'on_wire http $W'
}

t_ssh() {
  local d=/tmp/lab-ssh
  rm -rf $d && mkdir -p $d /run/sshd
  ssh-keygen -q -t ed25519 -N "" -f $d/ssh_host_ed25519_key
  ssh-keygen -q -t ed25519 -N "" -f $d/client_key
  install -d -m 700 -o labuser /home/labuser/.ssh
  install -m 600 -o labuser $d/client_key.pub /home/labuser/.ssh/authorized_keys
  # known_hosts construit depuis la vraie clé publique de l'hôte : la vérification est stricte.
  echo "[127.0.0.1]:2222 $(cat $d/ssh_host_ed25519_key.pub)" > $d/known_hosts
  ssh-keygen -lf $d/ssh_host_ed25519_key.pub > $E/ssh-host-fingerprint.txt
  /usr/sbin/sshd -f config/sshd_config
  sleep 1
  capture_start ssh "tcp port 2222"
  ssh -p 2222 -i $d/client_key -o UserKnownHostsFile=$d/known_hosts -o StrictHostKeyChecking=yes \
    labuser@127.0.0.1 cat /lab/$WWW/witness.txt > $E/ssh-output.txt
  capture_stop
  kill "$(cat $d/sshd.pid)"
  check "ssh : session ouverte et texte affiché" 'grep -q $W $E/ssh-output.txt'
  check "ssh : bannière SSH-2.0 visible" 'on_wire ssh SSH-2.0'
  check "ssh : texte témoin absent de la capture" '! on_wire ssh $W'
}

t_tls13() {
  # -WWW sert les fichiers du répertoire courant, d'où le cd.
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
  check "tls13 : certificat vérifié par s_client" 'grep -q "Verification: OK" $E/tls13-s_client.txt'
  check "tls13 : version TLSv1.3 négociée" 'grep -q "Protocol version: TLSv1.3" $E/tls13-s_client.txt'
  check "tls13 : testssl voit TLS 1.3 avec forward secrecy"     'grep -q "TLS 1.3    offered" $E/testssl-8443.txt && ! grep -q "No ciphers supporting Forward Secrecy" $E/testssl-8443.txt'
  check "tls13 : fichier reçu identique" 'cmp -s $E/tls13-witness.txt $WWW/witness.txt'
  check "tls13 : texte témoin absent de la capture" '! on_wire tls13 $W'
  check "tls13 : illisible sans secrets" '! tls_text $C/tls13.pcapng $dec | grep -q $W'
  check "tls13 : illisible avec la seule clé privée RSA" \
    '! tls_text $C/tls13.pcapng $dec -o "uat:rsa_keys:\"$S/server.key\",\"\"" | grep -q $W'
  check "tls13 : déchiffré avec le key log" \
    'tls_text $C/tls13.pcapng $dec -o tls.keylog_file:$S/tls13.keys | grep -q $W'
  check "tls13 : tls13-with-keys.pcapng s'ouvre déchiffré" 'tls_text $C/tls13-with-keys.pcapng $dec | grep -q $W'
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
  check "tls12 : fichier reçu identique" 'cmp -s $E/tls12-witness.txt $WWW/witness.txt'
  check "tls12 : suite TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c) négociée" '[ "$suite" = 0x009c ]'
  check "tls12 : testssl signale l'absence de forward secrecy" 'grep -q "No ciphers supporting Forward Secrecy" $E/testssl-8444.txt'
  check "tls12 : illisible sans clé" '! tls_text $C/tls12-rsa.pcapng $dec | grep -q $W'
  check "tls12 : session passée déchiffrée avec la clé privée RSA" \
    'tls_text $C/tls12-rsa.pcapng $dec -o "uat:rsa_keys:\"$S/server.key\",\"\"" | grep -q $W'
}

t_fake() {
  # Sans -WWW, s_server écrit ce qu'il reçoit : c'est le journal du faux serveur.
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
  check "fake : client vérifiant refuse le certificat (curl code 60)" '[ $verified -eq 60 ]'
  check "fake : rien reçu par le faux serveur avec vérification" '[ $leak_verified -eq 0 ]'
  check "fake : texte reçu par le faux serveur avec --insecure" 'grep -q $W $E/fake-server.log'
}

if [ $# -eq 0 ]; then
  setup
  set -- ping telnet http ssh tls13 tls12 fake
else
  [ -d $OUT ] || setup
fi
for t in "$@"; do "t_$t"; done
# Le conteneur tourne en root : out/ doit rester lisible et supprimable depuis l'hôte.
chmod -R a+rwX $OUT
echo "$FAILS échec(s)"
exit $((FAILS > 0))
