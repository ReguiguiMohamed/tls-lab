# Du trafic en clair à TLS

Laboratoire reproductible qui compare Telnet, HTTP, SSH et TLS dans Wireshark, avec une vérification automatique de chaque observation.

Projet de cybersécurité de Mohamed Reguigui et Firas Taktak, remise le 15 novembre 2026. Le plan complet, la méthode et les sources sont dans [PLAN.md](PLAN.md).

Tout tourne dans un conteneur Debian 13 sans réseau : clients, serveurs et captures partagent sa seule interface loopback. Une commande prépare les certificats, lance chaque service, capture la session, puis contrôle avec TShark ce qui est lisible et ce qui ne l'est pas.

## Démarrage

Prérequis sur Windows : [Docker Desktop](https://www.docker.com/products/docker-desktop/) démarré, et Wireshark pour ouvrir les captures.

```bash
winget install WiresharkFoundation.Wireshark
```

```bash
git clone https://github.com/ReguiguiMohamed/tls-lab.git
```

```bash
cd tls-lab
```

```bash
docker compose run --rm lab
```

La première exécution construit l'image en quelques minutes. Les suivantes prennent environ une minute. La dernière ligne doit afficher `0 échec(s)`.

Pour un seul test, ou pour explorer à la main pendant la soutenance :

```bash
docker compose run --rm lab bash lab.sh tls13 tls12
```

```bash
docker compose run --rm lab bash
```

## Tests

| Test | Ports | Ce que `lab.sh` vérifie |
| --- | --- | --- |
| `ping` | ICMP | 3 réponses sur `lo`. |
| `telnet` | 2323 | Identifiant, mot de passe et texte témoin lisibles dans la capture. |
| `http` | 8080 | Requête `GET` et texte témoin lisibles, fichier reçu identique. |
| `ssh` | 2222 | Clé d'hôte vérifiée, session ouverte, bannière `SSH-2.0` visible, texte témoin absent. |
| `tls13` | 8443 | Certificat et nom vérifiés, TLS 1.3 négocié, texte absent sans secrets et avec la seule clé RSA, présent avec le key log. |
| `tls12` | 8444 | Suite `TLS_RSA_WITH_AES_128_GCM_SHA256`, session passée déchiffrée avec la clé privée du serveur, testssl.sh signale l'absence de forward secrecy. |
| `fake` | 9443 | Le client qui vérifie refuse le faux certificat et n'envoie rien. Avec `--insecure`, le faux serveur reçoit le texte témoin. |

Le serveur TLS 1.3 et le serveur TLS 1.2 utilisent la même clé RSA. Elle déchiffre la session TLS 1.2 et pas la session TLS 1.3, ce qui isole l'effet de l'échange RSA statique.

## Résultats

| Fichier | Contenu |
| --- | --- |
| `out/results.txt` | Une ligne `PASS` ou `FAIL` par vérification. |
| `out/captures/*.pcapng` | Une capture originale par test, sans secrets intégrés. |
| `out/captures/tls13-with-keys.pcapng` | La session TLS 1.3 avec son key log intégré : elle s'ouvre déjà déchiffrée. |
| `out/evidence/` | Versions des outils, sorties des clients, journal du faux serveur, rapports testssl.sh. |
| `out/secrets/` | CA, clés et key log jetables du laboratoire, régénérés à chaque exécution. |

## Wireshark sous Windows

1. **Telnet et HTTP.** Ouvrir la capture, clic droit sur un paquet, Follow, TCP Stream.
2. **TLS 1.3 sans secrets.** Ouvrir `tls13.pcapng` : handshake visible, Application Data illisible.
3. **TLS 1.3 avec secrets.** Ouvrir `tls13-with-keys.pcapng`, ou régler Edit, Preferences, Protocols, TLS, (Pre)-Master-Secret log filename sur `out\secrets\tls13.keys`.
4. **TLS 1.2 RSA statique.** Dans Edit, Preferences, Protocols, TLS, RSA keys list, ajouter `out\secrets\server.key`, puis ouvrir `tls12-rsa.pcapng`.

Vider ces deux réglages TLS avant les observations suivantes, ou utiliser un profil Wireshark par test.

## Dépôt

| Chemin | Contenu |
| --- | --- |
| [`lab.sh`](lab.sh) | Préparation, services, captures et vérifications. |
| [`Dockerfile`](Dockerfile), [`compose.yaml`](compose.yaml) | Environnement Debian 13 épinglé par digest, lancé sans réseau. |
| [`config/`](config/) | `inetd.conf` pour Telnet, `sshd_config` de l'instance SSH du laboratoire. |
| [`fixtures/www/`](fixtures/www/) | Fichier témoin `PROJET_TLS_MOHAMED_FIRAS`. |
| [`.github/workflows/lab.yml`](.github/workflows/lab.yml) | Rejoue le laboratoire à chaque push et publie `out/` en artefact. |
| [`AGENTS.md`](AGENTS.md) | Règles pour les assistants IA. |

## Construit avec

OpenSSL 3.5, OpenSSH 10.0, inetutils telnetd 2.6, Python `http.server`, curl 8.14, TShark et dumpcap 4.4, testssl.sh 3.2, Debian 13.
