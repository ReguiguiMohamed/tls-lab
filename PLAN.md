# Du trafic en clair à TLS : comparaison pratique des communications client-serveur

**Binôme : Mohamed et Firas. Remise : 15 novembre 2026.**

Ce document remplace les précédents plans SilentTrace. Le projet suit la nouvelle consigne du professeur : établir des communications client-serveur, les examiner dans Wireshark, montrer les données exposées par les protocoles non chiffrés et expliquer les protections, les conditions d'utilisation et les limites de TLS. Le machine learning, le padding et le cover traffic sortent du projet.

## 1. Le scénario

Mohamed et Firas utilisent un client pour se connecter à un serveur de laboratoire et échanger un texte fictif identifiable, par exemple `PROJET_TLS_MOHAMED_FIRAS`. Ils réalisent d'abord une session Telnet et une requête HTTP. Wireshark permet de retrouver les données en clair. Ils répètent ensuite les échanges avec SSH et HTTPS utilisant TLS 1.3, puis examinent ce qui reste visible : adresses, ports, négociation et volumes. La partie principale porte sur TLS : certificat vérifié, handshake, chiffrement des données, déchiffrement autorisé avec des secrets de session, et conséquences d'une mauvaise configuration ou de la compromission d'une clé dans une ancienne configuration.

Nous utilisons les implémentations existantes. Notre travail consiste à préparer un laboratoire reproductible, commenter les configurations, réaliser les tests et expliquer les captures.

## 2. Les protocoles retenus

| Communication | But pratique | Observation attendue |
| --- | --- | --- |
| Telnet classique | Ouvrir une session avec un compte temporaire de laboratoire et envoyer le texte témoin. | Identifiants et commandes peuvent être reconstitués en clair dans le flux. |
| HTTP | Télécharger un petit fichier texte depuis un serveur local. | Méthode, chemin, en-têtes et contenu lisibles. |
| SSH | Ouvrir une session avec OpenSSH et afficher le même texte témoin. | Identification initiale et négociation visibles, contenu de session chiffré. |
| HTTPS / TLS 1.3 | Télécharger le fichier par une connexion authentifiée et chiffrée. | Handshake et trafic TLS visibles, contenu HTTP inaccessible au simple observateur sans secrets. |

Telnet et SSH servent à comparer l'accès distant. HTTP et HTTPS servent à comparer le même usage applicatif avec et sans TLS. TLS est une couche de protection, pas une application équivalente à Telnet. SSH moderne est aussi un protocole sécurisé : il ne sera pas présenté comme faible.

Ces quatre cas suffisent. FTP, anciens SSL, VPN et autres protocoles ne sont pas nécessaires pour terminer le projet.

## 3. Architecture retenue

Utiliser un conteneur Docker Debian 13, construit depuis le `Dockerfile` du dépôt et lancé sans réseau (`network_mode: none`). Le client et les serveurs sont des processus distincts dans ce conteneur. Le même conteneur tourne à l'identique chez Mohamed, chez Firas et dans GitHub Actions. Sur Windows, seuls Docker Desktop et Wireshark sont nécessaires.

Ubuntu ou Kali dans WSL auraient demandé, sur chaque machine, d'installer les paquets, de créer le compte de test et de lancer sshd et inetd à la main, avec des versions qui divergent. Kali n'apporte rien ici : tous les outils du projet sont dans Debian.

```text
Conteneur tls-lab - Debian 13, sans réseau

Client Telnet -------- TCP/2323 -----> serveur Telnet
Client OpenSSH ------- TCP/2222 -----> instance OpenSSH du laboratoire
Client curl ---------- TCP/8080 -----> serveur HTTP
Client OpenSSL ------- TCP/8443 -----> serveur HTTPS / TLS 1.3
Client OpenSSL ------- TCP/8444 -----> serveur TLS 1.2 / RSA statique
Client de test ------- TCP/9443 -----> faux serveur avec certificat non approuvé

                 Capture sur l'interface loopback
                               |
                         fichiers PCAPNG
                               |
                    analyse dans Wireshark
```

Faire écouter les services sur `127.0.0.1`. Utiliser des ports élevés pour limiter les conflits. La capture loopback observe des échanges TCP réels sur le même ordinateur. Le rapport doit le préciser, sans présenter cette topologie comme une interception sur un réseau externe.

La capture se fait dans le conteneur avec dumpcap. Les fichiers arrivent dans `out/captures/` et s'ouvrent dans Wireshark sous Windows. Wireshark Windows ne voit pas la boucle locale du conteneur.

Le compte de test `labuser` est sans privilèges, avec un mot de passe fictif. Les configurations Telnet et SSH sont propres au laboratoire. Les services s'arrêtent avec le conteneur, aucun script d'arrêt n'est nécessaire.

## 4. Outils et rôle exact

| Outil | Utilisation |
| --- | --- |
| Wireshark | Examiner les protocoles, suivre les flux et déchiffrer TLS lorsque les secrets nécessaires sont fournis. |
| dumpcap et TShark | Enregistrer les échanges dans le conteneur et vérifier automatiquement chaque observation. |
| OpenSSL | Générer les certificats de test et établir les connexions TLS avec `s_server` et `s_client`. |
| OpenSSH | Fournir une véritable session SSH, avec vérification de la clé du serveur. |
| inetutils telnet et telnetd, lancé par inetd | Fournir une véritable session Telnet classique, sans la remplacer par un simple socket TCP. |
| Python `http.server` | Servir le fichier témoin par HTTP. |
| curl | Tester HTTP et HTTPS avec vérification du certificat. |
| testssl.sh | Vérifier les versions et suites proposées par nos seuls serveurs TLS. C'est un outil d'audit, pas de déchiffrement. |

Utiliser les versions installées et enregistrer leur numéro. Si testssl.sh impose trop de dépendances, les négociations forcées avec OpenSSL suffisent pour vérifier nos profils. Aucun code cryptographique maison n'est requis.

## 5. Lecture, décodage et déchiffrement

Ces distinctions doivent apparaître dans le rapport et à l'oral :

- **Telnet et HTTP classiques : lecture en clair.** Wireshark reconstitue des données qui n'étaient pas chiffrées. Ce n'est pas une attaque cryptographique.
- **Base64 : décodage.** Si nous montrons un exemple HTTP Basic, retrouver `utilisateur:mot_de_passe` signifie décoder un encodage, pas casser un chiffrement. Cet exemple n'est pas nécessaire au noyau.
- **TLS avec secrets fournis : déchiffrement autorisé.** Wireshark dispose de données secrètes issues d'un endpoint du laboratoire.
- **TLS avec RSA statique et clé privée compromise : déchiffrement rétrospectif.** Cette démonstration montre l'absence de forward secrecy de cette configuration.

Nous ne promettons pas de casser TLS moderne ou SSH en observant seulement une capture. [1][2]

## 6. Déroulement des manipulations

### Test 1 - Connectivité et capture

Lancer `ping 127.0.0.1` dans le conteneur. Identifier l'interface loopback et enregistrer une première capture. Vérifier que le fichier s'ouvre dans Wireshark et que les paquets du bon port sont présents. Ping prouve la connectivité locale, pas la sécurité.

### Test 2 - Telnet : retrouver les données exposées

Lancer une instance Telnet locale, se connecter avec le compte temporaire et afficher le texte témoin. Capturer la connexion complète. Utiliser Follow TCP Stream pour reconstituer les échanges, notamment les saisies réparties sur plusieurs paquets.

Livrer une capture annotée du login et du texte témoin. Vérifier réellement leur présence avant de conclure. Un mot de passe masqué dans le terminal n'est pas nécessairement protégé sur le réseau.

### Test 3 - HTTP : retrouver la requête et le fichier

Lancer le serveur HTTP dans un dossier ne contenant que le fichier de démonstration. Télécharger ce fichier avec curl. Montrer la méthode GET, le chemin demandé, la réponse et le texte témoin.

Livrer une capture et une vérification que le fichier reçu correspond au fichier envoyé.

### Test 4 - SSH : observer une session protégée

Lancer une instance OpenSSH avec un fichier de configuration du projet, sur le port 2222. Comparer l'empreinte de sa clé avec celle annoncée au client avant de l'accepter. Ouvrir la session et afficher le texte témoin.

Montrer l'identification du protocole, la négociation et les paquets chiffrés. Expliquer que TLS et SSH utilisent des mécanismes différents. Le protocole SSH peut être sécurisé sans certificat X.509. Nous ne tentons pas de déchiffrer cette session SSH. [2]

### Test 5 - TLS 1.3 : le cas principal

Créer un certificat local avec un Subject Alternative Name adapté à `localhost`, puis le déclarer explicitement comme certificat de confiance du client pour le laboratoire. Ne pas modifier le magasin de confiance global de Windows.

Servir le même fichier par HTTPS avec OpenSSL. Le client vérifie à la fois la confiance du certificat et le nom du serveur. Avec `s_client`, activer explicitement `-verify_return_error` et `-verify_hostname localhost`, avec le fichier de confiance approprié : sans ces précautions, l'outil de diagnostic peut continuer après une erreur de vérification. [3]

Capturer la connexion dès son ouverture. Montrer ClientHello, ServerHello, la version réellement négociée et la suite cryptographique. En TLS 1.3, une partie du handshake, dont le certificat du serveur, est chiffrée. Ne pas promettre de lire ce certificat dans la capture passive : l'afficher côté client ou après le déchiffrement autorisé du test suivant. [4]

Vérifier la réception correcte du fichier. Avec un profil Wireshark sans clés et une capture sans secrets intégrés, le texte témoin n'est pas lisible dans les données applicatives.

### Test 6 - Wireshark déchiffre TLS avec les secrets de session

Créer une nouvelle session TLS 1.3 avec l'option OpenSSL `-keylogfile`. Importer le fichier de secrets dans le profil TLS de Wireshark et retrouver la requête ainsi que le contenu du fichier.

Présenter les deux vues : sans secrets puis avec secrets. La conclusion est que la sécurité dépend aussi de la protection des endpoints et des secrets de session. Ce test ne montre pas une faiblesse du chiffrement TLS. [1][3]

Conserver la capture originale sans secrets intégrés. Séparer les profils Wireshark afin que les clés d'un test ne faussent pas les observations suivantes. Les clés de démonstration restent clairement identifiées comme secrets jetables du laboratoire.

### Test 7 - Ancienne configuration TLS : absence de forward secrecy

Lancer un serveur dédié TLS 1.2 avec certificat RSA et échange de clés **RSA statique**, par exemple la suite OpenSSL `AES128-GCM-SHA256`, soit `TLS_RSA_WITH_AES_128_GCM_SHA256`. Forcer la même suite côté client et vérifier la négociation effective. [1][3]

Capturer une nouvelle connexion complète, sans reprise de session et sans exporter ses secrets. Fournir ensuite à Wireshark la clé privée RSA du serveur. Retrouver le contenu de cette session passée.

La faiblesse montrée est précise : si la clé privée du serveur est compromise, les anciennes sessions enregistrées peuvent être déchiffrées dans cette configuration. Ce n'est pas une cassure d'AES et ce n'est pas vrai de toutes les configurations TLS 1.2. Une suite TLS 1.2 utilisant ECDHE n'a pas cette même propriété. [1]

Refaire la comparaison avec notre session TLS 1.3 utilisant un échange éphémère : la seule clé privée du certificat ne permet pas le même déchiffrement. Utiliser une session sans key log et un profil propre. Le test 6 reste distinct, car les secrets de session permettent, eux, le déchiffrement. [1][4]

OpenSSL 3.5 du conteneur négocie la suite `0x009c` sans abaisser son niveau de sécurité. La configuration globale du système n'est pas modifiée. Contrôle croisé : avec la suite ECDHE-RSA-AES128-GCM-SHA256 sur le même serveur, la même clé privée ne déchiffre plus rien.

### Test 8 - Mauvaise vérification du certificat

Lancer un faux serveur local avec un autre certificat qui n'appartient pas à la confiance du client. Le client correctement configuré doit refuser la connexion avant d'envoyer la donnée témoin.

Répéter avec la vérification volontairement désactivée, par exemple `curl --insecure`, uniquement vers ce serveur de laboratoire. Montrer que le faux serveur reçoit alors le texte de test, malgré le chiffrement de la connexion. Revenir ensuite au client qui vérifie le certificat et montrer le refus.

La conclusion est que le chiffrement seul ne garantit pas l'identité du destinataire. Ce test illustre le risque d'usurpation lorsque la vérification est désactivée. Sans proxy transparent ni redirection réseau, nous le présentons comme un test de faux serveur, pas comme une interception MITM complète. [5]

## 7. Ce que nous expliquerons sur TLS

**Points forts :** confidentialité du contenu, intégrité des données, authentification du serveur lorsque le certificat et son nom sont correctement vérifiés, et forward secrecy dans notre profil TLS 1.3 avec échange éphémère. TLS 1.3 exclut notamment l'échange RSA statique. [4]

**Conditions et limites :** un endpoint voit les données qu'il traite, des secrets de session divulgués permettent leur déchiffrement, une vérification de certificat désactivée retire une protection essentielle, et le chiffrement ne masque pas toutes les métadonnées réseau.

Un certificat RSA n'implique pas forcément un échange RSA statique. RSA peut servir à signer le handshake alors qu'ECDHE établit les secrets. Nous devons savoir distinguer ces deux rôles.

Nous ne qualifions pas TLS 1.3 correctement configuré de « faible ». Nous montrons les différences entre un protocole en clair, un ancien choix cryptographique et une mauvaise utilisation d'un protocole moderne.

## 8. Répartition du travail

| Mohamed | Firas |
| --- | --- |
| Préparer les profils OpenSSL et les certificats locaux. | Préparer la capture et les profils Wireshark. |
| Mettre en place TLS 1.3, TLS 1.2 RSA statique et le faux serveur. | Mettre en place Telnet, HTTP et l'instance SSH, avec configurations isolées. |
| Vérifier les clients, les certificats et la livraison des fichiers. | Annoter les captures et réaliser les déchiffrements Wireshark. |
| Rédiger architecture, fonctionnement de TLS et explication des configurations. | Rédiger comparaison des protocoles, résultats, screenshots et limites. |

Ensemble : vérifier chaque manipulation, construire le tableau final, préparer les slides et échanger les rôles avant la soutenance. Aucun membre ne doit dépendre de l'autre pour expliquer un test.

## 9. Preuves à conserver

Pour chaque test : commande utilisée, configuration, version des outils, capture complète, screenshot utile et résultat observé. Les colonnes « observé » restent vides tant que la manipulation n'a pas été réalisée.

| Test | Résultat attendu | Preuve |
| --- | --- | --- |
| Ping | Réponse locale. | Screenshot du terminal. |
| Telnet | Données du laboratoire lisibles. | Flux TCP reconstitué. |
| HTTP | Requête et fichier lisibles. | Capture HTTP annotée. |
| SSH | Session fonctionnelle, contenu chiffré. | Terminal et capture SSH. |
| TLS 1.3 vérifié | Connexion acceptée et fichier correct. | Vérification client et capture sans secrets. |
| TLS 1.3 + key log | Contenu déchiffré avec secrets fournis. | Même session avant et après import des secrets. |
| TLS 1.2 RSA statique | Ancienne session déchiffrée avec clé privée du serveur. | Suite négociée, capture et résultat Wireshark. |
| Faux certificat, vérification active | Connexion refusée. | Erreur client et absence de réception du texte témoin. |
| Faux certificat, vérification désactivée | Donnée reçue par le faux serveur. | Sortie client et réception côté serveur. |

L'absence d'un texte dans une capture ne prouve pas à elle seule la solidité du chiffrement. Nous la relions à la configuration négociée et au fonctionnement documenté du protocole.

## 10. Organisation des fichiers

| Chemin | Contenu |
| --- | --- |
| `Dockerfile`, `compose.yaml` | Environnement du laboratoire. |
| `lab.sh` | Préparation, services, captures et vérifications. |
| `config/` | `inetd.conf` et `sshd_config` du laboratoire. |
| `fixtures/www/` | Fichier témoin servi par HTTP et HTTPS. |
| `out/` | Généré à chaque exécution, exclu du dépôt : `secrets/`, `captures/`, `evidence/`, `results.txt`. |

`lab.sh` régénère les clés et certificats de démonstration à chaque exécution complète. Ne pas publier les mots de passe personnels, clés SSH existantes ou secrets d'autres projets. Les seules cibles sont les services locaux préparés pour ce travail.

## 11. Ordre de réalisation

| Dates | Travail et critère de fin |
| --- | --- |
| 12-18 octobre | Vérifier les outils, préparer la capture, réaliser Ping, HTTP et TLS 1.3. Le même fichier est reçu dans les deux modes. |
| 19-25 octobre | Ajouter Telnet et SSH. Les quatre communications fonctionnent et disposent de captures. |
| 26 octobre-1 novembre | Réaliser les tests key log, RSA statique et faux certificat. Documenter les conditions de chaque résultat. |
| 2-8 novembre | Terminer le rapport, le tableau comparatif et les slides. Figer les configurations. |
| 9-14 novembre | Rejouer depuis un démarrage propre, préparer les captures de secours et répéter les questions. |
| 15 novembre | Remise et soutenance. |

Si un outil impose une configuration disproportionnée, garder l'objectif du test et utiliser l'alternative documentée. Ne pas ajouter de nouvelles familles de protocoles.

## 12. Rapport et soutenance

Le rapport suit le chemin de la démonstration : objectif, architecture, configurations, Telnet/HTTP, SSH, TLS 1.3, déchiffrements, faux certificat, bilan et sources. Il contient les captures Ping et Wireshark demandées. Le volet TLS occupe environ la moitié de l'exposé.

Déroulé oral : montrer une donnée en clair, montrer la communication protégée, expliquer le handshake TLS, déchiffrer avec les secrets connus, comparer RSA statique et échange éphémère, puis finir par le refus et l'acceptation du faux certificat selon la configuration client.

Questions à maîtriser : chiffrement et encodage, confidentialité et authentification, certificat et clé privée, TLS et HTTPS, TLS et SSH, clé de session et clé de certificat, forward secrecy, lecture passive et faux serveur, rôle exact de Wireshark.

Les quatre éléments de la note sont couverts : rapport documenté, présentation claire, services et tests fonctionnels, compréhension des concepts. Une capture externe utilisée en secours doit être annoncée comme telle.

## 13. État au 12 octobre 2026

Le laboratoire tourne dans le conteneur et `lab.sh` vérifie 27 observations, toutes réussies en 57 secondes sur le PC de Mohamed. Versions enregistrées dans `out/evidence/versions.txt` : OpenSSL 3.5.7, OpenSSH 10.0p1, inetutils-telnetd 2.6, curl 8.14.1, TShark 4.4.19, Python 3.13.5, testssl.sh 3.2.1.

Le TLS 1.3 de notre serveur négocie `TLS_AES_256_GCM_SHA384` avec le groupe hybride post-quantique `X25519MLKEM768`, valeur par défaut d'OpenSSL 3.5. Wireshark déchiffre cette session avec le key log comme les autres.

Restent les parties humaines : captures d'écran Wireshark annotées, rapport, slides et répétition.

## 14. Sources techniques

[1] [Wireshark : TLS et conditions de déchiffrement](https://wiki.wireshark.org/TLS/) — key logs, RSA statique, limites liées à ECDHE, TLS 1.3 et reprise de session. Fournit aussi des captures pédagogiques.

[2] [Wireshark : SSH](https://wiki.wireshark.org/SSH) — parties observables et contenu chiffré d'une session SSH.

[3] [OpenSSL s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/) et [s_server](https://docs.openssl.org/3.0/man1/openssl-s_server/) — profils de négociation, vérification des certificats et export des secrets.

[4] [RFC 8446 : TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) — handshake, protection des données et changements cryptographiques par rapport aux anciennes versions.

[5] [Documentation curl](https://curl.se/docs/manpage.html) — vérification TLS, fichier de confiance et effet de `--insecure`.

[6] [testssl.sh](https://github.com/testssl/testssl.sh) — audit des versions et suites de nos serveurs. Les résultats d'un scanner doivent être expliqués et ne remplacent pas les captures.

[7] [Guide Wireshark](https://www.wireshark.org/docs/wsug_html/) — capture, filtres, suivi des flux et secrets TLS.

[8] [OpenSSH](https://www.openssh.com/manual.html) — configuration client/serveur et vérification des clés d'hôte.
