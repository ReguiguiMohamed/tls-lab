# Règles pour les assistants IA

- Le seul périmètre est ce dépôt et les services locaux du conteneur. Aucune cible externe.
- Lancer `docker compose run --rm lab` avant chaque commit. Toutes les vérifications doivent réussir.
- Toute nouvelle observation du rapport reçoit sa vérification dans `lab.sh`.
- Ne jamais committer `out/`, des clés, des key logs ou des mots de passe réels.
- Pas de nouvelle famille de protocoles. Le périmètre est fixé dans `PLAN.md`.
- Documentation en français, phrases courtes, aucun contenu non vérifié.
