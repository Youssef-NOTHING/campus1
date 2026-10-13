# Campus — US1 : Connexion

## Démarrer
Installer Python 3.10 ou plus récent. Aucune dépendance supplémentaire.
Ouvrir un terminal dans le dossier extrait et lancer :

```sh
python server.py
```

Sur Linux/macOS, utiliser `python3 server.py` si nécessaire.
Ouvrir http://localhost:8000 dans le navigateur.

## Comptes de test
Professeur : professeur@campus.ma
Étudiant : etudiant@campus.ma
Mot de passe des deux comptes : Campus2026!

## Contenu
- index.html : interface responsive, CSS et JavaScript inclus.
- server.py : serveur local, base SQLite créée au premier lancement, mots de passe PBKDF2, sessions expirant après une heure, cookies HttpOnly et SameSite, protection CSRF et limitation des tentatives.
- /api/session : état de connexion.
- /api/login et /api/logout : connexion/déconnexion.
- /api/professeur et /api/etudiant : exemples d'accès contrôlé côté serveur.

L'aperçu hébergé et l'ouverture directe de index.html utilisent une simulation clairement signalée. Le serveur Python effectue la véritable vérification. La démo ne conserve pas la connexion après rechargement, contrairement au serveur local.

Le rôle provient de la base de données. L'interface HTML n'est pas une barrière de sécurité : les données protégées doivent toujours passer par les routes serveur. Les futures fonctions cours, PDF, devoirs et annonces ne sont pas encore implémentées.

Projet pédagogique local : les comptes de test sont publics, le serveur écoute uniquement sur votre PC. Pour une utilisation réelle, remplacer les comptes de test, utiliser HTTPS et un serveur de production, ajouter une gestion des comptes et un stockage durable des sessions. Le redémarrage du serveur déconnecte tous les utilisateurs.
