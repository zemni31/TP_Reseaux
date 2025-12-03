# Wi-Fi Scanner Projects

Ce dossier contient plusieurs scripts Python pour scanner et afficher les réseaux Wi-Fi sur Windows, avec différentes interfaces et fonctionnalités.

## Contenu du dossier

1. **Decouvrir_les_wifi.py (Version avancée GUI)**  
   - Scanner Wi-Fi complet avec interface graphique Tkinter.  
   - Affiche tous les réseaux et leurs points d'accès (BSSID).  
   - Couleurs pour la force du signal et tri des colonnes.  
   - Statistiques et export CSV.

2. **Associer_meilleur_ap.py (Auto Connect)**  
   - Scanner simple avec interface Tkinter.  
   - Détecte le meilleur réseau disponible parmi les profils existants.  
   - Connexion automatique au meilleur réseau.  
   - Affiche les informations des points d'accès et le statut de connexion.

3. **wifi_signal.py (Version texte GUI simple)**  
   - Scanner Wi-Fi minimaliste avec interface graphique Tkinter.  
   - Affiche tous les réseaux et BSSID dans une zone de texte.  
   - Statistiques simples sur le nombre de points d'accès détectés.

4. **courbePuissance.py (Affichage graphique du signal)**  
   - Affiche l’évolution de la puissance du signal Wi-Fi dans le temps.  
   - Génère des courbes pour visualiser la force du signal de différents points d’accès.  
   - Utile pour l’analyse de la couverture Wi-Fi ou le choix du meilleur emplacement pour un routeur.

## Installation et utilisation

1. Cloner ou télécharger ce dossier.
2. Exécuter le script Python souhaité sur Windows:
   ```bash
   python Decouvrir_les_wifi.py
   python Associer_meilleur_ap.py
   python wifi_signal.py
   python courbePuissance.py
