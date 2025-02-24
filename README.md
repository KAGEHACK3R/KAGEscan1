# KAGEscan1 - Master Edition

**Auteur** : GUY KOUAKOU (Pseudo : KAGEHACKER)  
**Date** : Février 2025  
**Licence** : MIT (en français) - Usage légal et éthique uniquement  

KAGEscan1 - Master Edition est un outil de scan réseau ultra-puissant conçu pour détecter les hôtes actifs, analyser les ports ouverts, identifier les systèmes d’exploitation et repérer les vulnérabilités potentielles via les bannières des services. Avec une interface graphique futuriste et des capacités multi-protocole (TCP/UDP), cet outil est destiné aux administrateurs réseau et aux professionnels de la sécurité pour des audits sur des réseaux autorisés.

## Fonctionnalités principales

- **Détection avancée des hôtes** : Scan ARP rapide et TCP furtif pour contourner les blocages ICMP.
- **Scan multi-protocole** : Prise en charge de TCP, UDP ou les deux simultanément.
- **Analyse intelligente** : Détection des OS via TTL et identification des vulnérabilités potentielles à partir des bannières (ex: Apache, OpenSSH).
- **Ports personnalisables** : Support des plages (ex: 20-100) et option "random" pour scanner 100 ports aléatoires.
- **Interface graphique moderne** : Tableau interactif, graphique en temps réel, thème sombre cyberpunk.
- **Rapports riches** : Exportation en JSON, CSV, TXT ou HTML interactif.
- **Furtivité** : Délais aléatoires pour éviter la détection par les systèmes IDS/IPS.
- **Puissance brute** : Jusqu’à 2000 threads pour des scans ultra-rapides.

## Prérequis

- **Python** : 3.11 ou supérieur
- **Dépendances** :
  - `scapy` (pour le scan ARP) : `pip install scapy`
  - `tqdm` (progression) : `pip install tqdm`
  - `matplotlib` (graphiques) : `pip install matplotlib`
- **Permissions** : Exécuter avec `sudo` sur Linux pour le scan ARP.
- **Systèmes supportés** : Testé sur Linux, compatible Windows avec ajustements.

## Installation

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/KAGEHACKER/kagescan1.git
   cd kagescan1
