                          SecureChat – Application de messagerie sécurisée en Java
 SecureChat est une application de messagerie sécurisée destinée aux étudiants de l’ENSA Safi.
Le projet implémente un système client/serveur en Java utilisant des sockets TCP, du multithreading, et des mécanismes de chiffrement (AES & RSA) afin d’assurer la confidentialité des échanges.

 Objectifs du projet:
Implémenter une architecture client/serveur en Java.
Gérer plusieurs connexions simultanées via des threads.
Assurer la sécurisation complète des messages grâce aux algorithmes AES (symétrique) et RSA (asymétrique).
Appliquer une conception orientée objet claire et modulaire.
Permettre aux étudiants d’échanger des messages de manière confidentielle.

Structure du projet: 
Côté Serveur (package chiffrement) :
SecureChatServer.java      → Serveur principal, écoute & accepte les connexions
ClientHandler.java         → Thread dédié à chaque client connecté
CryptoUtils.java           → Génération RSA, AES, chiffrement/déchiffrement
message.java               → Modèle Message (pseudo + texte)
Côté Client (package chiffrementclient) :
SecureChatClient.java     → Client avec interface console
CryptoUtils.java          → Chiffrement/déchiffrement côté client
Message.java              → Représentation simple d'un message

Vérification du chiffrement avec Wireshark: 
Pour s’assurer que les messages sont bien chiffrés :
Ouvrir Wireshark et capturer le trafic réseau sur le port du serveur 5555
Filtrer par protocole TCP et le port du serveur tcp.port == 5555
Envoyer des messages depuis le client
Observation : les messages capturés apparaissent illisibles (texte chiffré en AES)


Équipe du projet 
AYOUB Botaina ,
LAASSAL Asmaa , 
OUYAHIA Salma , 
SRIJA Fatima-Zahra ,
WARDY Zakia


