#!/bin/bash

# Adresse IP cible pour les paquets UDP
TARGET_IP="192.168.1.1"
# Port cible pour les paquets UDP
TARGET_PORT="12345"
# Adresse MAC cible pour les paquets ARP
TARGET_MAC="ff:ff:ff:ff:ff:ff"
# Interface réseau à utiliser
INTERFACE="eth0"

# Vérifier si hping3 et arping sont installés
if ! command -v hping3 &> /dev/null
then
    echo "hping3 could not be found. Please install it and try again."
    exit
fi

if ! command -v arping &> /dev/null
then
    echo "arping could not be found. Please install it and try again."
    exit
fi

# Boucle infinie pour envoyer les paquets
while true; do
    # Envoyer un paquet UDP
    sudo hping3 --udp -p $TARGET_PORT -c 1 $TARGET_IP
    
    # Envoyer un paquet ARP
    sudo arping -c 1 -I $INTERFACE $TARGET_IP
    
    # Attendre 1 seconde avant d'envoyer les paquets suivants
    sleep 1
done
