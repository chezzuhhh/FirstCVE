#!/bin/bash

sudo ip addr add 192.168.100.1/24 dev wlan0;
sudo ip link set wlan0 up;
sudo sysctl -w net.ipv4.ip_forward=1;
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE;

# HTTPS redirect
# sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-ports 8081
# mitmproxy --mode transparent --showhost -p 8081 -k

sudo systemctl restart hostapd;
sudo systemctl restart dnsmasq;
ip a;
