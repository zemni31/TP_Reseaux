#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Decouvrir_les_wifi.py - Version graphique simple
"""

import subprocess
import re
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext

def get_wifi_networks():
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True,
        text=True,
        encoding="cp1252"
    )
    output = result.stdout.encode("ascii", errors="ignore").decode()
    
    networks = []
    current_network = None
    current_bssid = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # SSID
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", line, re.IGNORECASE)
        if m:
            if current_network:
                if current_bssid:
                    current_network["bssids"].append(current_bssid)
                networks.append(current_network)
            current_network = {
                "ssid": m.group(1).strip(),
                "network_type": None,
                "authentication": None,
                "encryption": None,
                "bssids": []
            }
            current_bssid = None
            continue

        # Type réseau
        m = re.match(r"Type de rseau\s*:\s*(.*)", line, re.IGNORECASE)
        if m and current_network:
            current_network["network_type"] = m.group(1).strip()
            continue

        # Authentification
        m = re.match(r"Authentification\s*:\s*(.*)", line, re.IGNORECASE)
        if m and current_network:
            current_network["authentication"] = m.group(1).strip()
            continue

        # Chiffrement
        m = re.match(r"Chiffrement\s*:\s*(.*)", line, re.IGNORECASE)
        if m and current_network:
            current_network["encryption"] = m.group(1).strip()
            continue

        # BSSID
        m = re.match(r"BSSID\s+\d+\s*:\s*(.*)", line, re.IGNORECASE)
        if m and current_network:
            if current_bssid:
                current_network["bssids"].append(current_bssid)
            current_bssid = {
                "bssid": m.group(1).strip(),
                "signal": None,
                "radio_type": None,
                "channel": None
            }
            continue

        # Signal
        m = re.match(r"Signal\s*:\s*(\d+)%", line, re.IGNORECASE)
        if m and current_bssid:
            current_bssid["signal"] = int(m.group(1))
            continue

        # Type de radio
        m = re.match(r"Type de radio\s*:\s*(.*)", line, re.IGNORECASE)
        if m and current_bssid:
            current_bssid["radio_type"] = m.group(1).strip()
            continue

        # Canal
        m = re.match(r"Canal\s*:\s*(\d+)", line, re.IGNORECASE)
        if m and current_bssid:
            current_bssid["channel"] = int(m.group(1))
            continue

    if current_network:
        if current_bssid:
            current_network["bssids"].append(current_bssid)
        networks.append(current_network)

    return networks

class SimpleWiFiViewer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Wi-Fi Scanner")
        self.root.geometry("800x500")
        
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Titre
        title_label = ttk.Label(main_frame, text="🔍 Réseaux Wi-Fi", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Bouton scan
        self.scan_btn = ttk.Button(main_frame, text="Scanner", 
                                  command=self.scan)
        self.scan_btn.pack(pady=(0, 10))
        
        # Zone de texte
        self.text_area = scrolledtext.ScrolledText(main_frame, 
                                                  wrap=tk.WORD,
                                                  font=('Consolas', 10))
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Premier scan
        self.scan()
    
    def scan(self):
        self.scan_btn.config(state='disabled')
        self.text_area.delete(1.0, tk.END)
        
        self.text_area.insert(tk.END, "Scan en cours...\n")
        self.root.update()
        
        networks = get_wifi_networks()
        self.display_networks(networks)
        
        self.scan_btn.config(state='normal')
    
    def display_networks(self, networks):
        self.text_area.delete(1.0, tk.END)
        
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.text_area.insert(tk.END, f"[{now}] Réseaux détectés : {len(networks)}\n\n")
        
        if not networks:
            self.text_area.insert(tk.END, "Aucun réseau détecté")
            return
        
        for i, net in enumerate(networks, 1):
            self.text_area.insert(tk.END, f"--- Réseau #{i} ---\n")
            self.text_area.insert(tk.END, f"SSID           : {net.get('ssid')}\n")
            self.text_area.insert(tk.END, f"Type réseau    : {net.get('network_type')}\n")
            self.text_area.insert(tk.END, f"Authentification: {net.get('authentication')}\n")
            self.text_area.insert(tk.END, f"Chiffrement    : {net.get('encryption')}\n")
            
            if net.get("bssids"):
                for j, b in enumerate(net["bssids"], 1):
                    self.text_area.insert(tk.END, f"\n  BSSID #{j}:\n")
                    self.text_area.insert(tk.END, f"    Adresse MAC : {b.get('bssid')}\n")
                    self.text_area.insert(tk.END, f"    Signal      : {b.get('signal')}%\n")
                    self.text_area.insert(tk.END, f"    Type radio  : {b.get('radio_type')}\n")
                    self.text_area.insert(tk.END, f"    Canal       : {b.get('channel')}\n")
            
            self.text_area.insert(tk.END, "\n")
        
        # Ajouter des stats simples
        total_bssids = sum(len(n["bssids"]) for n in networks)
        self.text_area.insert(tk.END, f"\n{'='*50}\n")
        self.text_area.insert(tk.END, f"Total points d'accès : {total_bssids}\n")
    
    def run(self):
        self.root.mainloop()

def main():
    app = SimpleWiFiViewer()
    app.run()

if __name__ == "__main__":
    main()