#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan Wi-Fi et connexion automatique - Interface simple et claire
"""

import subprocess
import re
import time
import tkinter as tk
from tkinter import ttk
from datetime import datetime

REFRESH_INTERVAL = 1.0
INTERFACE_NAME = "Wi-Fi 2"
AUTO_CONNECT = True

class SimpleWiFiScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Wi-Fi Auto Connect")
        self.root.geometry("800x600")
        
        # Variables
        self.profiles = set()
        self.current_ssid = None
        self.best_ssid = None
        
        # Création de l'interface
        self.create_widgets()
        
        # Initialisation
        self.refresh_profiles()
        self.start_scan()
        
    def create_widgets(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text="Wi-Fi Scanner", 
                 font=('Arial', 16, 'bold')).pack(side=tk.LEFT)
        
        # Frame d'info connexion
        self.connection_frame = ttk.LabelFrame(main_frame, text="Connexion actuelle", padding=10)
        self.connection_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.connection_label = ttk.Label(self.connection_frame, text="Non connecté", font=('Arial', 11))
        self.connection_label.pack()
        
        # Frame pour les réseaux
        network_frame = ttk.LabelFrame(main_frame, text="Réseaux disponibles", padding=10)
        network_frame.pack(fill=tk.BOTH, expand=True)
        
        # Canvas avec scroll
        self.canvas = tk.Canvas(network_frame, bg='white', highlightthickness=0)
        scrollbar = ttk.Scrollbar(network_frame, orient="vertical", command=self.canvas.yview)
        
        self.networks_frame = ttk.Frame(self.canvas)
        self.networks_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        self.canvas.create_window((0, 0), window=self.networks_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Boutons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        self.connect_btn = ttk.Button(button_frame, text="Connecter au meilleur", 
                                     command=self.connect_to_best)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Rafraîchir profils", 
                  command=self.refresh_profiles).pack(side=tk.LEFT, padx=5)
        
        # Barre de statut
        self.status_label = ttk.Label(main_frame, text="Prêt", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, pady=(10, 0))
        
    def refresh_profiles(self):
        """Rafraîchit les profils"""
        self.profiles = self.get_profiles()
        self.status_label.config(text=f"{len(self.profiles)} profils disponibles")
        
    def get_wifi_networks(self):
        """Récupère les réseaux Wi-Fi"""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                encoding="cp1252",
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout.encode("ascii", errors="ignore").decode()
            
            networks = []
            current_network = None
            current_bssid = None

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue

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

                m = re.match(r"Type de rseau\s*:\s*(.*)", line, re.IGNORECASE)
                if m and current_network:
                    current_network["network_type"] = m.group(1).strip()
                    continue

                m = re.match(r"Authentification\s*:\s*(.*)", line, re.IGNORECASE)
                if m and current_network:
                    current_network["authentication"] = m.group(1).strip()
                    continue

                m = re.match(r"Chiffrement\s*:\s*(.*)", line, re.IGNORECASE)
                if m and current_network:
                    current_network["encryption"] = m.group(1).strip()
                    continue

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

                m = re.match(r"Signal\s*:\s*(\d+)%", line, re.IGNORECASE)
                if m and current_bssid:
                    current_bssid["signal"] = int(m.group(1))
                    continue

                m = re.match(r"Type de radio\s*:\s*(.*)", line, re.IGNORECASE)
                if m and current_bssid:
                    current_bssid["radio_type"] = m.group(1).strip()
                    continue

                m = re.match(r"Canal\s*:\s*(\d+)", line, re.IGNORECASE)
                if m and current_bssid:
                    current_bssid["channel"] = int(m.group(1))
                    continue

            if current_network:
                if current_bssid:
                    current_network["bssids"].append(current_bssid)
                networks.append(current_network)

            return networks
        except Exception as e:
            self.status_label.config(text=f"Erreur: {str(e)}")
            return []
    
    def get_profiles(self):
        """Récupère les profils Wi-Fi"""
        try:
            out = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True, text=True, encoding="cp1252",
                creationflags=subprocess.CREATE_NO_WINDOW
            ).stdout
            profiles = set()
            for line in out.splitlines():
                line = line.strip()
                m = re.match(r"Profil\s*.*:\s*(.*)", line, re.IGNORECASE)
                if m:
                    profiles.add(m.group(1).strip())
            return profiles
        except:
            return set()
    
    def get_current_ssid(self):
        """Récupère le SSID connecté"""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, encoding="cp1252",
                creationflags=subprocess.CREATE_NO_WINDOW
            ).stdout
            m = re.search(r"SSID\s*:\s*(.+)", result)
            if m:
                return m.group(1).strip()
            return None
        except:
            return None
    
    def connect_to_ssid(self, ssid):
        """Connecte à un SSID"""
        try:
            cmd = ["netsh", "wlan", "connect", f"name={ssid}", f"interface={INTERFACE_NAME}"]
            subprocess.run(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
            self.status_label.config(text=f"Connexion à {ssid}...")
        except Exception as e:
            self.status_label.config(text=f"Erreur: {str(e)}")
    
    def connect_to_best(self):
        """Connecte au meilleur réseau"""
        if self.best_ssid:
            self.connect_to_ssid(self.best_ssid)
    
    def create_network_card(self, parent, network):
        """Crée une carte pour un réseau"""
        ssid = network.get("ssid", "")
        has_profile = ssid in self.profiles
        
        # Couleur de fond
        bg_color = "#f0f8ff"  # Bleu clair par défaut
        
        if ssid == self.current_ssid:
            bg_color = "#d4edda"  # Vert clair pour connecté
        elif ssid == self.best_ssid:
            bg_color = "#fff3cd"  # Jaune clair pour meilleur
        
        # Frame de la carte
        card = tk.Frame(parent, bg=bg_color, bd=1, relief=tk.RAISED, padx=10, pady=8)
        card.pack(fill=tk.X, pady=5)
        
        # Header avec SSID
        header_frame = tk.Frame(card, bg=bg_color)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Icône
        icon = "📶"
        if ssid == self.current_ssid:
            icon = "✅"
        elif ssid == self.best_ssid:
            icon = "⭐"
        elif not has_profile:
            icon = "⭕"
        
        tk.Label(header_frame, text=icon, bg=bg_color, font=('Arial', 12)).pack(side=tk.LEFT, padx=(0, 10))
        
        # SSID
        ssid_label = tk.Label(header_frame, text=ssid, bg=bg_color, 
                            font=('Arial', 11, 'bold'))
        ssid_label.pack(side=tk.LEFT)
        
        # Signal
        if network.get("bssids"):
            best_signal = max((b.get("signal", 0) for b in network["bssids"]), default=0)
            signal_color = self.get_signal_color(best_signal)
            tk.Label(header_frame, text=f"{best_signal}%", bg=bg_color,
                   font=('Arial', 10, 'bold'), fg=signal_color).pack(side=tk.RIGHT)
        
        # Détails
        details_frame = tk.Frame(card, bg=bg_color)
        details_frame.pack(fill=tk.X)
        
        # Informations
        info_text = f"Type: {network.get('network_type', 'N/A')} | "
        info_text += f"Auth: {network.get('authentication', 'N/A')}"
        
        tk.Label(details_frame, text=info_text, bg=bg_color,
                font=('Arial', 9)).pack(anchor=tk.W)
        
        # Points d'accès
        if network.get("bssids"):
            ap_frame = tk.Frame(details_frame, bg=bg_color)
            ap_frame.pack(fill=tk.X, pady=(3, 0))
            
            for b in network["bssids"][:2]:  # Affiche 2 max
                ap_info = f"MAC: {b.get('bssid', '')[:17]}... "
                ap_info += f"| Signal: {b.get('signal', 0)}% "
                ap_info += f"| Canal: {b.get('channel', '')}"
                
                tk.Label(ap_frame, text=ap_info, bg=bg_color,
                        font=('Consolas', 8)).pack(anchor=tk.W)
        
        # Indicateur profil
        if not has_profile:
            tk.Label(card, text="⚠ Pas de profil", bg=bg_color,
                   font=('Arial', 9, 'italic'), fg='#666').pack(anchor=tk.W, pady=(5, 0))
        
        return card
    
    def get_signal_color(self, signal):
        """Retourne une couleur selon le signal"""
        if signal >= 80:
            return "green"
        elif signal >= 60:
            return "orange"
        else:
            return "red"
    
    def update_display(self):
        """Met à jour l'affichage"""
        networks = self.get_wifi_networks()
        self.current_ssid = self.get_current_ssid()
        
        # Trouver le meilleur réseau
        self.best_ssid = None
        best_signal = -1
        
        for net in networks:
            ssid = net.get("ssid")
            if ssid in self.profiles:
                for b in net.get("bssids", []):
                    s = b.get("signal")
                    if s is not None and s > best_signal:
                        best_signal = s
                        self.best_ssid = ssid
        
        # Effacer les anciennes cartes
        for widget in self.networks_frame.winfo_children():
            widget.destroy()
        
        # Afficher les réseaux
        if networks:
            for net in networks:
                self.create_network_card(self.networks_frame, net)
            
            # Mettre à jour l'info connexion
            conn_text = f"Connecté à: {self.current_ssid}" if self.current_ssid else "Non connecté"
            if self.best_ssid and self.best_ssid != self.current_ssid:
                conn_text += f" | Meilleur disponible: {self.best_ssid}"
            
            self.connection_label.config(text=conn_text)
            
            # Activer/désactiver le bouton
            if self.best_ssid and self.best_ssid != self.current_ssid:
                self.connect_btn.config(state='normal')
            else:
                self.connect_btn.config(state='disabled')
        else:
            tk.Label(self.networks_frame, text="Aucun réseau détecté", 
                   font=('Arial', 11)).pack(pady=20)
        
        # Connexion automatique
        if AUTO_CONNECT and self.best_ssid and self.best_ssid != self.current_ssid:
            self.connect_to_ssid(self.best_ssid)
    
    def start_scan(self):
        """Démarre le scan périodique"""
        self.update_display()
        self.root.after(int(REFRESH_INTERVAL * 1000), self.start_scan)
    
    def run(self):
        self.root.mainloop()

def main():
    app = SimpleWiFiScanner()
    app.run()

if __name__ == "__main__":
    main()