#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Decouvrir_les_wifi.py
Scan Wi-Fi networks avec interface graphique Tkinter
"""

import subprocess
import re
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import webbrowser

class WiFiScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Scanner Wi-Fi - Découvrir les réseaux")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.networks = []
        self.scanning = False
        self.auto_scan = False
        
        # Configuration du style
        self.setup_styles()
        
        # Création de l'interface
        self.create_widgets()
        
        # Premier scan
        self.refresh_networks()
    
    def setup_styles(self):
        """Configure les styles pour l'interface"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Style des boutons
        style.configure('Scan.TButton', 
                       padding=10,
                       font=('Segoe UI', 10, 'bold'))
        style.configure('Action.TButton', 
                       padding=5,
                       font=('Segoe UI', 9))
        
        # Style des labels
        style.configure('Title.TLabel',
                       font=('Segoe UI', 16, 'bold'),
                       background='#f0f0f0')
        style.configure('Header.TLabel',
                       font=('Segoe UI', 11, 'bold'),
                       background='#f0f0f0')
    
    def create_widgets(self):
        """Crée tous les widgets de l'interface"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configuration du grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Titre
        title_label = ttk.Label(main_frame, 
                               text="🔍 Scanner Wi-Fi Professionnel",
                               style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Barre d'outils
        toolbar = ttk.Frame(main_frame)
        toolbar.grid(row=1, column=0, columnspan=3, pady=(0, 10), sticky=(tk.W, tk.E))
        
        # Boutons de contrôle
        self.scan_btn = ttk.Button(toolbar, 
                                  text="🔁 Scanner maintenant", 
                                  style='Scan.TButton',
                                  command=self.refresh_networks)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.auto_scan_var = tk.BooleanVar()
        self.auto_scan_btn = ttk.Checkbutton(toolbar,
                                            text="Scan automatique (30s)",
                                            variable=self.auto_scan_var,
                                            command=self.toggle_auto_scan)
        self.auto_scan_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar,
                  text="📊 Statistiques",
                  style='Action.TButton',
                  command=self.show_stats).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar,
                  text="💾 Exporter CSV",
                  style='Action.TButton',
                  command=self.export_csv).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar,
                  text="❓ Aide",
                  style='Action.TButton',
                  command=self.show_help).pack(side=tk.LEFT, padx=5)
        
        # Frame pour les deux panneaux
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Panneau gauche - Liste des réseaux
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=1)
        
        # Liste des réseaux
        list_header = ttk.Label(left_frame, 
                               text="📶 Réseaux Wi-Fi détectés",
                               style='Header.TLabel')
        list_header.pack(pady=(0, 5))
        
        # Treeview pour les réseaux
        columns = ('ssid', 'signal', 'auth', 'channel', 'bssid_count')
        self.tree = ttk.Treeview(left_frame, columns=columns, show='headings')
        
        # Configuration des colonnes
        self.tree.heading('ssid', text='SSID', command=lambda: self.sort_tree('ssid', False))
        self.tree.heading('signal', text='Signal', command=lambda: self.sort_tree('signal', False))
        self.tree.heading('auth', text='Authentification', command=lambda: self.sort_tree('auth', False))
        self.tree.heading('channel', text='Canal', command=lambda: self.sort_tree('channel', False))
        self.tree.heading('bssid_count', text='Points d\'accès', command=lambda: self.sort_tree('bssid_count', False))
        
        self.tree.column('ssid', width=200)
        self.tree.column('signal', width=80, anchor=tk.CENTER)
        self.tree.column('auth', width=120)
        self.tree.column('channel', width=60, anchor=tk.CENTER)
        self.tree.column('bssid_count', width=100, anchor=tk.CENTER)
        
        # Scrollbar
        tree_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind de la sélection
        self.tree.bind('<<TreeviewSelect>>', self.on_network_select)
        
        # Panneau droit - Détails
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=1)
        
        # Détails du réseau
        detail_header = ttk.Label(right_frame, 
                                 text="📋 Détails du réseau",
                                 style='Header.TLabel')
        detail_header.pack(pady=(0, 5))
        
        # Frame pour les détails
        detail_container = ttk.Frame(right_frame)
        detail_container.pack(fill=tk.BOTH, expand=True)
        
        # Canvas avec scrollbar pour les détails
        detail_canvas = tk.Canvas(detail_container, bg='white')
        detail_scroll = ttk.Scrollbar(detail_container, orient=tk.VERTICAL, command=detail_canvas.yview)
        self.detail_frame = ttk.Frame(detail_canvas)
        
        detail_canvas.configure(yscrollcommand=detail_scroll.set)
        
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        detail_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_canvas.create_window((0, 0), window=self.detail_frame, anchor=tk.NW)
        
        # Configuration du scroll
        self.detail_frame.bind('<Configure>', 
                              lambda e: detail_canvas.configure(scrollregion=detail_canvas.bbox('all')))
        
        # Barre de statut
        self.status_var = tk.StringVar(value="Prêt")
        status_bar = ttk.Label(main_frame, 
                              textvariable=self.status_var,
                              relief=tk.SUNKEN,
                              anchor=tk.W)
        status_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Démarrer le thread de scan automatique
        self.auto_scan_thread()
    
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
            output = result.stdout
            clean_output = output.encode("ascii", errors="ignore").decode()
            
            networks = []
            current_network = None
            current_bssid = None

            for line in clean_output.splitlines():
                line = line.strip()
                if not line:
                    continue

                # SSID
                m = re.match(r"SSID\s+\d+\s*:\s*(.*)", line, re.IGNORECASE)
                if m:
                    if current_network:
                        if current_bssid:
                            current_network["bssids"].append(current_bssid)
                            current_bssid = None
                        networks.append(current_network)
                    current_network = {
                        "ssid": m.group(1).strip() or "[SSID Caché]",
                        "network_type": None,
                        "authentication": None,
                        "encryption": None,
                        "bssids": []
                    }
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

            # Ajouter le dernier réseau et BSSID
            if current_network:
                if current_bssid:
                    current_network["bssids"].append(current_bssid)
                networks.append(current_network)

            return networks
        except Exception as e:
            return []
    
    def refresh_networks(self):
        """Rafraîchit la liste des réseaux"""
        if self.scanning:
            return
            
        self.scanning = True
        self.scan_btn.config(state='disabled')
        self.status_var.set("Scan en cours...")
        
        # Lancer le scan dans un thread séparé
        thread = threading.Thread(target=self.scan_thread)
        thread.daemon = True
        thread.start()
    
    def scan_thread(self):
        """Thread pour le scan"""
        self.networks = self.get_wifi_networks()
        
        # Mettre à jour l'interface dans le thread principal
        self.root.after(0, self.update_interface)
    
    def update_interface(self):
        """Met à jour l'interface après le scan"""
        # Effacer l'arbre
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Ajouter les réseaux
        for i, net in enumerate(self.networks):
            # Trouver le meilleur signal
            best_signal = 0
            if net["bssids"]:
                best_signal = max(b.get("signal", 0) for b in net["bssids"])
            
            # Préparer les valeurs pour l'affichage
            values = (
                net["ssid"],
                f"{best_signal}%" if best_signal > 0 else "N/A",
                net.get("authentication", "N/A"),
                self.get_common_channel(net),
                len(net["bssids"])
            )
            
            # Insérer dans l'arbre avec tag selon le signal
            tags = ()
            if best_signal >= 80:
                tags = ('excellent',)
            elif best_signal >= 60:
                tags = ('good',)
            elif best_signal >= 40:
                tags = ('fair',)
            elif best_signal > 0:
                tags = ('poor',)
            
            item = self.tree.insert('', tk.END, values=values, tags=tags)
            
            # Configurer les couleurs
            self.tree.tag_configure('excellent', background='#d4edda')
            self.tree.tag_configure('good', background='#fff3cd')
            self.tree.tag_configure('fair', background='#f8d7da')
            self.tree.tag_configure('poor', background='#f5f5f5')
        
        # Mettre à jour le statut
        self.status_var.set(f"Scan terminé - {len(self.networks)} réseaux détectés")
        self.scanning = False
        self.scan_btn.config(state='normal')
        
        # Sélectionner le premier élément si disponible
        if self.tree.get_children():
            self.tree.selection_set(self.tree.get_children()[0])
            self.on_network_select(None)
    
    def get_common_channel(self, network):
        """Retourne le canal le plus commun"""
        channels = [b.get("channel") for b in network["bssids"] if b.get("channel")]
        if channels:
            # Retourner le canal le plus fréquent
            from collections import Counter
            return str(Counter(channels).most_common(1)[0][0])
        return "N/A"
    
    def on_network_select(self, event):
        """Affiche les détails du réseau sélectionné"""
        # Effacer les anciens détails
        for widget in self.detail_frame.winfo_children():
            widget.destroy()
        
        # Récupérer la sélection
        selection = self.tree.selection()
        if not selection:
            return
        
        # Récupérer l'index
        item = selection[0]
        index = self.tree.index(item)
        
        if index < len(self.networks):
            network = self.networks[index]
            
            # Afficher les informations du réseau
            row = 0
            
            # SSID
            ttk.Label(self.detail_frame, 
                     text=f"SSID: {network['ssid']}",
                     font=('Segoe UI', 12, 'bold')).grid(row=row, column=0, sticky=tk.W, pady=5)
            row += 1
            
            # Informations générales
            info_frame = ttk.LabelFrame(self.detail_frame, text="Informations générales", padding=10)
            info_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5, padx=5)
            
            ttk.Label(info_frame, text=f"Type de réseau: {network.get('network_type', 'N/A')}").grid(row=0, column=0, sticky=tk.W, pady=2)
            ttk.Label(info_frame, text=f"Authentification: {network.get('authentication', 'N/A')}").grid(row=1, column=0, sticky=tk.W, pady=2)
            ttk.Label(info_frame, text=f"Chiffrement: {network.get('encryption', 'N/A')}").grid(row=2, column=0, sticky=tk.W, pady=2)
            
            row += 1
            
            # Points d'accès
            if network["bssids"]:
                ap_frame = ttk.LabelFrame(self.detail_frame, text="Points d'accès", padding=10)
                ap_frame.grid(row=row, column=0, sticky=(tk.W, tk.E), pady=5, padx=5)
                
                # Créer un sous-frame avec canvas pour le scroll
                ap_canvas = tk.Canvas(ap_frame, height=200)
                ap_scroll = ttk.Scrollbar(ap_frame, orient=tk.VERTICAL, command=ap_canvas.yview)
                ap_inner_frame = ttk.Frame(ap_canvas)
                
                ap_canvas.configure(yscrollcommand=ap_scroll.set)
                
                ap_scroll.pack(side=tk.RIGHT, fill=tk.Y)
                ap_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                ap_canvas.create_window((0, 0), window=ap_inner_frame, anchor=tk.NW)
                
                # Configurer le scroll
                ap_inner_frame.bind('<Configure>', 
                                   lambda e: ap_canvas.configure(scrollregion=ap_canvas.bbox('all')))
                
                # Afficher chaque BSSID
                for i, bssid in enumerate(network["bssids"]):
                    bssid_frame = ttk.Frame(ap_inner_frame)
                    bssid_frame.grid(row=i, column=0, sticky=(tk.W, tk.E), pady=3)
                    
                    # Signal avec barre de progression
                    signal = bssid.get("signal", 0)
                    progress = ttk.Progressbar(bssid_frame, 
                                              length=100, 
                                              maximum=100, 
                                              value=signal)
                    progress.grid(row=0, column=0, padx=5)
                    
                    # Valeur du signal
                    ttk.Label(bssid_frame, 
                             text=f"{signal}%").grid(row=0, column=1, padx=5)
                    
                    # Informations du BSSID
                    info_text = f"MAC: {bssid.get('bssid', 'N/A')}\n"
                    info_text += f"Canal: {bssid.get('channel', 'N/A')} | "
                    info_text += f"Type: {bssid.get('radio_type', 'N/A')}"
                    
                    ttk.Label(bssid_frame, 
                             text=info_text,
                             justify=tk.LEFT).grid(row=0, column=2, padx=10)
    
    def sort_tree(self, col, reverse):
        """Trie l'arbre par colonne"""
        data = [(self.tree.set(child, col), child) 
                for child in self.tree.get_children('')]
        
        # Conversion pour le tri numérique
        def try_convert(val):
            try:
                # Essayer de convertir en nombre (pour les signaux)
                return float(val.rstrip('%'))
            except:
                return val
        
        data.sort(key=lambda x: try_convert(x[0]), reverse=reverse)
        
        for index, (_, child) in enumerate(data):
            self.tree.move(child, '', index)
        
        # Inverser l'ordre pour le prochain clic
        self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))
    
    def toggle_auto_scan(self):
        """Active/désactive le scan automatique"""
        self.auto_scan = self.auto_scan_var.get()
        if self.auto_scan:
            self.status_var.set("Scan automatique activé")
        else:
            self.status_var.set("Scan automatique désactivé")
    
    def auto_scan_thread(self):
        """Thread pour le scan automatique"""
        if self.auto_scan and not self.scanning:
            self.refresh_networks()
        
        # Reschedule après 30 secondes
        self.root.after(30000, self.auto_scan_thread)
    
    def show_stats(self):
        """Affiche les statistiques"""
        if not self.networks:
            messagebox.showinfo("Statistiques", "Aucun réseau détecté")
            return
        
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Statistiques Wi-Fi")
        stats_window.geometry("500x400")
        
        # Calcul des statistiques
        total_networks = len(self.networks)
        total_bssids = sum(len(n["bssids"]) for n in self.networks)
        
        # Types d'authentification
        auth_types = {}
        for net in self.networks:
            auth = net.get("authentication", "Inconnu")
            auth_types[auth] = auth_types.get(auth, 0) + 1
        
        # Canaux utilisés
        channels = {}
        for net in self.networks:
            for bssid in net["bssids"]:
                channel = bssid.get("channel")
                if channel:
                    channels[channel] = channels.get(channel, 0) + 1
        
        # Affichage des statistiques
        ttk.Label(stats_window, 
                 text="📊 Statistiques Wi-Fi",
                 font=('Segoe UI', 14, 'bold')).pack(pady=10)
        
        stats_text = scrolledtext.ScrolledText(stats_window, width=60, height=20)
        stats_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        stats = f"""RÉSUMÉ
{'='*40}
Total réseaux détectés : {total_networks}
Total points d'accès   : {total_bssids}

TYPES D'AUTHENTIFICATION
{'='*40}
"""
        for auth, count in auth_types.items():
            stats += f"{auth}: {count} réseaux\n"
        
        stats += f"""
CANAULES UTILISÉS
{'='*40}
"""
        for channel in sorted(channels.keys()):
            stats += f"Canal {channel}: {channels[channel]} points d'accès\n"
        
        stats_text.insert(tk.END, stats)
        stats_text.config(state='disabled')
    
    def export_csv(self):
        """Exporte les données en CSV"""
        if not self.networks:
            messagebox.showwarning("Export", "Aucune donnée à exporter")
            return
        
        try:
            from tkinter import filedialog
            import csv
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            
            if filename:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # En-tête
                    writer.writerow(['SSID', 'Type', 'Authentification', 'Chiffrement', 
                                   'BSSID', 'Signal', 'Canal', 'Type Radio'])
                    
                    # Données
                    for net in self.networks:
                        for bssid in net["bssids"]:
                            writer.writerow([
                                net["ssid"],
                                net.get("network_type", ""),
                                net.get("authentication", ""),
                                net.get("encryption", ""),
                                bssid.get("bssid", ""),
                                bssid.get("signal", ""),
                                bssid.get("channel", ""),
                                bssid.get("radio_type", "")
                            ])
                
                messagebox.showinfo("Export", f"Données exportées vers:\n{filename}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export:\n{str(e)}")
    
    def show_help(self):
        """Affiche l'aide"""
        help_text = """SCANNER WI-FI - AIDE

Fonctionnalités :
• Scan des réseaux Wi-Fi environnants
• Détection des points d'accès (BSSID)
• Affichage de la force du signal
• Informations de sécurité
• Scan automatique (30s)
• Export CSV

Coloration des réseaux :
• Vert : Excellent signal (>80%)
• Jaune : Bon signal (60-80%)
• Rose : Signal moyen (40-60%)
• Gris : Signal faible (<40%)

Utilisation :
1. Cliquez sur 'Scanner maintenant' pour un scan
2. Sélectionnez un réseau pour voir les détails
3. Activez le scan automatique pour une surveillance continue
4. Exportez les données pour analyse

© Découvrir les réseaux Wi-Fi - Version 1.0"""
        
        messagebox.showinfo("Aide", help_text)
    
    def run(self):
        """Lance l'application"""
        self.root.mainloop()

def main():
    """Point d'entrée principal"""
    app = WiFiScannerGUI()
    app.run()

if __name__ == "__main__":
    main()