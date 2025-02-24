#!/usr/bin/env python3
# KAGEscan1 - Master Edition
# Auteur : GUY KOUAKOU (Pseudo : KAGEHACKER)
# Date : Février 2025
# Description : L'outil de scan réseau ultime - Puissant, furtif, intelligent et incontournable.
# Licence : MIT - Usage légal et éthique uniquement.

import ipaddress
import subprocess
import platform
import socket
import concurrent.futures
import json
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread
from tqdm import tqdm
import os
import csv
import argparse
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import random
import time
import scapy.all as scapy  # pip install scapy
import logging

# Configuration des logs
logging.basicConfig(filename="kagescan1.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Dictionnaire des services et vulnérabilités
SERVICES = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP", 8080: "HTTP Proxy", 53: "DNS"}
VULN_DB = {
    "Apache 2.4.": "Possible CVE-2019-0211 (privilège escalation)",
    "OpenSSH 7.": "Possible CVE-2021-41617 (DoS)",
    "nginx 1.": "Possible CVE-2021-23017 (buffer overflow)"
}

def parse_ports(ports_input):
    """Parse les ports avec plages ou 'random' pour une sélection aléatoire."""
    if ports_input.lower() == "random":
        return random.sample(range(1, 65536), 100)
    ports = []
    for part in ports_input.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return [p for p in ports if 1 <= p <= 65535]

def arp_scan(ip_range):
    """Scan ARP ultra-rapide pour détecter les hôtes."""
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=0.5, verbose=False)[0]
        return {client[1].psrc: {"ports": [], "os": "Inconnu"} for client in answered_list}
    except Exception as e:
        logging.error(f"Erreur ARP: {e}")
        return {}

def tcp_stealth_scan(ip, port, timeout=0.3, retries=2):
    """Scan TCP furtif avec randomisation et retries."""
    for _ in range(retries):
        time.sleep(random.uniform(0.01, 0.1))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                result = s.connect_ex((ip, port))
                if result == 0:
                    banner = ""
                    if port in [80, 443, 8080]:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    elif port == 22:
                        s.send(b"SSH-2.0-KAGEscan1\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    vuln = next((v for k, v in VULN_DB.items() if k in banner), "Aucune vulnérabilité connue")
                    return True, banner or "Aucune bannière", vuln
                return False, "Fermé", "N/A"
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Erreur TCP sur {ip}:{port}: {e}")
                return False, "Erreur", "N/A"
    return False, "Timeout persistant", "N/A"

def udp_scan(ip, port, timeout=0.3):
    """Scan UDP avec réponse simulée."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(b"KAGEscan1", (ip, port))
            data, _ = s.recvfrom(1024)
            return True, f"UDP Response: {data.decode(errors='ignore')}", "N/A"
        except socket.timeout:
            return True, "UDP ouvert (pas de réponse)", "N/A"
        except Exception as e:
            logging.error(f"Erreur UDP sur {ip}:{port}: {e}")
            return False, "Erreur", "N/A"

def scan_ports_for_ip(ip, ports, timeout=0.3, protocol="tcp"):
    """Scan multi-protocole ultra-puissant."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(100, len(ports))) as executor:
        if protocol == "tcp":
            futures = {executor.submit(tcp_stealth_scan, ip, port, timeout): port for port in ports}
        else:
            futures = {executor.submit(udp_scan, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            is_open, banner, vuln = future.result()
            if is_open:
                open_ports.append({"port": futures[future], "banner": banner, "vuln": vuln})
    return open_ports

def guess_os(ip):
    """Détection OS via TTL."""
    cmd = ["ping", "-n" if platform.system().lower() == "windows" else "-c", "1", str(ip)]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ttl = None
        for line in result.stdout.splitlines():
            if "TTL=" in line.upper():
                ttl = int(line.split("TTL=")[1].split()[0])
        if ttl:
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "Routeur ou autre"
        return "Inconnu"
    except Exception:
        return "Inconnu"

class KAGEscan1App:
    def __init__(self, root):
        self.root = root
        self.root.title("KAGEscan1 - Master Edition")
        self.root.geometry("1200x900")
        self.root.resizable(False, False)
        self.root.configure(bg="black")
        self.scan_history = []
        self.scan_thread = None

        # Variables
        self.ip_range = tk.StringVar(value="192.168.1.0/24")
        self.ports = tk.StringVar(value="20-100,443,3389,random")
        self.timeout = tk.DoubleVar(value=0.3)
        self.protocol = tk.StringVar(value="both")
        self.max_workers = tk.IntVar(value=200)
        self.export_format = tk.StringVar(value="json")
        self.running = False

        # Interface
        self.create_widgets()

    def create_widgets(self):
        # Frame principal
        self.main_frame = ttk.Frame(self.root, padding="20", style="Dark.TFrame")
        self.main_frame.pack(fill="both", expand=True)

        # Titre
        title_label = ttk.Label(self.main_frame, text="KAGEscan1 - Master Edition", style="Title.TLabel")
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 10))
        author_label = ttk.Label(self.main_frame, text="Par GUY KOUAKOU (KAGEHACKER)", style="Signature.TLabel")
        author_label.grid(row=1, column=0, columnspan=4)

        # Section des entrées
        input_frame = ttk.LabelFrame(self.main_frame, text="Paramètres", padding="10", style="Dark.TLabelframe")
        input_frame.grid(row=2, column=0, columnspan=4, pady=10, sticky="ew")

        ttk.Label(input_frame, text="Plage IP (CIDR):", style="Dark.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.ip_range, width=25, style="Dark.TEntry").grid(row=0, column=1, pady=5)

        ttk.Label(input_frame, text="Ports (ex: 20-100,random):", style="Dark.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.ports, width=25, style="Dark.TEntry").grid(row=1, column=1, pady=5)

        ttk.Label(input_frame, text="Timeout (s):", style="Dark.TLabel").grid(row=2, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.timeout, width=10, style="Dark.TEntry").grid(row=2, column=1, sticky="w", pady=5)

        ttk.Label(input_frame, text="Protocole:", style="Dark.TLabel").grid(row=3, column=0, sticky="w")
        ttk.Combobox(input_frame, textvariable=self.protocol, values=["tcp", "udp", "both"], state="readonly", style="Dark.TCombobox").grid(row=3, column=1, sticky="w", pady=5)

        ttk.Label(input_frame, text="Threads max:", style="Dark.TLabel").grid(row=4, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.max_workers, width=10, style="Dark.TEntry").grid(row=4, column=1, sticky="w", pady=5)

        ttk.Label(input_frame, text="Export:", style="Dark.TLabel").grid(row=5, column=0, sticky="w")
        ttk.Combobox(input_frame, textvariable=self.export_format, values=["json", "csv", "txt", "html"], state="readonly", style="Dark.TCombobox").grid(row=5, column=1, sticky="w", pady=5)

        # Boutons
        self.start_btn = ttk.Button(input_frame, text="Lancer", command=self.start_scan, style="Dark.TButton")
        self.start_btn.grid(row=6, column=0, pady=10)

        self.stop_btn = ttk.Button(input_frame, text="Arrêter", command=self.stop_scan, state="disabled", style="Dark.TButton")
        self.stop_btn.grid(row=6, column=1, pady=10)

        ttk.Button(input_frame, text="Aide", command=self.show_help, style="Dark.TButton").grid(row=6, column=2, pady=10)

        # Statut et progression
        status_frame = ttk.LabelFrame(self.main_frame, text="Statut", padding="10", style="Dark.TLabelframe")
        status_frame.grid(row=3, column=0, columnspan=4, pady=10, sticky="ew")

        self.progress = ttk.Progressbar(status_frame, length=600, mode="determinate", style="Custom.Horizontal.TProgressbar")
        self.progress.grid(row=0, column=0, padx=5, pady=5)

        self.status_label = ttk.Label(status_frame, text="Hôtes: 0 | Ports: 0", style="Status.TLabel")
        self.status_label.grid(row=0, column=1, padx=5, pady=5)

        # Résultats (Tableau)
        result_frame = ttk.LabelFrame(self.main_frame, text="Résultats", padding="10", style="Dark.TLabelframe")
        result_frame.grid(row=4, column=0, columnspan=4, pady=10, sticky="nsew")

        self.tree = ttk.Treeview(result_frame, columns=("IP", "OS", "Ports", "Bannières", "Vulnérabilités"), show="headings", height=12)
        self.tree.heading("IP", text="IP")
        self.tree.heading("OS", text="OS")
        self.tree.heading("Ports", text="Ports")
        self.tree.heading("Bannières", text="Bannières")
        self.tree.heading("Vulnérabilités", text="Vulnérabilités")
        self.tree.column("IP", width=150)
        self.tree.column("OS", width=100)
        self.tree.column("Ports", width=200)
        self.tree.column("Bannières", width=200)
        self.tree.column("Vulnérabilités", width=250)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Historique
        history_frame = ttk.LabelFrame(self.main_frame, text="Historique", padding="10", style="Dark.TLabelframe")
        history_frame.grid(row=5, column=0, columnspan=4, pady=10, sticky="ew")

        ttk.Label(history_frame, text="Rapports:", style="Dark.TLabel").grid(row=0, column=0, sticky="w")
        self.history_combo = ttk.Combobox(history_frame, state="readonly", style="Dark.TCombobox")
        self.history_combo.grid(row=0, column=1, pady=5)
        self.history_combo.bind("<<ComboboxSelected>>", self.load_history)

        # Graphique
        graph_frame = ttk.LabelFrame(self.main_frame, text="Graphique", padding="10", style="Dark.TLabelframe")
        graph_frame.grid(row=6, column=0, columnspan=4, pady=10, sticky="nsew")
        self.fig, self.ax = plt.subplots(figsize=(10, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Avertissement
        ttk.Label(self.main_frame, text="⚠ Usage légal uniquement sur réseaux autorisés", style="Warning.TLabel").grid(row=7, column=0, columnspan=4, pady=10)

        # Styles
        style = ttk.Style()
        style.configure("Dark.TFrame", background="black")
        style.configure("Dark.TLabelframe", background="black", foreground="cyan")
        style.configure("Dark.TLabelframe.Label", background="black", foreground="cyan")
        style.configure("Title.TLabel", font=("Courier", 20, "bold"), foreground="cyan", background="black")
        style.configure("Signature.TLabel", font=("Courier", 12, "bold"), foreground="blue", background="black")
        style.configure("Status.TLabel", font=("Courier", 12), foreground="yellow", background="black")
        style.configure("Warning.TLabel", font=("Courier", 12), foreground="red", background="black")
        style.configure("Dark.TLabel", foreground="white", background="black")
        style.configure("Dark.TButton", background="gray20", foreground="white", font=("Courier", 10))
        style.configure("Dark.TEntry", fieldbackground="gray20", foreground="white", font=("Courier", 10))
        style.configure("Dark.TCombobox", fieldbackground="gray20", foreground="white", font=("Courier", 10))
        style.configure("Custom.Horizontal.TProgressbar", troughcolor="black", background="cyan")  # Style corrigé
        style.configure("Treeview", background="black", foreground="white", fieldbackground="black", font=("Courier", 10))
        style.configure("Treeview.Heading", background="gray20", foreground="cyan", font=("Courier", 10, "bold"))

    def log(self, ip, os_guess="", ports="", banners="", vulns=""):
        self.tree.insert("", "end", values=(ip, os_guess, ports, banners, vulns))
        self.root.update_idletasks()
        logging.info(f"IP: {ip}, OS: {os_guess}, Ports: {ports}, Bannières: {banners}, Vulnérabilités: {vulns}")

    def show_help(self):
        help_text = (
            "KAGEscan1 - Master Edition\n"
            "Auteur: GUY KOUAKOU (KAGEHACKER)\n\n"
            "Utilisation:\n"
            "- Plage IP: Ex: 192.168.1.0/24\n"
            "- Ports: Ex: 20-100,443,random (100 ports aléatoires)\n"
            "- Timeout: Temps d'attente par port (ex: 0.3)\n"
            "- Protocole: TCP, UDP ou les deux\n"
            "- Threads: Nombre max de threads (ex: 200)\n"
            "- Export: JSON, CSV, TXT ou HTML\n\n"
            "Note: Exécutez avec sudo pour le scan ARP.\n"
            "Usage légal uniquement sur des réseaux autorisés."
        )
        messagebox.showinfo("Aide - KAGEscan1", help_text)

    def validate_inputs(self):
        try:
            ipaddress.ip_network(self.ip_range.get(), strict=False)
            ports = parse_ports(self.ports.get())
            if not ports:
                raise ValueError("Aucun port valide spécifié.")
            if self.timeout.get() <= 0:
                raise ValueError("Timeout doit être positif.")
            if self.max_workers.get() <= 0:
                raise ValueError("Nombre de threads doit être positif.")
        except ValueError as e:
            messagebox.showerror("Erreur d'entrée", str(e))
            return False
        return True

    def start_scan(self):
        if self.running or not self.validate_inputs():
            return
        self.running = True
        self.start_btn["state"] = "disabled"
        self.stop_btn["state"] = "normal"
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0
        self.ax.clear()
        self.canvas.draw()
        self.log("AVERTISSEMENT", "Cet outil est destiné à un usage légal et éthique uniquement.")
        self.scan_thread = Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()
        self.pulse_progress()

    def stop_scan(self):
        self.running = False
        self.start_btn["state"] = "normal"
        self.stop_btn["state"] = "disabled"

    def pulse_progress(self):
        if self.running:
            self.progress.step(1)
            self.root.after(100, self.pulse_progress)

    def update_graph(self, active_hosts):
        self.ax.clear()
        ips = list(active_hosts.keys())
        port_counts = [len(data["ports"]) for data in active_hosts.values()]
        self.ax.bar(ips, port_counts, color="cyan", edgecolor="white")
        self.ax.set_xlabel("Adresses IP", fontsize=10, color="white")
        self.ax.set_ylabel("Ports ouverts", fontsize=10, color="white")
        self.ax.set_title("Scan en temps réel - KAGEscan1", fontsize=12, color="cyan")
        self.ax.set_xticks(range(len(ips)))
        self.ax.set_xticklabels(ips, rotation=45, ha="right", color="white")
        self.ax.set_facecolor("black")
        self.fig.set_facecolor("black")
        self.ax.spines["top"].set_color("white")
        self.ax.spines["right"].set_color("white")
        self.ax.spines["left"].set_color("white")
        self.ax.spines["bottom"].set_color("white")
        self.ax.tick_params(colors="white")
        self.canvas.draw()

    def save_report(self, report, export_format):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"kagescan1_master_rapport_{timestamp}.{export_format}"
        if export_format == "json":
            with open(filename, "w") as f:
                json.dump(report, f, indent=4)
        elif export_format == "csv":
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "OS", "Ports", "Services", "Bannières", "Vulnérabilités"])
                for ip, data in report["active_hosts"].items():
                    ports_str = ", ".join(f"{p['port']} ({p['service']}) - {p['banner']} [{p['vuln']}]" for p in data["ports"]) if data["ports"] else ""
                    writer.writerow([ip, data["os"], ports_str, "", "", ""])
        elif export_format == "txt":
            with open(filename, "w") as f:
                f.write(f"Réseau: {report['network']}\nTimestamp: {report['timestamp']}\n\n")
                for ip, data in report["active_hosts"].items():
                    if data["ports"]:
                        ports_str = ", ".join(f"{p['port']} ({p['service']}) - {p['banner']} [{p['vuln']}]" for p in data["ports"])
                        f.write(f"{ip} (OS: {data['os']}): {ports_str}\n")
        elif export_format == "html":
            with open(filename, "w") as f:
                f.write("<html><body style='background-color:black;color:white;'><h1>KAGEscan1 Report</h1>")
                f.write(f"<p>Réseau: {report['network']} | Timestamp: {report['timestamp']}</p>")
                f.write("<table border='1' style='border-collapse:collapse;'><tr><th>IP</th><th>OS</th><th>Ports</th></tr>")
                for ip, data in report["active_hosts"].items():
                    ports_str = ", ".join(f"{p['port']} ({p['service']}) - {p['banner']} [{p['vuln']}]" for p in data["ports"]) if data["ports"] else "Aucun"
                    f.write(f"<tr><td>{ip}</td><td>{data['os']}</td><td>{ports_str}</td></tr>")
                f.write("</table></body></html>")
        return filename

    def run_scan(self):
        try:
            network = ipaddress.ip_network(self.ip_range.get(), strict=False)
            ports = parse_ports(self.ports.get())
            timeout = self.timeout.get()
            protocol = self.protocol.get()
            max_workers = min(self.max_workers.get(), 2000)
            export_format = self.export_format.get()
            active_hosts = arp_scan(str(network))

            self.log(f"[KAGEscan1 Master] Début du scan sur {network}")
            total_hosts = network.num_addresses - 2
            self.progress["maximum"] = total_hosts

            self.log("=== Détection des hôtes actifs (ARP + TCP Stealth) ===")
            if not active_hosts:
                self.log("ARP inefficace", "Passage au scan TCP furtif...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(tcp_stealth_scan, str(ip), 80, timeout): ip for ip in network.hosts()}
                    for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), disable=True):
                        if not self.running:
                            self.log("Scan arrêté.")
                            return
                        ip = futures[future]
                        is_open, _, _ = future.result()
                        if is_open:
                            os_guess = guess_os(str(ip))
                            active_hosts[str(ip)] = {"ports": [], "os": os_guess}
                            self.log(ip, os_guess)
                        self.progress["value"] += 1
            else:
                for ip in active_hosts:
                    active_hosts[ip]["os"] = guess_os(ip)
                    self.log(ip, active_hosts[ip]["os"])
                self.progress["value"] = len(active_hosts)

            if not active_hosts:
                self.log("Aucun hôte détecté malgré les méthodes avancées.")
                return

            self.log("=== Scan des ports (Mode Master) ===")
            self.progress["value"] = 0
            self.progress["maximum"] = len(active_hosts)
            for ip in active_hosts:
                if not self.running:
                    self.log("Scan arrêté.")
                    return
                if protocol == "both":
                    tcp_ports = scan_ports_for_ip(ip, ports, timeout, "tcp")
                    udp_ports = scan_ports_for_ip(ip, ports, timeout, "udp")
                    active_hosts[ip]["ports"] = tcp_ports + udp_ports
                else:
                    active_hosts[ip]["ports"] = scan_ports_for_ip(ip, ports, timeout, protocol)
                if active_hosts[ip]["ports"]:
                    ports_str = ", ".join(str(p["port"]) for p in active_hosts[ip]["ports"])
                    banners_str = ", ".join(p["banner"] for p in active_hosts[ip]["ports"])
                    vulns_str = ", ".join(p["vuln"] for p in active_hosts[ip]["ports"])
                    self.log(ip, active_hosts[ip]["os"], ports_str, banners_str, vulns_str)
                self.progress["value"] += 1
                self.status_label.config(text=f"Hôtes: {len(active_hosts)} | Ports: {sum(len(data['ports']) for data in active_hosts.values())}")
                self.update_graph(active_hosts)

            report = {"network": str(network), "active_hosts": active_hosts, "timestamp": datetime.now().isoformat()}
            filename = self.save_report(report, export_format)
            self.scan_history.append(filename)
            self.history_combo["values"] = self.scan_history
            self.log("", "", f"Rapport sauvegardé dans {filename}")

        except Exception as e:
            self.log("Erreur MASTER", str(e))
            messagebox.showerror("Erreur", str(e))

    def load_history(self, event):
        selected_file = self.history_combo.get()
        with open(selected_file, "r") as f:
            if selected_file.endswith(".html"):
                import webbrowser
                webbrowser.open(selected_file)
                self.log("", "", f"Ouverture de {selected_file} dans le navigateur.")
            else:
                report = json.load(f)
                self.tree.delete(*self.tree.get_children())
                self.log("", "", f"Chargement de {selected_file}")
                for ip, data in report["active_hosts"].items():
                    if data["ports"]:
                        ports_str = ", ".join(str(p["port"]) for p in data["ports"])
                        banners_str = ", ".join(p["banner"] for p in data["ports"])
                        vulns_str = ", ".join(p["vuln"] for p in data["ports"])
                        self.log(ip, data["os"], ports_str, banners_str, vulns_str)

def run_silent_mode(args):
    network = ipaddress.ip_network(args.ip_range, strict=False)
    ports = parse_ports(args.ports)
    timeout = args.timeout
    protocol = args.protocol
    max_workers = min(args.workers, 2000)
    export_format = args.export
    active_hosts = arp_scan(str(network))

    print(f"[KAGEscan1 Master] Début du scan sur {network}...")
    logging.info(f"Début du scan sur {network}")
    if not active_hosts:
        print("ARP inefficace, passage au scan TCP furtif...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(tcp_stealth_scan, str(ip), 80, timeout): ip for ip in network.hosts()}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                is_open, _, _ = future.result()
                if is_open:
                    os_guess = guess_os(str(ip))
                    active_hosts[str(ip)] = {"ports": [], "os": os_guess}
                    print(f"{ip} est actif (OS probable: {os_guess})")

    if not active_hosts:
        print("Aucun hôte détecté.")
        return

    print("\nScan des ports...")
    for ip in active_hosts:
        if protocol == "both":
            tcp_ports = scan_ports_for_ip(ip, ports, timeout, "tcp")
            udp_ports = scan_ports_for_ip(ip, ports, timeout, "udp")
            active_hosts[ip]["ports"] = tcp_ports + udp_ports
        else:
            active_hosts[ip]["ports"] = scan_ports_for_ip(ip, ports, timeout, protocol)
        if active_hosts[ip]["ports"]:
            ports_str = ", ".join(f"{p['port']} ({SERVICES.get(p['port'], 'Inconnu')}) - {p['banner']} [{p['vuln']}]" for p in active_hosts[ip]["ports"])
            print(f"{ip}: {ports_str}")

    report = {"network": str(network), "active_hosts": active_hosts, "timestamp": datetime.now().isoformat()}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"kagescan1_master_rapport_{timestamp}.{export_format}"
    if export_format == "json":
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
    elif export_format == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "OS", "Ports", "Services", "Bannières", "Vulnérabilités"])
            for ip, data in active_hosts.items():
                ports_str = ", ".join(f"{p['port']} ({SERVICES.get(p['port'], 'Inconnu')}) - {p['banner']} [{p['vuln']}]" for p in data["ports"]) if data["ports"] else ""
                writer.writerow([ip, data["os"], ports_str, "", "", ""])
    elif export_format == "txt":
        with open(filename, "w") as f:
            f.write(f"Réseau: {network}\nTimestamp: {datetime.now().isoformat()}\n\n")
            for ip, data in active_hosts.items():
                if data["ports"]:
                    ports_str = ", ".join(f"{p['port']} ({SERVICES.get(p['port'], 'Inconnu')}) - {p['banner']} [{p['vuln']}]" for p in data["ports"])
                    f.write(f"{ip} (OS: {data['os']}): {ports_str}\n")
    elif export_format == "html":
        with open(filename, "w") as f:
            f.write("<html><body style='background-color:black;color:white;'><h1>KAGEscan1 Report</h1>")
            f.write(f"<p>Réseau: {network} | Timestamp: {datetime.now().isoformat()}</p>")
            f.write("<table border='1' style='border-collapse:collapse;'><tr><th>IP</th><th>OS</th><th>Ports</th></tr>")
            for ip, data in active_hosts.items():
                ports_str = ", ".join(f"{p['port']} ({SERVICES.get(p['port'], 'Inconnu')}) - {p['banner']} [{p['vuln']}]" for p in data["ports"]) if data["ports"] else "Aucun"
                f.write(f"<tr><td>{ip}</td><td>{data['os']}</td><td>{ports_str}</td></tr>")
            f.write("</table></body></html>")
    print(f"Rapport sauvegardé dans {filename}")

if __name__ == "__main__":
    try:
        import scapy
    except ImportError:
        print("Erreur: Installez scapy avec 'pip install scapy'.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="KAGEscan1 - Master Edition\nScanner réseau ultime par GUY KOUAKOU (KAGEHACKER)",
        epilog="Exemple: sudo python3 kagescan1.py --ip-range 192.168.1.0/24 --ports 20-100,random --protocol both --export html"
    )
    parser.add_argument("--ip-range", help="Plage IP en CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--ports", default="20-100,443,random", help="Ports ou plages (ex: 20-100,random)")
    parser.add_argument("--timeout", type=float, default=0.3, help="Timeout en secondes")
    parser.add_argument("--protocol", choices=["tcp", "udp", "both"], default="both", help="Protocole")
    parser.add_argument("--workers", type=int, default=200, help="Nombre maximum de threads")
    parser.add_argument("--export", choices=["json", "csv", "txt", "html"], default="json", help="Format d'export")
    args = parser.parse_args()

    if args.ip_range:
        run_silent_mode(args)
    else:
        root = tk.Tk()
        # root.iconbitmap("kage_icon.ico")  # Ajoute une icône si disponible
        app = KAGEscan1App(root)
        root.mainloop()
