import tkinter as tk
import nmap

# Création de la fenêtre
window = tk.Tk()
window.title("Scanner de réseau")

# Fonction appelée lorsque le bouton "Scan" est cliqué
def scan_network():
    # Récupération de l'adresse IP ou du nom de domaine saisi par l'utilisateur
    target = entry.get()
    # Création d'un objet nmap.PortScanner()
    nm = nmap.PortScanner()
    # Lancement de l'analyse avec les options "-sS" (analyse TCP syn) et "-O" (identification de l'OS)
    nm.scan(target, arguments="-sS -O")
    # Affichage des résultats de l'analyse
    for host in nm.all_hosts():
        print(f"Hôte {host} ({nm[host].hostname()})")
        print(f"État : {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocole : {proto}")
            lport = nm[host][proto].keys()
            lport = sorted(lport)
            for port in lport:
                print(f"Port {port} : {nm[host][proto][port]['state']}")

# Création du champ de texte pour saisir l'adresse IP ou le nom de domaine
entry = tk.Entry(window)
entry.pack()

# Création du bouton "Scan"
button = tk.Button(window, text="Scan", command=scan_network)
button.pack()

# Affichage de la fenêtre
window.mainloop()
