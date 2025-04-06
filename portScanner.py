import socket
import threading
import queue
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox

services_connus = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"
}

def scanner_port(cible, port, fichier_sortie, zone_resultats):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        resultat = s.connect_ex((cible, port))

        if resultat == 0:
            try:
                s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                banniere = s.recv(1024).decode(errors='ignore').strip()
                if not banniere:
                    raise Exception()
            except:
                banniere = services_connus.get(port, "Service inconnu")
            message = f"[TCP] Port {port} ouvert - Service : {banniere}"
        else:
            message = f"[TCP] Port {port} fermé"

        zone_resultats.insert(tk.END, message + "\n")
        zone_resultats.see(tk.END)
        with open(fichier_sortie, "a", encoding="utf-8") as f:
            f.write(message + "\n")

        s.close()
    except:
        pass


def scanner_port_udp(cible, port, fichier_sortie, zone_resultats):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b'', (cible, port))
        try:
            data, _ = s.recvfrom(1024)
            banniere = data.decode(errors='ignore').strip()
            if not banniere:
                banniere = services_connus.get(port, "Service UDP inconnu")
        except socket.timeout:
            banniere = services_connus.get(port, "Pas de réponse (peut être ouvert ou filtré)")

        message = f"[UDP] Port {port} - Réponse : {banniere}"
        zone_resultats.insert(tk.END, message + "\n")
        zone_resultats.see(tk.END)
        with open(fichier_sortie, "a", encoding="utf-8") as f:
            f.write(message + "\n")
        s.close()
    except:
        pass

def travailleur(cible, fichier_sortie, zone_resultats, file_attente):
    while not file_attente.empty():
        port = file_attente.get()
        scanner_port(cible, port, fichier_sortie, zone_resultats)
        file_attente.task_done()

def travailleur_udp(cible, fichier_sortie, zone_resultats, file_attente):
    while not file_attente.empty():
        port = file_attente.get()
        scanner_port_udp(cible, port, fichier_sortie, zone_resultats)
        file_attente.task_done()

def lancer_scan():
    cible = champ_ip.get()
    try:
        port_debut = int(champ_debut.get())
        port_fin = int(champ_fin.get())
    except ValueError:
        messagebox.showerror("Erreur", "Les ports doivent être des nombres entiers.")
        return

    if not cible:
        messagebox.showerror("Erreur", "Veuillez entrer une adresse IP.")
        return

    zone_resultats.delete(1.0, tk.END)
    fichier_sortie = f"resultats_scan_tcp_{cible}.txt"
    with open(fichier_sortie, "w", encoding="utf-8") as f:
        f.write(f"Résultats du scan TCP pour {cible} - {time.ctime()}\n\n")

    file_attente = queue.Queue()
    for port in range(port_debut, port_fin + 1):
        file_attente.put(port)

    for _ in range(100):
        t = threading.Thread(target=travailleur, args=(cible, fichier_sortie, zone_resultats, file_attente))
        t.daemon = True
        t.start()

def lancer_scan_udp():
    cible = champ_ip.get()
    try:
        port_debut = int(champ_debut.get())
        port_fin = int(champ_fin.get())
    except ValueError:
        messagebox.showerror("Erreur", "Les ports doivent être des nombres entiers.")
        return

    if not cible:
        messagebox.showerror("Erreur", "Veuillez entrer une adresse IP.")
        return

    zone_resultats.delete(1.0, tk.END)
    fichier_sortie = f"resultats_scan_udp_{cible}.txt"
    with open(fichier_sortie, "w", encoding="utf-8") as f:
        f.write(f"Résultats du scan UDP pour {cible} - {time.ctime()}\n\n")

    file_attente = queue.Queue()
    for port in range(port_debut, port_fin + 1):
        file_attente.put(port)

    for _ in range(100):
        t = threading.Thread(target=travailleur_udp, args=(cible, fichier_sortie, zone_resultats, file_attente))
        t.daemon = True
        t.start()

def ouvrir_interface_principale(type_scan):
    fenetre_choix.withdraw()

    def retour_menu():
        fenetre.destroy()
        fenetre_choix.deiconify()

    global champ_ip, champ_debut, champ_fin, zone_resultats

    fenetre = tk.Tk()
    fenetre.title("Scanner de Ports TCP / UDP")
    fenetre.geometry("600x500")

    if type_scan == "autre":
        tk.Label(fenetre, text="Adresse IP cible :").pack()
        champ_ip = tk.Entry(fenetre, width=50)
        champ_ip.pack()
    else:
        champ_ip = tk.Entry(fenetre)
        champ_ip.insert(0, "127.0.0.1")
        champ_ip.pack_forget()

    tk.Label(fenetre, text="Port de début :").pack()
    champ_debut = tk.Entry(fenetre, width=10)
    champ_debut.pack()

    tk.Label(fenetre, text="Port de fin :").pack()
    champ_fin = tk.Entry(fenetre, width=10)
    champ_fin.pack()

    tk.Button(fenetre, text="Scan TCP", command=lancer_scan, bg="green", fg="white").pack(pady=5)
    tk.Button(fenetre, text="Scan UDP", command=lancer_scan_udp, bg="orange", fg="white").pack(pady=5)

    zone_resultats = scrolledtext.ScrolledText(fenetre, width=70, height=20)
    zone_resultats.pack()

    tk.Button(fenetre, text="Retour au menu", command=retour_menu, bg="gray", fg="white").pack(pady=10)

    fenetre.mainloop()

def valider_choix():
    choix = var_choix.get()
    if choix == "local":
        ouvrir_interface_principale("local")
    else:
        ouvrir_interface_principale("autre")

fenetre_choix = tk.Tk()
fenetre_choix.title("Choix du type de scan")
fenetre_choix.geometry("400x180")

tk.Label(fenetre_choix, text="Voulez-vous scanner :", font=("Arial", 12)).pack(pady=10)

var_choix = tk.StringVar(value="local")
tk.Radiobutton(fenetre_choix, text="Ce PC (localhost)", variable=var_choix, value="local").pack()
tk.Radiobutton(fenetre_choix, text="Un autre PC", variable=var_choix, value="autre").pack()

tk.Button(fenetre_choix, text="Continuer", command=valider_choix, bg="blue", fg="white").pack(pady=10)
fenetre_choix.mainloop()