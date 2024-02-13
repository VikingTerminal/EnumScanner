import socket
import ipaddress
import time
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
import random

def print_ascii_art():
    ascii_art = """
░░░░░░░░░░▄▄▄▄▄▄▄░░░░░░░░░░
░░░░░░▄▄▀▀░░░░░░░▀▀▄▄░░░░░░
░░░░▄▀░░░░░░░░░░░░░░░▀▄░░░░
░░░▄▀░░░▄▄▄▄▄▄▄▄▄▄▄░░░░█░░░
░░█░░▄███████████████▄░░█░░
░█░░▄██▀░▄▄▀███▀▄▄░▀███░░█░
░█░░▀█████████████████▀░░█░
░█░░░░▀▀████████████▀░░░░█░
░░█░░░░░░░░▀▀▀▀▀░░░░░░░▄▀░░
░░░▀▀▄▄▄▄░░░░░░░░░▄▄▄▀▀░░░░
░░▄██▀▄▄▄█▀▀▀▀▀▀▀█▄▄▄▀██▄░░
░▄▀██░░░░░▀▀▀▀▀▀▀░░░░░██▀▄░
█░░██░░░░░░░░░░░░░░░░░██░░█
█░░██░░░░░░░░░░░░░░░░░██░░█
█░░██░░░░░░░░░░░░░░░░░██░░█
█░░██░░░░░░░░░░░░░░░░░██░░█
█░░██░░░░░░░░░░░░░░░░░██░░█
█░░██▄░░░░░░░░░░░░░░░▄██░░█
▀▀▄█░█▄▄▄▄░░░░░░░▄▄▄▄█░█▄▀▀
░░░░░░░░░█▄▄▄▄▄▄▄█░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░
"""

    colors = [32, 31, 34]
    for char in ascii_art:
        print(f"\033[{random.choice(colors)}m{char}\033[0m", end='', flush=True)

# Print the colored ASCII art on program start
print_ascii_art()

def print_color_text(text, color_code):
    print(f"\033[{color_code}m{text}\033[0m", end='', flush=True)
    time.sleep(0.05)

def typewriter_effect(text, color_code):
    for char in text:
        print_color_text(char, color_code)
    print()

def input_color_text(prompt, color_code):
    user_input = input(f"\033[{color_code}m{prompt}\033[0m")
    return user_input

def save_to_txt(ip_info, open_ports, admin_directories):
    with open("scan_results.txt", "w") as file:
        file.write("Hostname: {}\n".format(ip_info["hostname"]))
        file.write("IP Addresses:\n")
        for ip in ip_info["ip_addresses"]:
            file.write("  {}\n".format(ip))
        file.write("\nPort Scan Results:\n")
        for port in open_ports:
            file.write("  Port {}: Open\n".format(port))
        file.write("\nAdmin Directories Found:\n")
        for directory in admin_directories:
            file.write("  {}\n".format(directory))

def get_ip_info(hostname):
    try:
        ip_info = {"hostname": hostname, "ip_addresses": []}
        ip_addresses = socket.gethostbyname_ex(hostname)[2]

        for ip_address in ip_addresses:
            addr_info = socket.getaddrinfo(ip_address, None)
            family = addr_info[0][0]
            ip = ipaddress.ip_address(ip_address)
            network = ipaddress.ip_network(ip, strict=False)

            typewriter_effect(f"Indirizzo IP: {ip}", 33)  # Yellow
            typewriter_effect(f"Famiglia di indirizzi: {family}", 32)  # Green
            typewriter_effect(f"Rete: {network}", 36)  # Cyan
            print("-" * 30)

            ip_info["ip_addresses"].append(str(ip))

        return ip_info

    except (socket.gaierror, ValueError):
        typewriter_effect(f"Impossibile ottenere informazioni per l'hostname {hostname}", 31)  # Red
        return None  # Aggiunto per indicare che il dominio non esiste

def scan_port(ip_address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            print_color_text(f"Porta {port} aperta\n", 32)  # Green
        sock.close()
    except (socket.error, socket.timeout):
        pass

def scan_ports(ip_address):
    try:
        print_color_text("Scansione porte aperte:\n", 32)  # Green

        open_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, ip_address, port) for port in range(1, 1025)]

        for future in futures:
            future.result()
            open_ports.append(future)

        return open_ports

    except Exception as e:
        print_color_text(f"Errore nella scansione delle porte: {e}", 31)  # Red
        return []

def search_admin_directories(ip_address):
    try:
        print_color_text("\nRicerca directory di amministrazione in corso...", 36)  # Green

        common_directories = ["admin", "login", "dashboard"]
        found_directories = []

        for directory in common_directories:
            url = f"http://{ip_address}/{directory}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    found_directories.append(url)
            except requests.RequestException as e:
                print_color_text(f"Errore durante la richiesta a {url}: {e}", 31)  # Red

        if found_directories:
            print_color_text("\nDirectory trovate\n", 31)  # Green
            for dir_url in found_directories:
                print_color_text(f"{dir_url}\n", 32)  # Green
        else:
            print_color_text("\nNessuna directory di amministrazione trovata", 33)  # Yellow

        return found_directories

    except Exception as e:
        print_color_text(f"Errore nella ricerca delle directory di amministrazione: {e}", 31)  # Red
        return []

print_color_text("\nInserisci l'hostname da analizzare (digita 'exit' per uscire): ", 36)  
while True:
    try:
        hostname_input = input()
        if hostname_input.lower() == 'exit':
            typewriter_effect("\nGrazie per aver provato questo tool! Visita t.me/VikingTerminal per provare altre utility.", 36)  # Cyan
            time.sleep(1)
            break

        ip_info = get_ip_info(hostname_input)

        # Verifica se il dominio esiste prima di procedere
        if ip_info is not None:
            # Salva i risultati delle scansioni in variabili
            open_ports = scan_ports(hostname_input)
            found_directories = search_admin_directories(hostname_input)

            # Mostra i risultati
            save_result = input_color_text("\n\nVuoi salvare i risultati in un documento txt? (yes/no): ", 33)  # Yellow
            if save_result.lower() == 'yes':
                save_to_txt(ip_info, open_ports, found_directories)
                print_color_text("Risultati salvati nel file scan_results.txt", 36)  # Green
            elif save_result.lower() == 'no':
                print_color_text("Risultati non salvati.\n", 31) 
            else:
                print_color_text("Input non valido. dovevi scrivere 'yes' o 'no'.file non memorizzato\n", 31)  # Red

            print_color_text("\nInserisci l'hostname da analizzare (digita 'exit' per uscire): ", 32)  
        else:
            print_color_text("Il dominio specificato non esiste. Riprova con un dominio esistente : ", 31)  # Red

    except KeyboardInterrupt:
        print("\nProgramma interrotto dall'utente.")
        break
