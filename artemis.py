from scapy.all import IP, ICMP, sr1
import requests
import socket
import time

def geolocate_ip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,city,country").json()
        if res["status"] == "success":
            return f"{res.get('city', 'Desconhecida')}, {res.get('country', 'Desconhecido')}"
        else:
            return "Não encontrado"
    except Exception:
        return "Erro na geolocalização"

def custom_traceroute(dest, max_hops=30, timeout=2):
    print(f"[🌍] Artemis iniciando traceroute para {dest}...\n")

    try:
        dest_ip = socket.gethostbyname(dest)
        print(f"[📡] Endereço IP resolvido: {dest_ip}\n")
    except socket.gaierror:
        print("❌ Host inválido.")
        return

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=dest_ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=timeout)

        if reply is None:
            print(f"{ttl:2}  * * *  📍 Sem resposta")
        else:
            hop_ip = reply.src
            location = geolocate_ip(hop_ip)
            print(f"{ttl:2}  {hop_ip:15}  📍 {location}")

            if reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 0:
                print("\n🏁 Destino alcançado.")
                break

        time.sleep(1)

if __name__ == "__main__":
    destino = input("🌐 Host/IP de destino: ")
    custom_traceroute(destino)
