with open("eapol.txt", "r") as f:
    eapol_data = f.readlines()

print("ANonce:", eapol_data[0][34:98])
print("SNonce:", eapol_data[1][34:98])
print("MIC:", eapol_data[1][162:194])
print("EAPOL:", eapol_data[1])