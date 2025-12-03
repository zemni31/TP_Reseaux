import subprocess
import re
import time
import matplotlib.pyplot as plt
from datetime import datetime

# Fonction pour récupérer Signal % et RSSI
def get_wifi_info():
    result = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=True,
        encoding="cp1252"
    )
    output = result.stdout

    # Supprimer tous les caractères non-ASCII
    clean_output = output.encode("ascii", errors="ignore").decode()

    # Extraire Signal %
    match_signal = re.search(r"Signal\s*:\s*(\d+)\s*%", clean_output, re.IGNORECASE)
    signal = int(match_signal.group(1)) if match_signal else None

    # Extraire RSSI dBm
    match_rssi = re.search(r"Rssi\s*:\s*(-?\d+)", clean_output, re.IGNORECASE)
    rssi = int(match_rssi.group(1)) if match_rssi else None

    return signal, rssi

# --- Initialisation graphique ---
plt.ion()  # mode interactif pour mise à jour en temps réel
fig, ax = plt.subplots()
x_data = []  # Temps ou numéro de mesure
y_data = []  # Signal %
line, = ax.plot(x_data, y_data, 'b-o', label='Signal (%)')

ax.set_xlabel('Mesures')
ax.set_ylabel('Signal (%)')
ax.set_title('Évolution du Signal Wi-Fi')
ax.set_ylim(0, 100)
ax.grid(True)
ax.legend()

# --- Boucle principale ---
i = 0
try:
    while True:
        signal, rssi = get_wifi_info()
        if signal is not None:
            i += 1
            x_data.append(i)
            y_data.append(signal)

            # Mettre à jour le graphique
            line.set_xdata(x_data)
            line.set_ydata(y_data)
            ax.set_xlim(0, max(10, i+1))  # étendre l'axe x dynamiquement
            plt.pause(0.5)  # pause pour mettre à jour le graphique
        else:
            print("Signal non détecté")
        time.sleep(2)  # intervalle entre mesures
except KeyboardInterrupt:
    print("\nArrêt du programme")
    plt.ioff()
    plt.show()
