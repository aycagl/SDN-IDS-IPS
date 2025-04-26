from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import time

ALERT_FILE = "/var/log/snort/snort.alert.fast"  # Senin gerçek alert dosyan neyse onu yaz buraya

def send_block_request(attacker_ip):
    url = "http://127.0.0.1:5001/block"
    payload = {"attacker_ip": attacker_ip}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"[+] POX'a saldırı bildirildi: {attacker_ip}")
        else:
            print(f"[!] POX yanıtı hatalı: {response.status_code}")
    except Exception as e:
        print(f"[!] POX'a istek gönderilemedi: {e}")

class AlertHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == ALERT_FILE:
            with open(ALERT_FILE, "r") as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    print(f"[ALERT] {last_line}")

                    if "ICMP" in last_line:
                        attacker_ip = "10.0.0.1"  # Burayı geliştirebiliriz
                        print("[DEBUG] Alarm geldi, POX'a bildirim gönderiliyor...")
                        send_block_request(attacker_ip)

if __name__ == "__main__":
    event_handler = AlertHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/var/log/snort", recursive=False)
    observer.start()
    print("[*] Snort Alert Dinleyici Başladı (watchdog ile)...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

