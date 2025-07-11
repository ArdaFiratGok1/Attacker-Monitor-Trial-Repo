# attacker.py
import time
import random

AUTH_LOG_PATH = "test_auth.log"
ACCESS_LOG_PATH = "test_access.log"

def simulate_brute_force():
    """test_auth.log dosyasına sahte brute-force deneme logları yazar."""
    ip = f"198.51.{random.randint(100, 255)}.{random.randint(1, 254)}"
    print(f"\n-> Brute-Force saldırısı simüle ediliyor... (Saldırgan IP: {ip})")
    with open(AUTH_LOG_PATH, 'a') as f:
        for i in range(6):
            log_line = f"Jun 28 14:{random.randint(10,59)}:{random.randint(10,59)} server sshd[12345]: Failed password for invalid user admin from {ip} port 54321 ssh2\n"
            f.write(log_line)
            f.flush() # Diske hemen yazılmasını garantile
            print(f"   {i+1}. başarısız deneme logu yazıldı.")
            time.sleep(random.uniform(0.5, 2)) # Denemeler arası rastgele bekleme
    print("-> Simülasyon tamamlandı.")

def simulate_web_attack():
    """test_access.log dosyasına sahte web saldırısı logları yazar."""
    ip = f"203.0.{random.randint(100, 255)}.{random.randint(1, 254)}"
    print(f"\n-> Web saldırısı simüle ediliyor... (Saldırgan IP: {ip})")
    attacks = [
        f'{ip} - - [28/Jun/2025:15:01:00 +0300] "GET /products.php?id=123\' OR \'1\'=\'1\' -- HTTP/1.1"\n',
        f'{ip} - - [28/Jun/2025:15:01:05 +0300] "GET /index.php?page=../../../../etc/passwd HTTP/1.1"\n',
        f'{ip} - - [28/Jun/2025:15:01:10 +0300] "GET /search.php?q=; whoami HTTP/1.1" 200 - "sqlmap/1.5"\n'
    ]
    with open(ACCESS_LOG_PATH, 'a') as f:
        for attack in attacks:
            f.write(attack)
            f.flush()
            print(f"   '{attack.strip()}' logu yazıldı.")
            time.sleep(1)
    print("-> Simülasyon tamamlandı.")


def main_menu():
    """Kullanıcı için ana menüyü gösterir."""
    while True:
        print("\n--- SALDIRGAN SİMÜLATÖRÜ ---")
        print("1. Brute-Force Saldırısı Simüle Et")
        print("2. Web Uygulama Saldırısı Simüle Et")
        print("q. Çıkış")
        choice = input("Seçiminiz: ")
        
        if choice == '1':
            simulate_brute_force()
        elif choice == '2':
            simulate_web_attack()
        elif choice.lower() == 'q':
            print("Simülatör kapatıldı.")
            break
        else:
            print("Geçersiz seçim, lütfen tekrar deneyin.")

if __name__ == "__main__":
    main_menu()
