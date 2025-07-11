# monitor.py
import time
import re
from collections import defaultdict
from datetime import datetime, timedelta
import threading

# --- RENK KODLARI ---
class Renk:
    KIRMIZI = '\033[91m'
    SARI = '\033[93m'
    MAVI = '\033[94m'
    RESET = '\033[0m'

# --- AYARLAR ---
CONFIG = {
    "auth_log_path": "test_auth.log",
    "access_log_path": "test_access.log",
    "brute_force_limit": 5,  # Kaç adet başarısız denemede uyarı verilsin?
    "brute_force_timeframe_seconds": 60, # Bu denemeler kaç saniye içinde gerçekleşmeli?
}

# --- DURUM (STATE) YÖNETİMİ ---
# Her IP için başarısız giriş denemelerinin zaman damgalarını tutacağız.
# defaultdict kullanmak, bir IP ilk kez eklendiğinde hata vermeyi önler.
failed_logins = defaultdict(list)

# --- LOG AYRIŞTIRMA VE TESPİT FONKSİYONLARI ---

def detect_ssh_brute_force(line):
    """SSH log satırını analiz eder ve brute-force saldırısını tespit etmeye çalışır."""
    # "Failed password for admin from 123.45.67.89" gibi bir satırdan IP'yi çeker.
    match = re.search(r'Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if not match:
        return

    ip_address = match.group(1)
    current_time = datetime.now()
    
    # Bu IP için olan deneme listesine şimdiki zamanı ekle.
    failed_logins[ip_address].append(current_time)
    
    # Belirlenen zaman aralığından (örn: son 60 sn) daha eski kayıtları temizle.
    time_limit = current_time - timedelta(seconds=CONFIG["brute_force_timeframe_seconds"])
    recent_attempts = [t for t in failed_logins[ip_address] if t > time_limit]
    failed_logins[ip_address] = recent_attempts
    
    # Eğer son zaman dilimindeki deneme sayısı belirlenen limiti aştıysa, UYARI VER!
    if len(recent_attempts) >= CONFIG["brute_force_limit"]:
        print(f"{Renk.KIRMIZI}[!] KRİTİK UYARI: BRUTE FORCE SALDIRISI TESPİT EDİLDİ!{Renk.RESET}")
        print(f"  > Saldırgan IP: {ip_address}")
        print(f"  > Zaman: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  > {CONFIG['brute_force_timeframe_seconds']} saniye içinde {len(recent_attempts)} başarısız deneme yapıldı.\n")
        # Uyarı verdikten sonra bu IP için listeyi temizle ki sürekli aynı uyarıyı vermesin.
        failed_logins[ip_address] = []


def detect_web_attack(line):
    """Web sunucusu access loglarını analiz eder ve bilinen saldırı desenlerini arar."""
    # SQL Injection, Command Injection, Path Traversal gibi yaygın saldırı izleri
    patterns = {
        "SQL Injection": r"('|\"|\s)(union|select|insert|update|delete|or|and)(\s|\"|')",
        "Path Traversal": r"\.\./",
        "Komut Satırı Enjeksiyonu": r"(;|\`|\$)(\s)*(ls|cat|whoami|uname|wget)",
        "Zafiyet Tarayıcı": r"sqlmap|nmap|nikto|wpscan"
    }
    
    for attack_type, pattern in patterns.items():
        # re.IGNORECASE: büyük/küçük harf duyarsız arama yapar
        if re.search(pattern, line, re.IGNORECASE):
            ip_address = line.split(' ')[0] # Genellikle log satırının başındaki IP
            print(f"{Renk.SARI}[!] UYARI: POTANSİYEL WEB SALDIRISI GİRİŞİMİ!{Renk.RESET}")
            print(f"  > Saldırı Tipi: {attack_type}")
            print(f"  > Saldırgan IP: {ip_address}")
            print(f"  > Tespit Edilen Log: {line.strip()}\n")
            # Web saldırılarında genellikle tek bir satır bile önemlidir, bu yüzden anında uyarı veriyoruz.
            return # Bir saldırı tipi bulduysak diğerlerine bakmaya gerek yok.

# --- DOSYA İZLEME MOTORU ---

def tail_file(filepath, callback_function):
    """Bir dosyayı sürekli izler ve yeni eklenen satırları işlenmek üzere callback_function'a gönderir."""
    print(f"{Renk.MAVI}[INFO] '{filepath}' dosyası anlık olarak izleniyor...{Renk.RESET}")
    try:
        with open(filepath, 'r') as f:
            # Dosyanın sonuna git
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)  # Yeni satır yoksa kısa bir süre bekle
                    continue
                # Yeni satır varsa, ilgili tespit fonksiyonuna gönder
                callback_function(line)
    except FileNotFoundError:
        print(f"{Renk.KIRMIZI}[HATA] '{filepath}' dosyası bulunamadı. Lütfen boş bir dosya oluşturun.{Renk.RESET}")
    except Exception as e:
        print(f"{Renk.KIRMIZI}[HATA] Bir sorun oluştu: {e}{Renk.RESET}")


if __name__ == "__main__":
    # Her log dosyası için ayrı bir izleme süreci (thread) başlatıyoruz.
    # Bu sayede iki dosyayı da aynı anda, birbirini engellemeden izleyebiliriz.
    auth_thread = threading.Thread(target=tail_file, args=(CONFIG["auth_log_path"], detect_ssh_brute_force))
    access_thread = threading.Thread(target=tail_file, args=(CONFIG["access_log_path"], detect_web_attack))
    
    auth_thread.daemon = True  # Ana program kapandığında thread'in de kapanmasını sağlar
    access_thread.daemon = True
    
    auth_thread.start()
    access_thread.start()
    
    # Ana programın kapanmaması için sonsuz bir döngüde bekletiyoruz.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Renk.MAVI}[INFO] Monitör kapatılıyor... Hoşça kalın!{Renk.RESET}")
