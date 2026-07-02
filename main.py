#!/usr/bin/env python3
import argparse
import getpass
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

HAS_STEM = False
try:
    from stem import Signal
    from stem.control import Controller
    HAS_STEM = True
except ImportError:
    pass

DEFAULT_CONTROL_PORT = 9051
DEFAULT_SOCKS_PORT = 9050
DEFAULT_INTERVAL = 60
MIN_INTERVAL = 10
MAX_INTERVAL = 3600
CONFIG_DIR = Path.home() / ".config" / "tor-rotator"
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_FILE = CONFIG_DIR / "rotator.log"
PID_FILE = CONFIG_DIR / "rotator.pid"

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"

def ensure_dependencies():
    global HAS_STEM
    if HAS_STEM:
        return True
    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} Required package 'stem' is not installed.")
    if sys.stdin.isatty():
        choice = input("Would you like to install 'stem' automatically via pip? [y/N]: ").strip().lower()
        if choice == "y":
            print("Installing stem...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "stem"], check=True)
                from stem import Signal
                from stem.control import Controller
                HAS_STEM = True
                print(f"{Colors.GREEN}Successfully installed stem!{Colors.RESET}")
                return True
            except Exception as e:
                print(f"{Colors.RED}Failed to install stem automatically: {e}{Colors.RESET}")
                print("Please install it manually using: pip3 install stem")
                sys.exit(1)
        print("Exiting. The 'stem' package is required to control Tor.")
        sys.exit(1)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [ERROR] Missing dependency 'stem'. Run 'pip3 install stem' to fix.\n")
    print("ERROR: Missing dependency 'stem'. Cannot run as daemon without it.")
    sys.exit(1)

class TorRotator:
    def __init__(self, args):
        self.args = args
        self.controller = None
        self.running = False
        self.shutdown_event = threading.Event()
        self.stats = {"rotations": 0, "failures": 0, "start_time": None}
        self.current_ip = None
        self._setup_config()
        self._setup_logging()
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)

    def _setup_config(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.config = {}
        if CONFIG_FILE.exists():
            try:
                self.config = json.loads(CONFIG_FILE.read_text())
            except Exception:
                self.config = {}
        defaults = {
            "control_port": DEFAULT_CONTROL_PORT,
            "socks_port": DEFAULT_SOCKS_PORT,
            "interval": DEFAULT_INTERVAL,
            "password": None,
            "auto_start": False,
            "verify_ip": True
        }
        updated = False
        for k, v in defaults.items():
            if k not in self.config:
                self.config[k] = v
                updated = True
        if updated:
            self._save_config()

    def _save_config(self):
        try:
            CONFIG_FILE.write_text(json.dumps(self.config, indent=2))
        except Exception as e:
            self.log(f"Failed to write config: {e}", "ERROR")

    def _setup_logging(self):
        self.verbose = getattr(self.args, "verbose", False)
        self.quiet = getattr(self.args, "quiet", False)

    def log(self, message, level="INFO"):
        if level == "DEBUG" and not self.verbose:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARN": Colors.YELLOW,
            "ERROR": Colors.RED,
            "DEBUG": Colors.BLUE
        }
        formatted = f"{colors.get(level, Colors.WHITE)}[{timestamp}]{Colors.RESET} {message}"
        if not self.quiet:
            print(formatted)
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
        except Exception:
            pass

    def handle_shutdown(self, signum, frame):
        signame = signal.Signals(signum).name
        self.log(f"Received signal {signame} ({signum}). Initiating graceful shutdown...", "WARN")
        self.running = False
        self.shutdown_event.set()
        raise KeyboardInterrupt

    def is_port_open(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                return s.connect_ex(("127.0.0.1", port)) == 0
        except Exception:
            return False

    def validate_tor_installation(self):
        tor_paths = ["/opt/homebrew/bin/tor", "/usr/local/bin/tor", "/usr/bin/tor"]
        which_tor = shutil.which("tor")
        if which_tor:
            tor_paths.insert(0, which_tor)
        for path in tor_paths:
            if path and Path(path).exists():
                self.log(f"Found Tor installation at: {path}", "DEBUG")
                return path
        self.log("Tor installation was not found on your system.", "ERROR")
        self.log("Install it using Homebrew: brew install tor", "INFO")
        return None

    def validate_torrc(self):
        torrc_paths = [
            Path("/opt/homebrew/etc/tor/torrc"),
            Path("/usr/local/etc/tor/torrc"),
            Path("/etc/tor/torrc"),
            Path.home() / ".torrc",
            Path.home() / ".config" / "tor" / "torrc"
        ]
        found_path = None
        for path in torrc_paths:
            if path.exists():
                found_path = path
                break
        if not found_path:
            self.log("torrc configuration file not found in standard locations.", "WARN")
            self.log("Tor might run with default settings. Please ensure ControlPort 9051 is enabled.", "INFO")
            return False
        self.log(f"Validating torrc configuration at: {found_path}", "DEBUG")
        try:
            content = found_path.read_text()
            active_lines = []
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    active_lines.append(line)
            active_content = "\n".join(active_lines)
            has_control = "ControlPort" in active_content
            has_socks = "SOCKSPort" in active_content
            has_auth = "CookieAuthentication" in active_content or "HashedControlPassword" in active_content
            issues = []
            if not has_control:
                issues.append("ControlPort is not configured (add 'ControlPort 9051' to torrc)")
            if not has_socks:
                issues.append("SOCKSPort is not configured (add 'SOCKSPort 9050' to torrc)")
            if not has_auth:
                issues.append("No ControlPort authentication configured (add 'CookieAuthentication 1' or 'HashedControlPassword')")
            if issues:
                for issue in issues:
                    self.log(f"torrc configuration warning: {issue}", "WARN")
                return False
            self.log("torrc validation completed successfully.", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Failed to read torrc file: {e}", "ERROR")
            return False

    def check_tor_service(self):
        control_port = self.args.port or self.config.get("control_port", DEFAULT_CONTROL_PORT)
        socks_port = self.args.socks_port or self.config.get("socks_port", DEFAULT_SOCKS_PORT)
        if self.is_port_open(control_port) or self.is_port_open(socks_port):
            self.log(f"Tor service detected (port {control_port} or {socks_port} is active)")
            return True
        try:
            result = subprocess.run(["pgrep", "-x", "tor"], capture_output=True, text=True)
            if result.returncode == 0:
                self.log("Tor process detected (found via pgrep)")
                return True
        except Exception:
            pass
        brew_found = shutil.which("brew") is not None
        if brew_found:
            try:
                result = subprocess.run(["brew", "services", "list"], capture_output=True, text=True)
                if "tor" in result.stdout and "started" in result.stdout:
                    self.log("Tor service detected running under Homebrew services")
                    return True
            except Exception:
                pass
        self.log("Tor service is currently inactive.", "WARN")
        auto_start = self.config.get("auto_start", False)
        should_start = False
        if auto_start:
            should_start = True
        elif sys.stdin.isatty() and not getattr(self.args, "once", False):
            try:
                choice = input("Start Tor service now? [y/N]: ").strip().lower()
                should_start = choice == "y"
            except (KeyboardInterrupt, EOFError):
                should_start = False
        if should_start:
            if brew_found:
                self.log("Attempting to start Tor via Homebrew services...")
                subprocess.run(["brew", "services", "start", "tor"], capture_output=True)
                time.sleep(2.5)
                if self.is_port_open(control_port) or self.is_port_open(socks_port):
                    self.log("Tor service started successfully via Homebrew.", "SUCCESS")
                    return True
            tor_bin = self.validate_tor_installation()
            if tor_bin:
                self.log(f"Attempting to launch Tor binary directly: {tor_bin} ...")
                try:
                    subprocess.Popen([tor_bin, "--daemon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(2.5)
                    if self.is_port_open(control_port) or self.is_port_open(socks_port):
                        self.log("Tor binary started in background successfully.", "SUCCESS")
                        return True
                except Exception as e:
                    self.log(f"Failed to launch Tor binary directly: {e}", "ERROR")
        self.log("Could not establish connection or launch Tor service. Please start Tor manually.", "ERROR")
        return False

    def connect(self):
        port = self.args.port or self.config.get("control_port", DEFAULT_CONTROL_PORT)
        password = self.args.password or self.config.get("password")
        try:
            self.controller = Controller.from_port(port=port)
        except Exception as e:
            self.log(f"Connection to control port {port} failed: {e}", "ERROR")
            self.log("Ensure Tor is active and the correct ControlPort is specified.", "WARN")
            return False
        try:
            self.controller.authenticate()
            self.log(f"Successfully connected to Tor control port {port} (Authenticated).", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Default/Cookie authentication failed: {e}", "DEBUG")
        if password:
            try:
                self.controller.authenticate(password=password)
                self.log(f"Connected and authenticated to Tor control port {port} (Password).", "SUCCESS")
                return True
            except Exception as e:
                self.log(f"Password authentication failed: {e}", "ERROR")
        elif sys.stdin.isatty():
            self.log("Tor ControlPort requires a password for connection.", "WARN")
            try:
                prompted_password = getpass.getpass("Enter Tor ControlPort password: ")
                if prompted_password:
                    self.controller.authenticate(password=prompted_password)
                    self.log(f"Connected and authenticated to Tor control port {port} (Prompted Password).", "SUCCESS")
                    return True
            except Exception as e:
                self.log(f"Authentication failed: {e}", "ERROR")
        self.log("Authentication failed completely.", "ERROR")
        self.log("How to fix Tor authentication issues:", "INFO")
        self.log("1. Ensure 'CookieAuthentication 1' is active in torrc, and your user accounts have read access.", "INFO")
        self.log("2. Generate a hashed password using: tor --hash-password <your_password>", "INFO")
        self.log("3. Add the generated HashedControlPassword line to your torrc, and pass --password when starting this script.", "INFO")
        return False

    def get_current_ip(self):
        verify = self.config.get("verify_ip", True)
        if self.args.no_verify_ip:
            verify = False
        elif self.args.verify_ip:
            verify = True
        if not verify:
            return "Verification disabled"
        socks_port = self.args.socks_port or self.config.get("socks_port", DEFAULT_SOCKS_PORT)
        endpoints = [
            ("https://check.torproject.org/api/ip", True, lambda d: d.get("IP")),
            ("https://api.ipify.org?format=json", True, lambda d: d.get("ip")),
            ("https://ifconfig.me/ip", False, lambda t: t.strip()),
            ("https://icanhazip.com", False, lambda t: t.strip()),
            ("https://ipapi.co/ip", False, lambda t: t.strip())
        ]
        try:
            import requests
            for url, is_json, extractor in endpoints:
                try:
                    session = requests.Session()
                    session.proxies = {
                        "http": f"socks5h://127.0.0.1:{socks_port}",
                        "https": f"socks5h://127.0.0.1:{socks_port}"
                    }
                    self.log(f"Verifying IP via {url} (requests)...", "DEBUG")
                    response = session.get(url, timeout=7)
                    if response.status_code == 200:
                        ip = extractor(response.json()) if is_json else extractor(response.text)
                        if ip:
                            return ip
                except Exception as e:
                    self.log(f"Verification endpoint {url} failed: {e}", "DEBUG")
        except ImportError:
            self.log("requests package not available. Falling back to native curl...", "DEBUG")
        for url, is_json, extractor in endpoints:
            try:
                self.log(f"Verifying IP via {url} (curl)...", "DEBUG")
                cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{socks_port}", "--connect-timeout", "7", url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout:
                    text = result.stdout.strip()
                    if is_json:
                        try:
                            data = json.loads(text)
                            ip = extractor(data)
                        except json.JSONDecodeError:
                            ip = text
                    else:
                        ip = extractor(text)
                    if ip:
                        return ip
            except Exception as e:
                self.log(f"Curl verification endpoint {url} failed: {e}", "DEBUG")
        return "Failed to resolve external IP (Circuit building or SOCKS connection issue)"

    def rotate(self):
        if not self.controller:
            return False
        try:
            try:
                wait_time = self.controller.get_newnym_wait()
            except Exception:
                wait_time = 10
            if wait_time > 0:
                self.log(f"Tor rate-limit active. Waiting {wait_time:.1f}s before rotation...", "INFO")
                self.shutdown_event.wait(timeout=wait_time)
                if not self.running:
                    return False
            self.controller.signal(Signal.NEWNYM)
            self.log("Sent NEWNYM signal to Tor controller. Building new circuit...", "INFO")
            self.shutdown_event.wait(timeout=2.0)
            if not self.running:
                return False
            new_ip = self.get_current_ip()
            self.current_ip = new_ip
            self.stats["rotations"] += 1
            self.log(f"Tor exit IP rotated successfully #{self.stats['rotations']}: {new_ip}", "SUCCESS")
            return True
        except Exception as e:
            self.stats["failures"] += 1
            self.log(f"Rotation operation failed: {e}", "ERROR")
            return False

    def _acquire_pid_lock(self):
        if PID_FILE.exists():
            try:
                old_pid = int(PID_FILE.read_text().strip())
                os.kill(old_pid, 0)
                self.log(f"Another instance is running (PID: {old_pid}). Exiting to prevent conflict.", "ERROR")
                sys.exit(1)
            except (ValueError, OSError):
                PID_FILE.unlink(missing_ok=True)
        try:
            PID_FILE.write_text(str(os.getpid()))
        except Exception as e:
            self.log(f"Failed to write PID file: {e}", "WARN")

    def _release_pid_lock(self):
        try:
            if PID_FILE.exists():
                pid = int(PID_FILE.read_text().strip())
                if pid == os.getpid():
                    PID_FILE.unlink(missing_ok=True)
        except Exception:
            pass

    def run(self):
        self.stats["start_time"] = time.time()
        interval = self.args.interval or self.config.get("interval", DEFAULT_INTERVAL)
        if interval < MIN_INTERVAL or interval > MAX_INTERVAL:
            self.log(f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL}. Fallback to default: {DEFAULT_INTERVAL}", "WARN")
            interval = DEFAULT_INTERVAL
        self.log(f"Starting Tor IP Rotator daemon (Rotation interval: {interval}s)")
        self._acquire_pid_lock()
        if not self.connect():
            self._release_pid_lock()
            return False
        self.current_ip = self.get_current_ip()
        self.log(f"Initial exit IP: {self.current_ip}")
        self.running = True
        try:
            if self.args.once:
                self.rotate()
            else:
                while self.running:
                    self.rotate()
                    if self.running:
                        self.shutdown_event.wait(timeout=interval)
        except KeyboardInterrupt:
            self.log("Interrupt signal received from user.", "WARN")
        finally:
            self.cleanup()
        return True

    def cleanup(self):
        self.running = False
        if self.controller:
            try:
                self.controller.close()
            except Exception:
                pass
        self._release_pid_lock()
        uptime = int(time.time() - self.stats["start_time"]) if self.stats["start_time"] else 0
        self.log(f"Session summary: {self.stats['rotations']} rotations, {self.stats['failures']} failures, {uptime}s uptime")

    def show_config(self):
        print(json.dumps(self.config, indent=2))

    def set_config(self, key, value):
        if key in self.config:
            try:
                if isinstance(self.config[key], bool):
                    if value.lower() in ("true", "1", "yes", "y"):
                        self.config[key] = True
                    elif value.lower() in ("false", "0", "no", "n"):
                        self.config[key] = False
                    else:
                        raise ValueError("Invalid boolean value")
                elif isinstance(self.config[key], int):
                    self.config[key] = int(value)
                else:
                    self.config[key] = value
                self._save_config()
                self.log(f"Config updated successfully: {key} = {self.config[key]}", "SUCCESS")
            except Exception as e:
                self.log(f"Invalid format/value for config '{key}': {e}", "ERROR")
        else:
            self.log(f"Unknown configuration key: {key}", "ERROR")

def main():
    ensure_dependencies()
    parser = argparse.ArgumentParser(description="Advanced Tor IP Rotator for macOS", formatter_class=argparse.RawDescriptionHelpFormatter, epilog="")
    parser.add_argument("-p", "--port", type=int, help="Tor ControlPort (default: 9051)")
    parser.add_argument("-s", "--socks-port", type=int, help="Tor SOCKSPort (default: 9050)")
    parser.add_argument("-i", "--interval", type=int, help=f"Rotation interval in seconds ({MIN_INTERVAL}-{MAX_INTERVAL})")
    parser.add_argument("--password", help="ControlPort password")
    parser.add_argument("--once", action="store_true", help="Rotate once and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (log only)")
    parser.add_argument("--verify-ip", action="store_true", help="Verify IP after rotation")
    parser.add_argument("--no-verify-ip", action="store_true", help="Disable IP verification")
    parser.add_argument("--config", nargs=2, metavar=("KEY", "VALUE"), help="Set config value")
    parser.add_argument("--show-config", action="store_true", help="Show current config")
    parser.add_argument("--validate", action="store_true", help="Validate Tor setup and exit")
    args = parser.parse_args()
    rotator = TorRotator(args)
    if args.show_config:
        rotator.show_config()
        return
    if args.config:
        rotator.set_config(args.config[0], args.config[1])
        return
    if args.validate:
        tor = rotator.validate_tor_installation()
        torrc = rotator.validate_torrc()
        service = rotator.check_tor_service()
        conn = rotator.connect()
        if tor and torrc and service and conn:
            print(f"\n{Colors.GREEN}✔ All Tor setup validations passed successfully.{Colors.RESET}")
            sys.exit(0)
        print(f"\n{Colors.RED}✘ Validation failed. Check the errors logged above.{Colors.RESET}")
        sys.exit(1)
    if not rotator.validate_tor_installation():
        sys.exit(1)
    rotator.validate_torrc()
    if not rotator.check_tor_service():
        sys.exit(1)
    rotator.run()

if __name__ == "__main__":
    main()
