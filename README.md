# Vault Messenger - Modernisierung & Integration

## 📦 Neue/Aktualisierte Komponenten

### 1. **vault_config.py** (NEU)
Sichere Konfigurationsverwaltung mit Verschlüsselung.

**Hauptmerkmale:**
```python
# Verwendung
config = VaultConfig(app_name="VaultMessenger", use_encryption=True)
config.load()

# Sichere Einstellungen
config.set("user.name", "Alice")
config.set("network.port", 11000)
config.save()

# Verschlüsselt in ~/.config/VaultMessenger/ (Linux)
# oder ~/AppData/Local/VaultMessenger/ (Windows)
```

**Sicherheit:**
- ✅ Private Keys verschlüsselt mit NaCl SecretBox
- ✅ Atomic writes (kein Corrupting bei Crash)
- ✅ Platform-spezifische sichere Verzeichnisse
- ✅ Datei-Permissions 0o600 (nur Besitzer)
- ✅ Passwort-basierte Schlüsselerzeugung mit Argon2i

---

### 2. **Message.py** (VERBESSERT)
Sichere Nachrichtenverarbeitung mit modernen kryptographischen Praktiken.

**Verbesserungen:**

#### Vorher (Unsicher):
```python
def __set_uuid(self):
    uuid_to_set = str(uuid.uuid4())  # ❌ Vorhersehbar
```

#### Nachher (Sicher):
```python
def __set_uuid(self) -> None:
    random_bytes = nacl.utils.random(16)  # ✅ 128-bit Crypto Random
    uuid_str = random_bytes.hex()
```

#### Vorher (Timing-Attack anfällig):
```python
def padding(self, length):
    for i in range(length):
        return_string += random.choice(alphabet)  # ❌ Timing-Seitenkanal
```

#### Nachher (Konstante Zeit):
```python
@staticmethod
def __generate_padding(length: int) -> str:
    random_bytes = nacl.utils.random(length)  # ✅ Schnell & sicher
    return random_bytes.hex()
```

**Neue Type Hints:**
```python
def set_text(self, text: str) -> None:
def to_json(self) -> List[str]:
def from_json(self, input_list: Union[str, List[str]]) -> None:
```

**Exception Handling:**
```python
# Vorher: Bare except
try:
    json.loads(data)
except:  # ❌
    return

# Nachher: Spezifische Exceptions
try:
    json.loads(data)
except json.JSONDecodeError as e:  # ✅
    raise InvalidMessageError(f"Invalid JSON: {e}")
```

---

### 3. **Messenger_GUI.py** (VÖLLIG ÜBERARBEITET)

#### Problem: GUI Blocking bei Netzwerk-Operationen

**Vorher (Blocking):**
```python
# ❌ Freezt die GUI
threading.Timer(5, self.update_ctl_send).start()
```

**Nachher (Qt-Thread):**
```python
# ✅ Nicht-blockierend
self._network_thread = PyQt6.QtCore.QThread()
self._network_worker = NetworkWorker()
self._network_worker.moveToThread(self._network_thread)
self._network_thread.started.connect(self._on_network_worker_started)
self._network_thread.start()
```

#### Problem: Keine Input-Validierung

**Vorher (Unsicher):**
```python
# ❌ Keine Prüfung
int(self.textboxes_addr[addr_number][1].text())
```

**Nachher (Mit Validierung):**
```python
# ✅ Umfangreiche Validierung
class InputValidator:
    @staticmethod
    def validate_port(port_input: str) -> Tuple[bool, Optional[int], str]:
        try:
            port = int(port_input.strip())
        except ValueError:
            return False, None, "Port must be a number"
        
        if port < VALID_PORT_MIN or port > VALID_PORT_MAX:
            return False, None, f"Port must be between {VALID_PORT_MIN} and {VALID_PORT_MAX}"
        
        return True, port, ""

    @staticmethod
    def validate_ip(ip_input: str) -> Tuple[bool, str]:
        # ... (siehe Code)

    @staticmethod
    def validate_name(name_input: str) -> Tuple[bool, str]:
        # ... (siehe Code)
```

#### Problem: Config-Dateien unsicher gespeichert

**Vorher (Unsicher):**
```python
# ❌ Im aktuellen Verzeichnis, unverschlüsselt
self.filename = "{}/{}".format(os.getcwd(), "config/config.json")
# Private Keys in Klartext!
```

**Nachher (Sicher):**
```python
# ✅ Platform-spezifisches Verzeichnis, verschlüsselt
self.config = vault_config.VaultConfig(
    app_name="VaultMessenger",
    use_encryption=True,
)
self.config.load()
```

#### Problem: Keine Type Hints

**Vorher:**
```python
def on_recv_text(self, text, addr=""):  # ❌
```

**Nachher:**
```python
def _on_network_worker_error(self, error_msg: str) -> None:  # ✅
```

---

## 🔄 Integration mit UDP-Bibliothek

Die aktualisierte UDP-Bibliothek (vault_udp_socket.py v2) ist vollständig kompatibel.

### Hauptänderungen:

#### 1. Protokoll v2 Support
```python
from vault_udp_socket import UDPSocketClass, PROTOCOL_VERSION

socket = UDPSocketClass(recv_port=11000)
print(f"Protocol version: {PROTOCOL_VERSION}")  # Version 2
```

#### 2. Bessere Exception Handling
```python
# Vorher: Generische Exception
except:
    pass

# Nachher: Spezifische Exceptions
from vault_udp_socket import (
    RateLimitExceededError,
    MessageTooLargeError,
    ProtocolVersionError,
)

try:
    socket.send_data(data)
except RateLimitExceededError:
    logger.warning("Rate limit exceeded")
except MessageTooLargeError:
    logger.warning("Message exceeds MTU")
```

#### 3. Type Hints in UDP
```python
def send_data(self, data: Any, addr: Optional[Tuple[str, int]] = None) -> None:
def add_peer(self, addr: Tuple[str, int]) -> None:
def get_peers(self) -> List[Tuple[str, int]]:
```

#### 4. Verbesserte Fehlerbehandlung in Multicast
```python
# vault_multicast_service_discovery.py
try:
    self.listener = vault_multicast.VaultMultiListener()
    self.listener.recv_signal.connect(self._on_service_discovered)
    self.listener.start()
except Exception as e:
    logger.error("Failed to start listener: %s", e)
    PyQt6.QtWidgets.QMessageBox.critical(self, "Error", f"Failed: {e}")
```

---

## 📋 Migrationsschritte

### 1. Neue Abhängigkeiten installieren
```bash
pip install --upgrade platformdirs  # Für XDG-Compliance
pip install --upgrade pyzstd msgpack  # Falls noch nicht vorhanden
```

### 2. Alte Config-Dateien migrieren

```python
# migration.py
import json
from pathlib import Path
import vault_config

# Alte Config (im CWD)
old_config_file = Path("config/config.json")

if old_config_file.exists():
    with open(old_config_file) as f:
        old_data = json.load(f)
    
    # Neue sichere Config
    new_config = vault_config.VaultConfig(
        app_name="VaultMessenger",
        use_encryption=True,
    )
    
    # Daten kopieren
    for key, value in old_data.items():
        new_config.set(key, value)
    
    new_config.save()
    print(f"✓ Config migrated to {new_config._config_file}")
```

### 3. GUI-Code aktualisieren

```python
# ALT: Nicht-threadsicher
from Messenger_GUI import MessengerGui
gui = MessengerGui()

# NEU: Thread-sicher
from Messenger_GUI import MessengerGui, setup_logging
import vault_config

config = vault_config.VaultConfig()
setup_logging(config)

gui = MessengerGui()
gui.show()
```

---

## ✅ Verbesserungen Zusammenfassung

| Problem | Lösung | Status |
|---------|--------|--------|
| UUID vorhersehbar | nacl.utils.random(16) | ✅ Behoben |
| Padding Timing-Angriff | Konstante Zeit (hex) | ✅ Behoben |
| Config unsicher | vault_config.py mit Verschlüsselung | ✅ Behoben |
| GUI blockiert | QThread + NetworkWorker | ✅ Behoben |
| Keine Input-Validierung | InputValidator Klasse | ✅ Behoben |
| Bare except clauses | Spezifische Exceptions | ✅ Behoben |
| Type Hints fehlen | Überall hinzugefügt | ✅ Behoben |
| Logging minimal | RotatingFileHandler + Config | ✅ Behoben |
| Exception Handling schwach | Umfassendes Auditing | ✅ Behoben |

---

## 🔒 Sicherheits-Checkliste

- ✅ Private Keys verschlüsselt
- ✅ UUID kryptographisch sicher
- ✅ Padding konstante Zeit
- ✅ Input Validierung überall
- ✅ Exception Handling spezifisch
- ✅ Type Hints vollständig
- ✅ Config-Datei permissions 0o600
- ✅ Atomic writes für Config
- ✅ Thread-sichere GUI
- ✅ Logging mit Rotation

---

## 📝 Verwendungsbeispiel

```python
#!/usr/bin/env python3

import logging
import sys
from pathlib import Path

import PyQt6.QtWidgets

import vault_config
from Messenger_GUI import MessengerGui, setup_logging

def main():
    """Main entry point with proper setup."""
    # Initialize config
    config = vault_config.VaultConfig(
        app_name="VaultMessenger",
        use_encryption=True,
    )
    config.load()

    # Setup logging
    setup_logging(config)
    logger = logging.getLogger(__name__)
    logger.info("Starting Vault Messenger")

    # Create Qt app
    app = PyQt6.QtWidgets.QApplication(sys.argv)

    # Create and show GUI
    try:
        window = MessengerGui()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        logger.critical("Failed to start messenger: %s", e)
        PyQt6.QtWidgets.QMessageBox.critical(
            None,
            "Startup Error",
            f"Failed to start Vault Messenger: {e}",
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
```

---

## 🚀 Nächste Schritte

1. ✅ **Vollständige Unit Tests** für Message, Config, Validierung
2. ✅ **Integration Tests** für UDP Socket
3. ✅ **Security Audit** des Key-Exchange-Protokolls
4. ✅ **Performance Tests** bei vielen gleichzeitigen Peers
5. ✅ **Documentation** für Protokoll und APIs

---

## 📚 Referenzen

- [NaCl Dokumentation](https://pynacl.readthedocs.io/)
- [PyQt6 Threading Best Practices](https://doc.qt.io/qt-6/qthread.html)
- [Platformdirs XDG Compliance](https://platformdirs.readthedocs.io/)
- [OWASP Password Hashing](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
