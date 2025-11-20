# Messenger Application

A secure, decentralized peer-to-peer messaging application with encrypted communication, file transfer, and image sharing capabilities.

## 🌟 Features

- **Authenticated Encryption**: NaCl-based asymmetric encryption with replay protection
- **Message Splitting**: Automatic large message splitting and reassembly
- **Multiple Content Types**: Text, images, and file transfers
- **Service Discovery**: Multicast-based peer discovery
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Modern UI**: PyQt6-based graphical interface
- **Configuration Management**: Persistent configuration with auto-migration
- **Thread-Safe**: Concurrent message handling and network operations

## 📋 System Requirements

- **Python**: 3.8 or higher
- **OS**: Windows, macOS, or Linux
- **RAM**: 256 MB minimum
- **Network**: UDP port 11000+ (configurable)

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd messenger

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. First Run

```bash
python Messenger_GUI.py
```

On first launch:
- Application will generate encryption and signing keys
- Configuration file will be created at `~/.config/Messenger/config.json`
- You'll be prompted to configure connection settings

### 3. Connect to Another Messenger

1. Note your IP address and port (displayed in "Aktueller Zustand" button)
2. In the other Messenger: Click "Einstellungen" (Settings)
3. Enter IP and port of the first Messenger
4. Click "Ok" to save configuration

## 📁 Project Structure

```
messenger/
├── Messenger_GUI.py                 # Main application GUI
├── Message.py                       # Message serialization/deserialization
├── config_manager.py                # Configuration management
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
└── libs/
    ├── udp/
    │   ├── vault_ip.py             # Network interface utilities
    │   ├── vault_udp_socket.py     # UDP socket with encryption
    │   ├── vault_udp_encryption.py # Asymmetric encryption handler
    │   └── vault_udp_socket_helper.py  # Cryptographic primitives
    └── multicast/
        ├── vault_multicast.py       # Multicast publisher/listener
        └── vault_multicast_service_discovery.py  # Service discovery UI
```

## 🔑 Key Features Explained

### Dual-Key System

The application uses two pairs of keys:

- **Encryption Keys** (X25519): For message encryption/decryption
- **Signing Keys** (Ed25519): For message authentication

Both keys are:
- Generated on first run
- Stored in `config.json` (encrypted recommended for production)
- Used for authenticated encryption between peers

### Message Handling

Messages are automatically:
1. Split into chunks if larger than MTU
2. Serialized to JSON with metadata
3. Encrypted with peer's public key
4. Sent with sequence numbers and hashes
5. Reassembled on receipt
6. Verified for integrity

### Configuration

Default configuration path:
- **Windows**: `%APPDATA%\Local\Messenger\config.json`
- **macOS/Linux**: `~/.config/Messenger/config.json`

Configuration includes:
- Application name and settings
- Public/private encryption and signing keys
- Known peers (IP, port, timestamp)
- User display names

## 🎮 Usage Guide

### Sending Text Messages

1. Type message in the input field
2. Click "Send" or press Enter
3. Message will appear in the output area

### Sending Images

1. Click "Bild senden" (Send Image)
2. Select an image file
3. Image will be compressed and sent
4. Recipient receives notification

### Sending Files

1. Click "Datei senden" (Send File)
2. Select the file to send
3. File will be Base64 encoded and transmitted
4. Recipient can save the file

### Settings

Click "Einstellungen" to:
- Change your display name
- Add/remove peer addresses
- Discover peers via multicast
- Save configuration

### View Status

Click "Aktueller Zustand" (Current State) to see:
- Number of connected peers
- MTU (Maximum Transmission Unit)
- Current receive port

## 🔐 Security

### Encryption

- **Method**: NaCl Box (Curve25519 + XSalsa20-Poly1305)
- **Authentication**: Sender authentication included
- **Replay Protection**: Nonce tracking and timestamp validation
- **Hash Verification**: SHA256 for message integrity

### Key Management

- Keys are unique per installation
- Auto-migration from legacy format to dual-key system
- Keys persist across sessions
- Public keys shared only via control messages

### Recommendations for Production

- Store private keys with restricted file permissions
- Use environment variables for sensitive configuration
- Enable firewall rules for UDP port
- Regular backups of `config.json`
- Use certificate pinning for known peers

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Find process using the port
lsof -i :11000

# Kill the process (if needed)
kill -9 <PID>
```

### "No peers to send to"

- Ensure peer is configured in Settings
- Check peer IP and port are correct
- Verify network connectivity between peers

### "Hash validation failed"

- Message may be corrupted in transit
- Try resending the message
- Check network conditions

### Config Migration Failed

- Delete `config.json`
- Restart the application
- New keys will be generated automatically

## 📊 Logging

Enable debug logging:

```bash
export LOGLEVEL=DEBUG
python Messenger_GUI.py
```

Or set in code:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Logs are sent to:
- Console (stdout)
- Optional: File (configure in logging setup)

## 🧪 Testing

### Unit Tests

```bash
# Run message serialization tests
python -m pytest tests/test_message.py -v

# Run socket tests
python -m pytest tests/test_socket.py -v

# Run all tests with coverage
python -m pytest --cov=. --cov-report=html
```

### Integration Tests

```bash
# Terminal 1
python Messenger_GUI.py

# Terminal 2 (different port in settings)
python Messenger_GUI.py

# Send text, images, and files between instances
```

### Verification Scripts

```bash
# Check key configuration
python debug_keys.py

# Test config migration
python test_config_migration.py

# Test key handling
python test_key_handling.py

# Test control messages
python test_control_messages.py
```

## 📈 Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Startup | < 3s | With config load |
| Key Generation | < 1s | One-time only |
| Key Exchange | < 5s | Between peers |
| Text Message | < 100ms | 1KB text |
| Image (100KB) | < 500ms | Auto-compressed |
| MTU | ~1300 bytes | After encryption overhead |

## 🔄 Protocol Details

### Protocol Version

Current: **v2** with following features:
- Versioned message format
- Separation of control and payload channels
- Structured msgpack serialization
- Automatic replay protection

### Message Types

| Type | Purpose | Format |
|------|---------|--------|
| `txt` | Text messages | UTF-8 encoded |
| `img` | Image transfer | Base64 encoded |
| `dat` | File transfer | JSON with metadata |
| `ctl` | Control/ACK | JSON with command |

### Handshake

1. Peer A sends public keys via multicast/control message
2. Peer B receives and stores keys
3. Peer B sends its public keys to A
4. Peers can now communicate securely

## 🛠 Development

### Code Style

```bash
# Format with black
black Messenger_GUI.py Message.py

# Check with pylint
pylint Messenger_GUI.py

# Type checking with mypy
mypy Messenger_GUI.py --ignore-missing-imports
```

### Adding Features

1. Create feature branch: `git checkout -b feature/new-feature`
2. Make changes with tests
3. Run tests: `pytest`
4. Commit: `git commit -m "feat: description"`
5. Push: `git push origin feature/new-feature`
6. Create Pull Request

### Key Files to Modify

- **UI Changes**: `Messenger_GUI.py` - MessengerGui class
- **Message Logic**: `Message.py` - Message/MessageHandler classes
- **Network**: `libs/udp/vault_udp_socket.py`
- **Encryption**: `libs/udp/vault_udp_encryption.py`

## 📚 Architecture

### Signal Flow

```
UI Events (Button Click)
    ↓
Messenger GUI Handler
    ↓
Message Handler (send_*_msg)
    ↓
Socket Send (UDP)
    ↓
[Network]
    ↓
Socket Receive (UDP)
    ↓
Message Handler (recv_msg)
    ↓
Assembly & Verification
    ↓
Signal Emit (mh_recv_text, etc)
    ↓
UI Update Handler
    ↓
Display in Output Box
```

### Threading Model

- **Main Thread**: UI event handling
- **Socket Thread**: UDP receive loop
- **Cleanup Thread**: Message buffer management
- **Key Management Thread**: Periodic key refresh
- **Timers**: Qt event loop based

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

Apache License 2.0 - See LICENSE file for details

## 🙋 Support

### Reporting Issues

1. Check existing issues
2. Provide detailed reproduction steps
3. Include logs (with sensitive data removed)
4. Specify OS and Python version

### Getting Help

- Review this README
- Check logs with `DEBUG` level enabled
- Run verification scripts
- Test with simple messages first

## 📝 Version History

### v2.1 (Current)
- ✅ Dual-key system (encryption + signing)
- ✅ Config auto-migration
- ✅ Protocol v2 with structured format
- ✅ Replay attack prevention
- ✅ Comprehensive error handling
- ✅ Full logging support

### v2.0
- Vault API v2 integration
- Message splitting and reassembly
- Multicast service discovery

### v1.0
- Initial release
- Basic text messaging
- Single-key encryption

## 🎯 Roadmap

- [ ] Web UI alternative to Qt
- [ ] Mobile client support
- [ ] End-to-end group messaging
- [ ] Message history/persistence
- [ ] User profile management
- [ ] Advanced network protocols (QUIC)
- [ ] Cloud synchronization
- [ ] REST API for integrations

## ⚙️ Configuration Reference

### config.json Structure

```json
{
    "title": "Messenger",
    "name": "User1",
    "bsd_type": "BertMessenger",
    "recv_port": 11000,
    "icon": null,
    "addr": [
        ["192.168.1.100", 11001, "2025-01-20 10:00:00"]
    ],
    "enc_pub_key": "...",
    "enc_priv_key": "...",
    "sign_pub_key": "...",
    "sign_priv_key": "...",
    "addr_name": {
        "192.168.1.100": ["User2", 1234567890]
    }
}
```

### Environment Variables

```bash
# Set log level
export LOGLEVEL=DEBUG

# Set config directory
export MESSENGER_CONFIG_DIR=~/.config/custom

# Disable auto-migration
export SKIP_CONFIG_MIGRATION=1
```

## 📞 Contact

For questions or suggestions:
- Create an issue on GitHub
- Check discussions for Q&A
- Review existing documentation

---

**Happy Messaging! 🚀**

Made with ❤️ for secure peer-to-peer communication