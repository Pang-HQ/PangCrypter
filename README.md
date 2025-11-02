# PangCrypter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

PangCrypter is a secure text editor with military-grade encryption capabilities. It provides a user-friendly interface for encrypting and editing sensitive files with strong AES-256 encryption, featuring hardware-tied security through USB key binding.

## ✨ Features

### 🔐 Advanced Encryption
- **AES-256 Encryption**: Military-grade encryption for maximum security
- **Multiple Encryption Modes**:
  - Password-only encryption
  - USB key-only encryption (hardware-tied)
  - Password + USB key hybrid encryption
- **Secure Key Storage**: Hidden key storage on removable drives

### 🎨 Modern User Interface
- **Dark Theme**: Easy on the eyes with a professional dark interface
- **Rich Text Editor**: Full-featured text editing with formatting support
- **Screen Recording Protection**: Automatic editor hiding during screen recording
- **Focus Protection**: Editor hides when focus is lost (configurable)

### 🔄 Auto-Updates
- **Automatic Update Checking**: Built-in updater that checks for new versions
- **One-Click Installation**: Seamless update process with progress tracking
- **Safe Updates**: Backup creation and rollback capability

### 🛡️ Security Features
- **Hardware-Bound Keys**: Encryption keys tied to specific USB drives
- **Memory Security**: Secure memory clearing to prevent data leaks
- **Process Monitoring**: Detection of screen recording software
- **Secure File Handling**: Safe encryption/decryption with validation

## 🚀 Installation

### Option 1: Pre-built Executable (Recommended)
1. Download the latest release from [GitHub Releases](https://github.com/Pang-Dev/PangCrypter/releases)
2. Extract the ZIP file
3. Run `PangCrypter.exe`

### Option 2: From Source
```bash
# Clone the repository
git clone https://github.com/Pang-Dev/PangCrypter.git
cd PangCrypter

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
# Or as a module:
python -m pangcrypter
```

### Option 3: Using Setup.py
```bash
# Install as a Python package
pip install .

# Or for development
pip install -e .
```

## 📖 Usage

### Basic Usage
1. **Launch**: Double-click `PangCrypter.exe` or run `python -m pangcrypter.main`
2. **Create/Open Files**: Use **File → Open** to open encrypted `.enc` files
3. **Edit Securely**: Work with your files in the built-in rich text editor
4. **Save Encrypted**: Files are automatically encrypted when saved

### Encryption Modes

#### Password-Only Mode
- Uses a password for encryption/decryption
- Good for personal use and file sharing

#### USB Key-Only Mode
- Encryption key bound to a specific USB drive
- Hardware-tied security - requires the USB drive to decrypt
- Perfect for high-security scenarios

#### Password + USB Key Mode
- Combines password and hardware security
- Maximum security with two-factor authentication

### Auto-Updates
- **Check for Updates**: Go to **Help → Check for Updates**
- **Automatic Updates**: The app can download and install updates automatically
- **Safe Installation**: Creates backups and handles failures gracefully

## 🏗️ Project Structure

```
pangcrypter/
├── core/                    # Core functionality
│   ├── __init__.py
│   ├── encrypt.py          # Encryption/decryption logic
│   ├── key.py              # Key management
│   └── updater.py          # Auto-update functionality
├── ui/                     # User interface components
│   ├── __init__.py
│   ├── main_ui.py          # Main UI components
│   ├── update_dialog.py    # Update dialog
│   └── messagebox.py       # Custom message boxes
├── utils/                  # Utility functions
│   ├── __init__.py
│   ├── preferences.py      # User preferences
│   └── styles.py           # UI styling
└── __init__.py            # Package initialization

scripts/                    # Build and utility scripts
├── build.py               # PyInstaller build script

tests/                     # Test files
├── test_*.py             # Unit and integration tests

docs/                     # Documentation
requirements.txt          # Python dependencies
setup.py                 # Package setup script
README.md                # This file
LICENSE                  # MIT License
```

## 🔧 Development

### Prerequisites
- Python 3.8 or higher
- PyQt6
- Required dependencies (see `requirements.txt`)

### Building from Source
```bash
# Install development dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Run tests
python -m pytest tests/

# Build executable
python scripts/build.py
```

### Code Quality
- Follow PEP 8 style guidelines
- Use type hints for better code documentation
- Write comprehensive tests for new features
- Update documentation for API changes

## ⚠️ Security Notes

### Important Warnings
- **Data Loss Risk**: Losing your USB drive or password means data recovery is likely impossible
- **Backup Strategy**: Always maintain secure backups of critical encrypted files
- **Hardware Security**: USB keys are bound to specific drives - moving keys between drives won't work

### Best Practices
- Use strong, memorable passwords
- Store USB drives in secure locations
- Regularly backup your encryption keys (if using password-only mode)
- Keep your operating system and antivirus software updated
- Be aware of screen recording when working with sensitive data

### Technical Security
- **AES-256 Encryption**: Industry-standard encryption strength
- **Hardware Binding**: Keys are cryptographically tied to USB drive hardware IDs
- **Memory Security**: Sensitive data is securely cleared from memory
- **Process Monitoring**: Automatic detection of screen recording software

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the `docs/` folder for detailed guides
- **Issues**: Report bugs on [GitHub Issues](https://github.com/Pang-Dev/PangCrypter/issues)
- **Discussions**: Join community discussions on [GitHub Discussions](https://github.com/Pang-Dev/PangCrypter/discussions)
- **Contact**: Reach out at [panghq.com/contact](https://www.panghq.com/contact)

## 🙏 Acknowledgments

- Built with [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) for the GUI
- Uses [cryptography](https://cryptography.io/) for encryption
- Inspired by the need for secure, user-friendly encryption tools

---

**Enjoy secure and hassle-free encrypted editing with PangCrypter! 🔒✨**
