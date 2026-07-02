# Tor IP Rotator for macOS

Production-ready Python script to automatically rotate Tor exit IP addresses on macOS.

## Prerequisites

- **macOS** (tested on macOS 15+)
- **Homebrew** package manager
- **Python**

### Install dependencies

```bash
brew install tor python
pip3 install stem requests
```

## Tor Configuration

Edit `/opt/homebrew/etc/tor/torrc` (Apple Silicon) or `/usr/local/etc/tor/torrc` (Intel):

```ini
ControlPort 9051
CookieAuthentication 1
# OR use hashed password instead:
# HashedControlPassword 16:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
CookieAuthFileGroupReadable 1
SOCKSPort 9050
```

Generate a hashed password (if using password auth):
```bash
tor --hash-password "your_password"
```

Start Tor service (or run manually: tor):
```bash
brew services start tor
```


<img src="https://github.com/user-attachments/assets/cd0a9d6e-261f-408a-96b4-3043a858eb09" style="max-width:700px; height:auto;" />
<img src="https://github.com/user-attachments/assets/f6ac1b9d-b4a4-4863-8356-27d4a80e2eaf" style="max-width:700px; height:auto;" />
<img src="https://github.com/user-attachments/assets/9bdc097d-44c2-402e-b482-bc2246a4038c" style="max-width:700px; height:auto;" />


Verify Tor is running:
```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

## Usage
```bash
# Show help
python3 main.py -h

# Rotate IP every 60 seconds (default)
python3 main.py

# Custom interval (seconds)
python3 main.py -i 30

# Custom control port
python3 main.py -p 9051

# With password authentication
python3 main.py --password "your_password"

# Rotate once and exit
python3 main.py --once

# Validate Tor setup and configuration
python3 main.py --validate
```

## Legal & Ethical Notice
**This tool is provided for educational and privacy research purposes only.**

- **Legal compliance**: Use in accordance with your local laws and regulations
- **Terms of Service**: Respect Tor network policies and exit node operators' policies
- **No illegal activities**: Do not use for illegal activities, abuse, or harassment
- **Respect rate limits**: Rotate IPs responsibly (minimum 10 second interval)
- **No warranty**: Use at your own risk. No liability for misuse or damages

## License
MIT License - See LICENSE file for details.

## References (Thanks to :)
- [Tor Project](https://www.torproject.org/)
- [Stem Library](https://stem.torproject.org/)
- [Tornet Repository](https://github.com/ayadseghairi/tornet)
