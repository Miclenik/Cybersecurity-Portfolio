# ThreatLens

A command-line IOC and threat intelligence analysis tool using the VirusTotal API. Supports hashes, IPs, domains, batch processing, caching, and JSON export.

## Features

- Hash, IP, and domain analysis
- File history and network indicators
- Threat classification (family, category, labels)
- IP geolocation and ASN data
- Domain WHOIS and registration info
- Batch processing from text files
- Local caching system
- JSON export
- Color-coded terminal output

## Installation

```bash
git clone https://github.com/yourusername/ThreatLens.git
cd ThreatLens
pip install -r requirements.txt
```

Create an `apikeys.env` file:

```env
VT_API_KEY=your_api_key_here
HYBRID_API_KEY=your_api_key_here
URLHAUS_API_KEY=your_api_key_here
GROQ_API_KEY=your_api_key_here
GEMINI_API_KEY=your_api_key_here
```

## Usage

### Single IOC Analysis

```bash
python main.py --hash 44d88612fea8a8f36de82e1278abb02f
python main.py --ip 8.8.8.8
python main.py --domain google.com
python main.py --hash abc123 --json output.json
```

### Batch Processing

Create `hashes.txt` with one hash per line, then run:

```bash
python main.py --batch hashes.txt
python main.py --batch hashes.txt --json my_results/
```

## Command Reference

| Command | Description |
|---------|-------------|
| `--hash <hash>` | Analyze file hash |
| `--ip <ip>` | Analyze IP address |
| `--domain <domain>` | Analyze domain |
| `--json <file>` | Save results to JSON |
| `--batch <file>` | Batch process hashes |

## Notes

- Cache is stored locally until manually deleted
- Supports VirusTotal enrichment and relationship analysis
- Intended for educational and authorized security research purposes only

## License

MIT
