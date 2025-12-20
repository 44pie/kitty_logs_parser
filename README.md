# Kitty Logs Parser

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠒⠦⣄⣠⠶⠞⠳⣆⠀⠀⠀⠀
⠀⠀⠀⣴⠛⠛⠛⠲⢦⣤⡴⠶⠶⢶⠏⠀⢀⣄⣹⣇⡀⠀⠀⣻⡀⠀⠀⠀
⠀⠀⠀⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠂⠀⢿⣼⠋⠀⠉⣿⣍⠉⠉⡆⠀⠀
⠀⠀⠀⢿⡤⠀⠀⠀⠀⠀⠀⠀⠀⠈⠧⠤⠤⠿⢦⣀⣤⠿⠼⠀⣰⠃⠀⠀
⠀⠀⠀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⠤⠶⢿⡀⠀⠀
⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣼⡧⠤⠆
⣠⣤⢼⡧⢤⠀⠀⠀⢠⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⡇⠀⠀⠀⣤⣧⣄⡀
⠀⠀⢀⡿⠉⠹⡄⠀⠈⠋⠀⠀⠀⣴⠒⡆⠀⠀⠀⠀⠀⠀⠀⣀⣼⠁⠀⠀
⢠⡞⠉⠛⠀⠀⠹⠶⠶⣄⠀⠀⠀⠈⠉⠀⠀⠀⠀⠀⠀⠀⣀⠾⠉⠙⠒⠀
⠀⠳⢤⣀⠀⠀⢠⠖⠒⠈⢳⣀⠀⠀⢀⣀⣀⣀⣤⠤⠖⠛⠁⠀⠀⠀⠀⠀
⠀⠀⠀⢹⡀⠀⠘⠲⠖⠃⣼⠋⠉⠁⠉⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠛⠦⣤⣤⠴⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

A powerful Python CLI tool for parsing and analyzing InfoStealer logs (Redline, Raccoon, Vidar, Mars, etc.).

## Features

- Multi-threaded log parsing (20+ threads)
- Support for various stealer log formats
- Real-time progress bar with statistics
- Domain filtering to exclude major corporations
- Search filtering across all data
- Country-based filtering
- Multiple export formats (TXT, CSV)
- Pink-themed ASCII art banner

## Installation

```bash
pip install -r requirements.txt
```

Or simply run (no external dependencies required):
```bash
python kitty_lp.py -h
```

## Usage

### Basic Usage

```bash
python kitty_lp.py -i ./logs -o ./results -d
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `-i, --input` | Input directory with logs (required) |
| `-o, --output` | Output directory for results (default: ./output) |
| `-d, --domains` | Export unique second-level domains |
| `-p, --passwords` | Export unique passwords |
| `-e, --emails` | Export unique emails |
| `-ep` | Export email:password pairs |
| `-l, --logins` | Export unique logins |
| `-lp` | Export login:password pairs |
| `-s, --search` | Filter by keyword (affects all exports) |
| `-f, --filter` | Filter domains using file (default: filter.txt) |
| `-c, --country` | Filter by countries (comma-separated) or show available |
| `-a, --all` | Export all data types |
| `--csv` | Export to CSV table |
| `-w, --workers` | Number of threads (default: 20) |

### Examples

Export all unique domains:
```bash
python kitty_lp.py -i ./logs -o ./results -d
```

Export domains with filter (exclude major sites):
```bash
python kitty_lp.py -i ./logs -o ./results -d -f
```

Filter by countries:
```bash
python kitty_lp.py -i ./logs -o ./results -c RU,UA,BY -a
```

Search by keyword:
```bash
python kitty_lp.py -i ./logs -o ./results -s "paypal" -d -ep
```

Export everything + CSV:
```bash
python kitty_lp.py -i ./logs -o ./results -a --csv
```

Show available countries:
```bash
python kitty_lp.py -i ./logs -o ./results -c
```

## Domain Filter

The `-f` flag uses `filter.txt` to exclude domains from results. The filter contains 800+ domains including:

- Social media (Google, Facebook, Instagram, Twitter, TikTok...)
- Marketplaces (Amazon, eBay, AliExpress, Walmart...)
- Banks & Payment (PayPal, Chase, Bank of America...)
- Streaming (Netflix, Spotify, YouTube...)
- Gaming (Steam, Epic Games, PlayStation...)
- VPN & Security (NordVPN, ExpressVPN, Avast...)
- Crypto exchanges (Binance, Coinbase, Kraken...)
- ISP & Telecom providers
- Adult sites
- File sharing & Torrents
- CDN & Infrastructure

Use `-f` without argument to use default `filter.txt`, or specify custom file:
```bash
python kitty_lp.py -i ./logs -o ./results -d -f          # uses filter.txt
python kitty_lp.py -i ./logs -o ./results -d -f my.txt   # uses my.txt
```

## Output Files

| File | Description |
|------|-------------|
| `domains.txt` | Unique second-level domains |
| `passwords.txt` | Unique passwords |
| `emails.txt` | Unique email addresses |
| `email_pass.txt` | Email:password pairs |
| `logins.txt` | Unique login usernames |
| `login_pass.txt` | Login:password pairs |
| `search_*.txt` | Detailed search results |
| `data.csv` | Full CSV export |

When using `-s` filter, files are suffixed with search term (e.g., `domains_paypal.txt`).

## Log Format Support

The parser supports various InfoStealer log formats:
- Redline Stealer
- Raccoon Stealer
- Vidar Stealer
- Mars Stealer
- And other similar formats

Expected folder structure:
```
logs/
├── 123456_US_192.168.1.1_25-12-24/
│   ├── Passwords.txt
│   ├── Cookies/
│   └── System.txt
├── 123457_RU_10.0.0.1_25-12-24/
│   └── ...
```

## License

MIT License

## Disclaimer

This tool is intended for security research and authorized penetration testing only. The author is not responsible for any misuse of this software.
