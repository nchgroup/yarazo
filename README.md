# yarazo

Script for testing backdoors with yara rules

## Usage

```bash
$ python3 yarazo.py <binary>
```

## Update Yara rules

```bash
bash update.sh
```

## Install

```bash
sudo apt install git -y
bash install.sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Testing

shell_reverse_tcp.bin is a metasploit shellcode windows/x64/shell_reverse_tcp
