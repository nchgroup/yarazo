# yarazo

Script for testing backdoors with yara rules

## Usage

```bash
$ python3 yarazo.py <binary>
```

## Install

```bash
bash install.sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Testing

test.bin is a metasploit shellcode windows/x64/shell_reverse_tcp
