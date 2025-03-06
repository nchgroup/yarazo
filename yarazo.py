import yara
import os
import sys
import signal
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

executor = None


def shutdown():
    global executor
    print("[!] Shutting down...")
    if executor:
        executor.shutdown(wait=False, cancel_futures=True)
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)


def check_file(file_path, rule_path):
    """Scan a file with a specific YARA rule"""
    try:
        rules = yara.compile(filepath=str(rule_path))
        matches = rules.match(file_path)

        if matches:
            return (
                f"+ {rule_path.name} --> {', '.join(str(match) for match in matches)}"
            )
        return None
    except yara.Error:
        return None
    except Exception:
        return None


def main():
    global executor
    if len(sys.argv) < 2:
        print("[-] Error: Please provide an executable file as an argument.")
        sys.exit(1)

    executable = sys.argv[1]
    if not os.path.isfile(executable):
        print(f"[-] Error: {executable} is not a valid file.")
        sys.exit(1)

    rules_dir = Path.cwd() / "yara-rules"

    yara_files = list(rules_dir.glob("**/*.yar"))
    if not yara_files:
        print(
            "[-] Error: No YARA rules found in yara-rules directory. Please run 'bash install.sh'"
        )
        sys.exit(1)

    found_match = False  # Bandera para detectar si se imprime algo

    with ThreadPoolExecutor(max_workers=4) as executor_instance:
        executor = executor_instance

        future_to_rule = {
            executor.submit(check_file, executable, rule): rule for rule in yara_files
        }

        for future in future_to_rule:
            result = future.result()
            if result:
                print(result)
                found_match = True  # Se imprimió al menos una coincidencia

    sys.exit(1 if found_match else 0)  # Estado de salida según si hubo impresión


if __name__ == "__main__":
    main()
