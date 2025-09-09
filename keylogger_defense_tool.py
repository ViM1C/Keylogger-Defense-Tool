import psutil

def detect_suspicious_processes():
    suspicious_keywords = ["keylogger", "logger", "keyboard"]
    flagged = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            pname = proc.info['name'] or ""
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

            # Simple heuristic check
            if any(keyword.lower() in pname.lower() for keyword in suspicious_keywords) \
               or any(keyword.lower() in cmdline.lower() for keyword in suspicious_keywords):
                flagged.append((proc.info['pid'], pname, cmdline))

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return flagged


if __name__ == "__main__":
    results = detect_suspicious_processes()
    if results:
        print("[!] Suspicious processes found (possible keyloggers):")
        for pid, name, cmd in results:
            print(f"  PID: {pid} | Name: {name} | Command: {cmd}")
    else:
        print("[+] No suspicious processes detected.")
