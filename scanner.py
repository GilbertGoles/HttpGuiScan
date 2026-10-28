import logging
import nmap

logger = logging.getLogger("network_scanner.scanner")

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target: str, mode: str) -> dict:
        # Скоростные пресеты с лимитом повторов пакетов для неблокирующей работы
        scan_presets = {
            "stealth": "-Pn -sS -T4 --open --min-rate 1000",
            "fast": "-Pn -F -T4 --min-rate 1000",
            "aggressive": "-A -T4 --max-retries 1 --min-rate 500",
            "normal": "-Pn -sV --version-light -O -T4 --max-retries 1",
            "ping": "-sn --min-rate 1000"
        }
        arguments = scan_presets.get(mode, scan_presets["normal"])
        logger.info(f"Запуск Nmap: '{target}' | Режим: '{mode}' | Опции: '{arguments}'")
        
        try:
            self.nm.scan(hosts=target, arguments=arguments)
        except Exception as e:
            logger.error(f"Ошибка Nmap: {e}")
            return {"error": str(e)}

        hosts_data = []
        for host in self.nm.all_hosts():
            mac = self.nm[host].get("addresses", {}).get("mac", "Не определен")
            host_info = {
                "ip": host, "mac": mac, 
                "vendor": self.nm[host].get("vendor", {}).get(mac, "Unknown"),
                "status": self.nm[host].state(), "os": "Unknown", "ports": []
            }
            if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
                host_info["os"] = self.nm[host]["osmatch"][0]["name"]
            
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    p_info = self.nm[host][proto][port]
                    host_info["ports"].append({"port": port, "state": p_info["state"], "name": p_info["name"]})
            hosts_data.append(host_info)

        return {"hosts": hosts_data, "summary": self.generate_summary(hosts_data)}

    def generate_summary(self, hosts: list) -> dict:
        summary = {"total": len(hosts), "windows": 0, "linux": 0, "printer": 0, "other": 0}
        for h in hosts:
            os_lower = h["os"].lower()
            if "windows" in os_lower: summary["windows"] += 1
            elif "linux" in os_lower or "ubuntu" in os_lower: summary["linux"] += 1
            else: summary["other"] += 1
        return summary
