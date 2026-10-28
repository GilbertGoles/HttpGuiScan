import logging
import nmap

# Настройка локального логгера для модуля сканера
logger = logging.getLogger("network_scanner.scanner")


class NetworkScanner:

    def __init__(self):
        logger.info("Инициализация модуля NetworkScanner...")
        try:
            self.nm = nmap.PortScanner()
            logger.info("Утилита Nmap успешно обнаружена в системе.")
        except Exception as e:
            logger.critical(f"Не удалось инициализировать Nmap! Проверьте, установлен ли nmap в системе. Ошибка: {e}")
            raise e

    def scan(self, target: str, mode: str) -> dict:
        """Выполняет сканирование подсети с логированием каждого шага."""
        scan_presets = {
            "stealth": "-Pn -sS -T2 --open",
            "fast": "-Pn -F -T4",
            "aggressive": "-A -T4 -v",
            "normal": "-Pn -sV -O -T3",
            "ping": "-sn",
        }

        arguments = scan_presets.get(mode, scan_presets["normal"])
        logger.info(f"Запуск сканирования цели: '{target}' | Режим: '{mode}' | Аргументы Nmap: '{arguments}'")

        try:
            self.nm.scan(hosts=target, arguments=arguments)
            logger.info(f"Nmap успешно завершил сканирование цели {target}.")
        except Exception as e:
            logger.error(f"Критическая ошибка Nmap при сканировании {target}: {str(e)}", exc_info=True)
            return {"error": f"Ошибка выполнения Nmap: {str(e)}"}

        hosts_data = []
        all_found_hosts = self.nm.all_hosts()
        logger.info(f"Обнаружено хостов для обработки: {len(all_found_hosts)}")

        for host in all_found_hosts:
            mac_addr = self.nm[host].get("addresses", {}).get("mac", "Не определен")
            vendor = self.nm[host].get("vendor", {}).get(mac_addr, "Unknown")
            state = self.nm[host].state()

            host_info = {"ip": host, "mac": mac_addr, "vendor": vendor, "status": state, "os": "Unknown", "ports": []}

            # Определение ОС
            if "osmatch" in self.nm[host] and self.nm[host]["osmatch"]:
                host_info["os"] = self.nm[host]["osmatch"]["name"]

            # Извлечение портов
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    p_info = self.nm[host][proto][port]
                    host_info["ports"].append(
                        {
                            "port": port,
                            "state": p_info["state"],
                            "name": p_info["name"],
                            "product": p_info.get("product", ""),
                            "version": p_info.get("version", ""),
                        }
                    )

            logger.info(f"Обработан хост: IP={host} | OS={host_info['os']} | Открытых портов={len(host_info['ports'])}")
            hosts_data.append(host_info)

        summary = self.generate_summary(hosts_data)
        logger.info(f"Сканирование обработано успешно. Сводка: {summary}")
        return {"hosts": hosts_data, "summary": summary}

    def generate_summary(self, hosts: list) -> dict:
        summary = {"total": len(hosts), "windows": 0, "linux": 0, "printer": 0, "other": 0}
        for h in hosts:
            os_lower = h["os"].lower()
            if "windows" in os_lower:
                summary["windows"] += 1
            elif "linux" in os_lower or "ubuntu" in os_lower:
                summary["linux"] += 1
            elif "print" in os_lower or "hp" in os_lower:
                summary["printer"] += 1
            else:
                summary["other"] += 1
        return summary
