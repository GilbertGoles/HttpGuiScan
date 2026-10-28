import logging
import asyncio
import xml.etree.ElementTree as ET

logger = logging.getLogger("network_scanner.scanner")

class NetworkScanner:
    async def scan_async(self, target: str, mode: str) -> dict:
        # Высокоскоростные агрессивные и скрытные пресеты для Kali Linux
        scan_presets = {
            "stealth": ["-Pn", "-sS", "-T4", "--open", "--min-rate", "1000", "-F"],
            "fast": ["-Pn", "-F", "-T4", "--min-rate", "1000"],
            "aggressive": ["-Pn", "-sV", "-O", "-T4", "--max-retries", "1", "--min-rate", "1000"],
            "normal": ["-Pn", "-sV", "-T4", "--max-retries", "1", "--min-rate", "800"],
            "ping": ["-sn", "--min-rate", "1000"]
        }
        
        args = scan_presets.get(mode, scan_presets["normal"])
        full_args = ["-oX", "-"] + args + [target]
        
        logger.info(f"Запуск асинхронного подпроцесса Nmap: nmap {' '.join(full_args)}")
        
        try:
            # Запуск nmap как независимого асинхронного процесса
            proc = await asyncio.create_subprocess_exec(
                "nmap", *full_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                err_msg = stderr.decode('utf-8', errors='ignore')
                logger.error(f"Nmap завершился с ошибкой кода {proc.returncode}: {err_msg}")
                return {"error": f"Nmap error: {err_msg}"}
                
            return self.parse_xml_output(stdout.decode('utf-8', errors='ignore'))
            
        except Exception as e:
            logger.error(f"Ошибка вызова подпроцесса Nmap: {e}", exc_info=True)
            return {"error": str(e)}

    def parse_xml_output(self, xml_data: str) -> dict:
        """Безопасный парсинг XML-вывода Nmap без падений всего процесса"""
        hosts_data = []
        try:
            root = ET.fromstring(xml_data)
            for host_node in root.findall("host"):
                status_node = host_node.find("status")
                if status_node is封装 and status_node.get("state") != "up":
                    continue
                    
                ip_addr = "0.0.0.0"
                mac_addr = "Не определен"
                vendor = "Unknown"
                
                for addr in host_node.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip_addr = addr.get("addr")
                    elif addr.get("addrtype") == "mac":
                        mac_addr = addr.get("addr")
                        vendor = addr.get("vendor", "Unknown")
                
                os_name = "Unknown"
                os_node = host_node.find("os")
                if os_node is not None:
                    osmatch = os_node.find("osmatch")
                    if osmatch is not None:
                        os_name = osmatch.get("name", "Unknown")
                        
                ports_list = []
                ports_node = host_node.find("ports")
                if ports_node is not None:
                    for port in ports_node.findall("port"):
                        state_node = port.find("state")
                        if state_node is not None and state_node.get("state") == "open":
                            port_id = port.get("portid")
                            service_node = port.find("service")
                            service_name = service_node.get("name", "unknown") if service_node is not None else "unknown"
                            ports_list.append({"port": port_id, "state": "open", "name": service_name})
                            
                hosts_data.append({
                    "ip": ip_addr, "mac": mac_addr, "vendor": vendor,
                    "status": "up", "os": os_name, "ports": ports_list
                })
                
        except Exception as e:
            logger.error(f"Ошибка разбора XML-структуры: {e}")
            return {"error": f"XML parse error: {e}"}
            
        return {"hosts": hosts_data, "summary": self.generate_summary(hosts_data)}

    def generate_summary(self, hosts: list) -> dict:
        summary = {"total": len(hosts), "windows": 0, "linux": 0, "printer": 0, "other": 0}
        for h in hosts:
            os_lower = h["os"].lower()
            if "windows" in os_lower: summary["windows"] += 1
            elif "linux" in os_lower or "ubuntu" in os_lower: summary["linux"] += 1
            else: summary["other"] += 1
        return summary
