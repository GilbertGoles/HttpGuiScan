import logging
import asyncio
import xml.etree.ElementTree as ET

logger = logging.getLogger("network_scanner.scanner")

class NetworkScanner:
    async def scan_async(self, target: str, mode: str) -> dict:
        # Высокоскоростные пресеты
        scan_presets = {
            "stealth": ["-Pn", "-sS", "-T4", "--open", "--min-rate", "1000", "-F"],
            "fast": ["-Pn", "-F", "-T4", "--min-rate", "1000"],
            "aggressive": ["-Pn", "-sV", "-O", "-T4", "--max-retries", "1", "--min-rate", "1000"],
            "normal": ["-Pn", "-sV", "-T4", "--max-retries", "1", "--min-rate", "1000"],
            "ping": ["-sn", "--min-rate", "1000"]
        }
        
        args = scan_presets.get(mode, scan_presets["normal"])
        
        # ИСПРАВЛЕНО: Убираем "sudo" из массива. Процесс унаследует root от main.py автоматически.
        full_args = ["nmap", "-oX", "-"] + args + [target]
        
        logger.info(f"Запуск процесса: {' '.join(full_args)}")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", *full_args[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout_chunks = []
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                stdout_chunks.append(line)
                
            stderr_data = await proc.stderr.read()
            await proc.wait()
            
            full_stdout = b"".join(stdout_chunks).decode('utf-8', errors='ignore')
            err_msg = stderr_data.decode('utf-8', errors='ignore').strip()
            
            if proc.returncode != 0:
                logger.error(f"Nmap завершился с кодом {proc.returncode}. Ошибка: {err_msg}")
                if not err_msg:
                    err_msg = f"Процесс завершился с кодом {proc.returncode} (сбой сигналов системы или прав)"
                return {"error": f"Nmap error: {err_msg}"}
                
            return self.parse_xml_output(full_stdout)
            
        except Exception as e:
            logger.error(f"Ошибка выполнения подпроцесса Nmap: {e}", exc_info=True)
            return {"error": str(e)}

    def parse_xml_output(self, xml_data: str) -> dict:
        hosts_data = []
        try:
            if not xml_data.strip() or "</nmaprun>" not in xml_data:
                logger.error("Получен неполный или пустой XML от Nmap.")
                return {"error": "Получены некорректные или пустые данные от Nmap."}

            root = ET.fromstring(xml_data)
            for host_node in root.findall("host"):
                status_node = host_node.find("status")
                if status_node is not None and status_node.get("state") != "up":
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
                
            return {"hosts": hosts_data, "summary": self.generate_summary(hosts_data)}
        except Exception as e:
            logger.error(f"Ошибка разбора XML-структуры: {e}")
            return {"error": f"XML parse error: {e}"}

    def generate_summary(self, hosts: list) -> dict:
        summary = {"total": len(hosts), "windows": 0, "linux": 0, "printer": 0, "other": 0}
        for h in hosts:
            os_lower = h["os"].lower()
            if "windows" in os_lower: summary["windows"] += 1
            elif "linux" in os_lower or "ubuntu" in os_lower: summary["linux"] += 1
            else: summary["other"] += 1
        return summary
