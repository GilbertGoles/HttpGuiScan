import logging

logger = logging.getLogger("network_scanner.reporter")


def generate_html_report(scan_data: dict, target_subnet: str) -> str:
    """Генерирует HTML файл отчета с логированием процесса сборки."""
    logger.info(f"Старт генерации автономного HTML-отчета для подсети: {target_subnet}")

    summary = scan_data.get("summary", {})
    hosts = scan_data.get("hosts", [])

    try:
        cards_html = f"""
        <div class="cards">
            <div class="card card-total"><div class="card-num">{summary.get('total', 0)}</div><div class="card-label">Всего хостов</div></div>
            <div class="card card-linux"><div class="card-num">{summary.get('linux', 0)}</div><div class="card-label">Linux/Unix</div></div>
            <div class="card card-windows"><div class="card-num">{summary.get('windows', 0)}</div><div class="card-label">Windows</div></div>
            <div class="card card-printer"><div class="card-num">{summary.get('printer', 0)}</div><div class="card-label">Printers</div></div>
            <div class="card card-other"><div class="card-num">{summary.get('other', 0)}</div><div class="card-label">Other</div></div>
        </div>
        """

        table_rows = ""
        for host in hosts:
            ports_badges = "".join([f'<span class="port port-ok">{p["port"]}/{p["name"]}</span>' for p in host["ports"]])
            table_rows += f"""
            <tr class="row">
                <td class="col-ip">🟢 {host['ip']}</td>
                <td class="col-mac">{host['mac']}</td>
                <td>{host['vendor']}</td>
                <td class="col-os">{host['os']}</td>
                <td class="col-ports">{ports_badges if ports_badges else '<span style="color:var(--muted)">Нет портов</span>'}</td>
            </tr>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Инвентаризация сети — {target_subnet}</title>
<style>
  :root {{
    --bg: #0f1115; --panel: #171a21; --panel-2: #1f232c; --border: #2a2f3a;
    --text: #e6e9ef; --muted: #9aa3b2; --accent: #4f8cff;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text); font-family: sans-serif; font-size: 14px; }}
  header {{ padding: 20px 24px; background: var(--panel); border-bottom: 1px solid var(--border); }}
  h1 {{ margin: 0 0 6px; font-size: 20px; }}
  main {{ padding: 20px 24px; max-width: 1600px; margin: 0 auto; }}
  .cards {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; min-width: 140px; flex: 1; }}
  .card-num {{ font-size: 22px; font-weight: 600; }}
  .card-label {{ color: var(--muted); font-size: 12px; margin-top: 2px; }}
  .card-total .card-num {{ color: var(--accent); }}
  .card-windows .card-num {{ color: #60a5fa; }}
  .card-linux .card-num {{ color: #34d399; }}
  .card-printer .card-num {{ color: #fbbf24; }}
  table.main {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  table.main thead th {{ text-align: left; padding: 10px 12px; background: var(--panel-2); color: var(--muted); border-bottom: 1px solid var(--border); }}
  table.main tbody td {{ padding: 9px 12px; border-bottom: 1px solid var(--border); }}
  .port {{ display: inline-block; padding: 1px 6px; margin: 1px 2px; border-radius: 4px; font-size: 11px; background: #2a2f3a; color: #cbd5e1; }}
</style>
</head>
<body>
<header>
  <h1>🖧 Результаты сканирования сети <code>{target_subnet}</code></h1>
</header>
<main>
  {cards_html}
  <table class="main">
    <thead>
      <tr><th>IP адрес</th><th>MAC адрес</th><th>Вендор</th><th>Операционная система</th><th>Открытые порты</th></tr>
    </thead>
    <tbody>
      {table_rows}
    </tbody>
  </table>
</main>
</body>
</html>
"""
        logger.info("HTML-отчет успешно скомпилирован.")
        return html_template
    except Exception as e:
        logger.error(f"Ошибка при сборке HTML-отчета: {e}", exc_info=True)
        raise e
