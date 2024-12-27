def parse_nessus(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    vulnerabilities = defaultdict(lambda: {"ip_ports": defaultdict(list), "cvss_scores": [], "risk_levels": []})
    json_vulnerabilities = []

    for report in root.findall('.//Report'):
        for host in report.findall('.//ReportHost'):
            hostname = host.get('name', 'N/A')

            for item in host.findall('.//ReportItem'):
                cvss_base_score = float(item.findtext('cvss_base_score', '0.0'))
                vulnerability_name = item.get('pluginName', 'N/A')
                ip_address = hostname
                port = item.get('port', 'N/A')
                risk_level = get_risk_level(cvss_base_score)

                # Informational risk seviyesini atla
                if risk_level == 'Informational':
                    continue

                vulnerabilities[vulnerability_name]["ip_ports"][ip_address].append(port)
                vulnerabilities[vulnerability_name]["cvss_scores"].append(cvss_base_score)
                vulnerabilities[vulnerability_name]["risk_levels"].append(risk_level)

                json_vulnerabilities.append({
                    "vulnerability_name": vulnerability_name,
                    "ip": ip_address,
                    "ports": port
                })

    return vulnerabilities, json_vulnerabilities
