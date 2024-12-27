import sys
import os
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import xlsxwriter
import csv
import argparse

def get_risk_level(cvss_score):
    if cvss_score >= 9.0:
        return 'Critical'
    elif 7.0 <= cvss_score < 9.0:
        return 'High'
    elif 4.0 <= cvss_score < 7.0:
        return 'Medium'
    elif 0.1 <= cvss_score < 4.0:
        return 'Low'
    else:
        return 'Informational'

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

                vulnerabilities[vulnerability_name]["ip_ports"][ip_address].append(port)
                vulnerabilities[vulnerability_name]["cvss_scores"].append(cvss_base_score)
                vulnerabilities[vulnerability_name]["risk_levels"].append(risk_level)

                json_vulnerabilities.append({
                    "vulnerability_name": vulnerability_name,
                    "ip": ip_address,
                    "ports": port
                })

    return vulnerabilities, json_vulnerabilities

def export_to_excel(parsed_data):
    workbook = xlsxwriter.Workbook('Nessus_Rapor.xlsx')
    worksheet = workbook.add_worksheet()

    bold_format = workbook.add_format({'bold': True})
    headers = ['Zafiyet Adı', 'IP ve Portlar', 'Ortalama CVSS Skoru', 'Kritiklik Seviyesi']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header, bold_format)

    row = 1
    for vulnerability_name, data in parsed_data.items():
        ip_ports = ', '.join([f"{ip} ({', '.join(ports)})" for ip, ports in data["ip_ports"].items()])
        average_cvss_score = sum(data["cvss_scores"]) / len(data["cvss_scores"])
        risk_level = get_risk_level(average_cvss_score)

        worksheet.write(row, 0, vulnerability_name)
        worksheet.write(row, 1, ip_ports)
        worksheet.write(row, 2, average_cvss_score)
        worksheet.write(row, 3, risk_level)
        row += 1

    workbook.close()
    print("Excel dosyası başarıyla oluşturuldu: Nessus_Rapor.xlsx")

def export_to_csv(parsed_data):
    with open('Nessus_Rapor.csv', 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        headers = ['Zafiyet Adı', 'IP ve Portlar', 'Ortalama CVSS Skoru', 'Kritiklik Seviyesi']
        writer.writerow(headers)

        for vulnerability_name, data in parsed_data.items():
            ip_ports = ', '.join([f"{ip} ({', '.join(ports)})" for ip, ports in data["ip_ports"].items()])
            average_cvss_score = sum(data["cvss_scores"]) / len(data["cvss_scores"])
            risk_level = get_risk_level(average_cvss_score)

            writer.writerow([vulnerability_name, ip_ports, average_cvss_score, risk_level])

    print("CSV dosyası başarıyla oluşturuldu: Nessus_Rapor.csv")

def export_to_json(json_data):
    with open('zafiyetler.json', 'w') as json_file:
        json.dump(json_data, json_file, indent=4)
    print("JSON dosyası başarıyla oluşturuldu: zafiyetler.json")

def main():
    parser = argparse.ArgumentParser(description="Nessus dosyalarını analiz edip çıktılar üretir.")
    parser.add_argument("directory", help="Nessus dosyalarının bulunduğu dizin yolu")
    parser.add_argument("--format", choices=["xlsx", "csv"], default="xlsx", help="Çıktı formatı (xlsx veya csv)")
    args = parser.parse_args()

    directory_path = args.directory
    if not os.path.isdir(directory_path):
        print(f"{directory_path} dizini bulunamadı.")
        sys.exit(1)

    all_vulnerabilities = defaultdict(lambda: {"ip_ports": defaultdict(list), "cvss_scores": [], "risk_levels": []})
    all_json_vulnerabilities = []

    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path) and file_name.endswith('.nessus'):
            parsed_data, json_vulnerabilities = parse_nessus(file_path)
            for vulnerability_name, data in parsed_data.items():
                for ip, ports in data["ip_ports"].items():
                    all_vulnerabilities[vulnerability_name]["ip_ports"][ip].extend(ports)
                all_vulnerabilities[vulnerability_name]["cvss_scores"].extend(data["cvss_scores"])
                all_vulnerabilities[vulnerability_name]["risk_levels"].extend(data["risk_levels"])

            all_json_vulnerabilities.extend(json_vulnerabilities)

    if args.format == "xlsx":
        export_to_excel(all_vulnerabilities)
    elif args.format == "csv":
        export_to_csv(all_vulnerabilities)

    export_to_json(all_json_vulnerabilities)

if __name__ == '__main__':
    main()
