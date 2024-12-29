<h1>Hello</h1>

This tool can be used parse nessus files to json or excel files 

python3 parsethemallv2.0.py -f /path --format=csv,xls 







jq -r '.[] | select(.vulnerability_name == "Example Vulnerability") | .ip' zafiyetler.json  You can use json methods for hook vuln IP Adresses
