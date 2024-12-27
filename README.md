jq -r '.[] | select(.vulnerability_name == "Example Vulnerability") | .ip' zafiyetler.json -->istediğin zafiyete sahip tüm ipleri çekme
