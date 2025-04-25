#!/bin/bash

ABUSEIPDB_API_KEY="Insert Your AbuseIPDB API Key Here"
VIRUSTOTAL_API_KEY="Insert Your VirusTotal API Key Here"

check_abuseipdb() {
    local ip=$1
    response=$(curl -sG https://api.abuseipdb.com/api/v2/check \
        --data-urlencode "ipAddress=${ip}" \
        -d maxAgeInDays=90 \
        -d verbose \
        -H "Key: ${ABUSEIPDB_API_KEY}" \
        -H "Accept: application/json")

    confidence_score=$(echo "$response" | jq -r '.data.abuseConfidenceScore')
    usage_type=$(echo "$response" | jq -r '.data.usageType')
    country=$(echo "$response" | jq -r '.data.countryCode')
    last_reported=$(echo "$response" | jq -r '.data.lastReportedAt')

    if [[ "$last_reported" == "null" ]]; then
        last_reported="Never"
    else
        last_reported=$(date -d "$last_reported" +"%b %d, %Y %H:%M UTC" 2>/dev/null || echo "$last_reported")
    fi

    echo "AbuseIPDB - IP: $ip | Confidence Score: $confidence_score | Country: $country | Usage Type: $usage_type | Last Reported: $last_reported"
}

check_virustotal() {
    local ip=$1
    response=$(curl -s -X GET "https://www.virustotal.com/api/v3/ip_addresses/${ip}" \
        -H "x-apikey: ${VIRUSTOTAL_API_KEY}")

    positives=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious')
    vendor_names=$(echo "$response" | jq -r '.data.attributes.last_analysis_results | to_entries[] | select(.value.category == "malicious") | .key' | paste -sd ", " -)
    
    echo "VirusTotal - IP: $ip | Malicious Reports: $positives | Vendors: $vendor_names"
}

check_ip() {
    local ip=$1
    echo "Checking IP: $ip"
    check_abuseipdb "$ip"
    check_virustotal "$ip"
    echo "----------------------------------------"
}

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <IP or file.txt>"
    exit 1
fi

if [[ -f $1 ]]; then
    while IFS= read -r ip; do
        check_ip "$ip"
    done < "$1"
else
    check_ip "$1"
fi
