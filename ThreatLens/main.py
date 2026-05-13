import argparse
import requests
import time
import json
import os
from datetime import datetime
from config import VT_API_KEY


# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# Create output directory if it doesn't exist
def process_batch(filepath, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Read hashes from file
    with open(filepath, 'r') as f:
        hashes = [line.strip() for line in f if line.strip()]
    
    total = len(hashes)
    print(f"Found {total} hashes to analyze")
    
    results = []
    for i, hash_value in enumerate(hashes, 1):
        print(f"\n[{i}/{total}] Analyzing: {hash_value[:16]}...")
        
        result = check_virustotal("files", hash_value)
        
        if result:
            # Save individual JSON file
            json_file = os.path.join(output_dir, f"{hash_value}.json")
            save_to_json(result, json_file)
            results.append({"hash": hash_value, "status": "success"})
        else:
            results.append({"hash": hash_value, "status": "failed"})
    
    # Print summary
    print("\n" + "="*50)
    print("BATCH SUMMARY")
    print("="*50)
    successful = sum(1 for r in results if r["status"] == "success")
    print(f"{Colors.GREEN}Successful: {successful}/{total}{Colors.RESET}")
    print(f"{Colors.RED}Failed: {total - successful}/{total}{Colors.RESET}")
    
    # Save summary to JSON
    summary_file = os.path.join(output_dir, "batch_summary.json")
    save_to_json(results, summary_file)


def save_to_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Results saved to {filename}")


#cache results to avoid redundant API calls

def get_cache_key(endpoint, value):
    """Create a unique key for caching"""
    return f"{endpoint}_{value}"

def load_from_cache(cache_key):
    """Load cached result if it exists and is less than 7 days old"""
    cache_file = f"cache/{cache_key}.json"
    if os.path.exists(cache_file):
        # Check if cache is less than 7 days old (604800 seconds)
        if time.time() - os.path.getmtime(cache_file) < 604800:
            with open(cache_file, 'r') as f:
                return json.load(f)
    return None

def save_to_cache(cache_key, data):
    """Save result to cache"""
    if not os.path.exists("cache"):
        os.makedirs("cache")
    cache_file = f"cache/{cache_key}.json"
    with open(cache_file, 'w') as f:
        json.dump(data, f)



#command line argument parsing

def get_args():
    parser = argparse.ArgumentParser(description="IOC Analysis Tool")
    parser.add_argument("--ip", help="IP address to analyze")
    parser.add_argument("--domain", help="Domain to analyze")
    parser.add_argument("--hash", help="File hash to analyze")
    parser.add_argument("--json", help="Save results to JSON file")
    parser.add_argument("--csv", help="Save results to CSV file")
    parser.add_argument("--batch", help="Text file with hashes (one per line)")
    return parser.parse_args()

#VirusTotal API interaction

def check_virustotal(endpoint, value):
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{value}"
    cache_key = get_cache_key(endpoint, value)
    cached_result = load_from_cache(cache_key)
    if cached_result:
        print("(from cache)")
        return cached_result
    
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    # Initialize result as None
    result = None  # ← ADD THIS LINE
    
    if response.status_code == 200:
        data = response.json()
        attributes = data["data"]["attributes"]
        
        result = {
            "hash": value,
            "stats": attributes.get("last_analysis_stats", {}),
            "first_submission": attributes.get("first_submission_date"),
            "last_submission": attributes.get("last_submission_date"),
            "first_submission_readable": datetime.fromtimestamp(attributes.get("first_submission_date")).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("first_submission_date") else None,
            "times_submitted": attributes.get("times_submitted"),
            "type_tag": attributes.get("type_tag"),
            "tags": attributes.get("tags", []),
            "contacted_domains": [],
            "contacted_ips": [],
            "threat_classification": None
        }
        
        # IP and domain specific fields
        if endpoint == "ip_addresses":
            result["country"] = attributes.get("country")
            result["continent"] = attributes.get("continent")
            result["as_owner"] = attributes.get("as_owner")
            result["asn"] = attributes.get("asn")
            result["reputation"] = attributes.get("reputation")
            result["jarm"] = attributes.get("jarm")                   
            result["whois"] = attributes.get("whois")[:300] if attributes.get("whois") else None
            result["total_votes"] = attributes.get("total_votes", {})
            
        if endpoint == "domains":
            result["registrar"] = attributes.get("registrar")
            result["creation_date"] = attributes.get("creation_date")
            result["last_update_date"] = attributes.get("last_update_date")
            result["jarm"] = attributes.get("jarm")                   
            result["whois"] = attributes.get("whois")[:300] if attributes.get("whois") else None
            result["total_votes"] = attributes.get("total_votes", {})
            result["categories"] = attributes.get("categories", {})  
        
        # For files only - get additional data
        if endpoint == "files" and value:
            file_hash = value
            # Get contacted domains
            try:
                domains_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/relationships/contacted_domains"
                domains_response = requests.get(domains_url, headers=headers)
                if domains_response.status_code == 200:
                    domains_data = domains_response.json()
                    result["contacted_domains"] = []
                    for item in domains_data.get("data", []):
                        attrs = item.get("attributes", {})
                        result["contacted_domains"].append({
                            "domain": attrs.get("domain_name") or item.get("id"),
                            "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0)
                        })
            except:
                result["contacted_domains"] = []
            
            # Get contacted IPs
            try:
                ips_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/relationships/contacted_ips"
                ips_response = requests.get(ips_url, headers=headers)
                if ips_response.status_code == 200:
                    ips_data = ips_response.json()
                    result["contacted_ips"] = []
                    for item in ips_data.get("data", []):
                        attrs = item.get("attributes", {})
                        result["contacted_ips"].append({
                            "ip": item.get("id"),
                            "country": attrs.get("country"),
                            "as_owner": attrs.get("as_owner")
                        })
            except:
                result["contacted_ips"] = []
            
            # Get threat classification
            try:
                if "popular_threat_classification" in attributes:
                    threat_class = attributes["popular_threat_classification"]
                    result["threat_classification"] = {
                        "popular_threat_label": threat_class.get("suggested_threat_label"),
                        "threat_categories": [cat.get("value") for cat in threat_class.get("popular_threat_category", [])],
                        "family_labels": [name.get("value") for name in threat_class.get("popular_threat_name", [])]
                    }
                else:
                    result["threat_classification"] = None
            except:
                result["threat_classification"] = None
            
            save_to_cache(cache_key, result)
    
    else:
        print("Error:", response.status_code)
    
    return result
    

#Result processing and output

def get_verdict(stats):
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    if malicious >= 5:
        return "Malicious", Colors.RED
    elif malicious > 0 or suspicious > 2:
        return "Suspicious", Colors.YELLOW
    else:
        return "Likely Clean", Colors.GREEN
    
#print results in a user-friendly format
    
def print_result(result):
    if not result:
        return
    
    stats = result.get("stats", {})
    
    print(f"\n{Colors.BOLD}--- VirusTotal Result ---{Colors.RESET}")
    
    # Color the malicious count if > 0
    malicious_count = stats.get('malicious', 0)
    if malicious_count > 0:
        print(f"Malicious: {Colors.RED}{malicious_count}{Colors.RESET}")
    else:
        print(f"Malicious: {malicious_count}")
    
    # Color suspicious count if > 0
    suspicious_count = stats.get('suspicious', 0)
    if suspicious_count > 0:
        print(f"Suspicious: {Colors.YELLOW}{suspicious_count}{Colors.RESET}")
    else:
        print(f"Suspicious: {suspicious_count}")
    
    print(f"Harmless: {stats.get('harmless', 0)}")
    
    verdict, color = get_verdict(stats)
    print(f"Verdict: {color}{verdict}{Colors.RESET}")
    
    # Print file history if available
    print(f"\n{Colors.BOLD}--- File History ---{Colors.RESET}")
    if result.get("first_submission"):
        first_sub = datetime.fromtimestamp(result["first_submission"]).strftime('%Y-%m-%d %H:%M:%S')
        print(f"\nFirst Submission: {first_sub}")
    if result.get("last_submission"):
        last_sub = datetime.fromtimestamp(result["last_submission"]).strftime('%Y-%m-%d %H:%M:%S')
        print(f"Last Submission: {last_sub}")
    if result.get("times_submitted"):
        print(f"Times Submitted: {result['times_submitted']}")
    if result.get("type_tag"):
        print(f"File Type: {result['type_tag']}")
    
    # Print contacted domains
    if result.get("contacted_domains"):
        print(f"\n{Colors.BOLD}Contacted Domains:{Colors.RESET}")
        for domain in result["contacted_domains"][:10]:
            if domain['malicious'] > 0:
                print(f"  {domain['domain']} (malicious detections: {Colors.RED}{domain['malicious']}{Colors.RESET})")
            else:
                print(f"  {domain['domain']} (malicious detections: {domain['malicious']})")
    
    if result.get("registrar") or result.get("creation_date"):
        print("\n--- Domain Registration ---")
        if result.get("registrar"):
            print(f"Registrar: {result['registrar']}")
        if result.get("creation_date"):
            creation = datetime.fromtimestamp(result["creation_date"]).strftime('%Y-%m-%d')
            print(f"Creation Date: {creation}")
    
    # Print contacted IPs
    if result.get("contacted_ips"):
        print("\nContacted IPs:")
        for ip in result["contacted_ips"][:10]:
            print(f"  {ip['ip']} - Country: {ip.get('country', 'N/A')} - AS: {ip.get('as_owner', 'N/A')}")
            
    if result.get("country") or result.get("as_owner"):
        print("\n--- IP Geolocation & Ownership ---")
        if result.get("country"):
            print(f"Country: {result['country']}")
        if result.get("continent"):
            print(f"Continent: {result['continent']}")
        if result.get("as_owner"):
            print(f"AS Owner: {result['as_owner']}")
        if result.get("asn"):
            print(f"ASN: {result['asn']}")
        if result.get("reputation"):
            print(f"VT Reputation: {result['reputation']}")
    
    # Print tags if available
    if result.get("tags"):
        print(f"\nTags: {', '.join(result['tags'][:10])}")
        
    # Print threat classification
    if result.get("threat_classification"):
        tc = result["threat_classification"]
        if tc.get("popular_threat_label") or tc.get("threat_categories") or tc.get("family_labels"):
            print("\n--- Threat Classification ---")
            if tc.get("popular_threat_label"):
                print(f"Popular Threat Label: {tc['popular_threat_label']}")
            if tc.get("threat_categories"):
                print(f"Threat Categories: {', '.join(tc['threat_categories'])}")
            if tc.get("family_labels"):
                print(f"Family Labels: {', '.join(tc['family_labels'][:5])}")
                
    # Print additional IP/domain details
    if result.get("jarm"):
        print(f"JARM Fingerprint: {result['jarm']}")
    
    if result.get("whois"):
        print(f"WHOIS: {result['whois']}")
    
    if result.get("total_votes"):
        votes = result["total_votes"]
        print(f"Community Votes: {votes.get('harmless', 0)} harmless, {votes.get('malicious', 0)} malicious")
    
    if result.get("categories"):
        print(f"Categories: {', '.join(list(result['categories'].keys())[:5])}")
                

        
    
  
#main execution logic
    
args = get_args()

#main logic to determine which IOC type is being analyzed and call the appropriate function

if args.domain:
    result = check_virustotal("domains", args.domain)
    if result:
        print_result(result)
        if args.json:
            save_to_json(result, args.json)
elif args.ip:
    result = check_virustotal("ip_addresses", args.ip)
    if result:
        print_result(result)
        if args.json:
            save_to_json(result, args.json)
elif args.hash:
    result = check_virustotal("files", args.hash)
    if result:
        print_result(result)
        if args.json:
            save_to_json(result, args.json)
elif args.batch:
    # Default output directory if not specified
    output_dir = args.json if args.json else "batch_results"
    process_batch(args.batch, output_dir)
else:
    print("Please provide an IOC to analyze (IP, domain, or hash)")