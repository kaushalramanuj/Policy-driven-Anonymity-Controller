import csv
import re
from urllib.parse import urlparse

def extract_domain(url):
    """Extract domain from full URL"""
    try:
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove www.
        domain = domain.replace('www.', '')
        
        return domain
    except:
        return None

def process_csv_file(input_file, output_file, limit=100):
    """
    Read CSV of malicious URLs and extract domains
    
    Args:
        input_file: Path to downloaded CSV file
        output_file: Path to save domain list
        limit: Max number of domains to extract (default 100)
    """
    malicious_domains = set()  # Use set to avoid duplicates
    
    with open(input_file, 'r', encoding='utf-8') as csvfile:
        # Skip header line
        next(csvfile)
        
        reader = csv.reader(csvfile)
        
        for row in reader:
            if len(malicious_domains) >= limit:
                break
                
            try:
                # URLhaus CSV: URL is in column 2 (index 2)
                url = row[2]
                domain = extract_domain(url)
                
                if domain and len(domain) > 4:  # Valid domain
                    malicious_domains.add(domain)
                    
            except Exception as e:
                continue  # Skip problematic rows
    
    # Save to text file
    with open(output_file, 'w') as f:
        for domain in sorted(malicious_domains):
            f.write(domain + '\n')
    
    print(f"✅ Extracted {len(malicious_domains)} unique domains")
    print(f"✅ Saved to: {output_file}")
    
    return list(malicious_domains)

# Run the script
if __name__ == "__main__":
    # Download the CSV first from:
    # https://urlhaus.abuse.ch/downloads/csv_recent/
    
    input_csv = "csv_recent.csv"  # Downloaded file
    output_txt = "malicious_domains.txt"
    
    domains = process_csv_file(input_csv, output_txt, limit=200)
    
    # Print first 10 as preview
    print("\n📋 First 10 domains:")
    for domain in domains[:10]:
        print(f"  - {domain}")
