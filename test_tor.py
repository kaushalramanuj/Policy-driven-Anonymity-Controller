import requests

# Configure Tor proxy
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

print("Testing Tor connection...")

try:
    # Test 1: Get your IP through Tor
    response = requests.get(
        'http://httpbin.org/ip',
        proxies=proxies,
        timeout=30
    )
    
    print("\n✅ SUCCESS! Connected through Tor!")
    print(f"Your Tor IP address: {response.json()['origin']}")
    print("\nThis should be different from your real IP!")
    
    # Test 2: Verify it's actually Tor
    response2 = requests.get(
        'https://check.torproject.org',
        proxies=proxies,
        timeout=30
    )
    
    if 'Congratulations' in response2.text:
        print("\n✅ Confirmed: You are using Tor network!")
    else:
        print("\n⚠️ Warning: May not be using Tor")
        
except Exception as e:
    print(f"\n❌ ERROR: {str(e)}")
    print("\nPossible issues:")
    print("1. Tor Browser is not running")
    print("2. Port 9050 is blocked")
    print("3. PySocks not installed")
