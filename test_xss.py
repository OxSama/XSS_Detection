import requests
import json
from urllib.parse import quote
import time

def test_xss_detection():
    BASE_URL = "http://localhost:8080"
    
    # Test payloads
    payloads = [
        # Basic XSS attacks
        "<script>alert('xss')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg onload='alert(1)'>",
        "javascript:alert(1)",
        
        # Encoded payloads
        quote("<script>alert('xss')</script>"),
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        
        # Advanced payloads
        "<div onmouseover='alert(1)'>hover me</div>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<a href='javascript:alert(1)'>click me</a>",
        
        # Obfuscated payloads
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<script>script>alert(1)<</script>/script>",
        
        # Data URI
        "data:text/html,<script>alert(1)</script>",
        
        # CSS attacks
        "<div style='background:url(javascript:alert(1))'>",
        "<div style='expression(alert(1))'>",
        
        # Valid inputs (should pass)
        "Hello, this is a normal comment!",
        "Check out this website: https://example.com",
        "<p>This is normal HTML</p>"
    ]
    
    def test_get_request(payload):
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY'
        }
        response = requests.get(
            f"{BASE_URL}/?input={payload}",
            headers=headers
        )
        return response

    def test_post_request(payload):
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {'input': payload}
        response = requests.post(
            BASE_URL,
            headers=headers,
            data=data
        )
        return response

    def check_metrics():
        response = requests.get(f"{BASE_URL}/metrics")
        return response.json()

    # Run tests
    print("Starting XSS Detection Tests...")
    print("-" * 50)

    results = {
        'blocked': 0,
        'passed': 0,
        'failed': 0
    }

    for payload in payloads:
        print(f"\nTesting payload: {payload[:50]}...")
        
        # Test GET request
        try:
            response = test_get_request(payload)
            if response.status_code == 400 and "XSS payload detected" in response.text:
                print("✅ GET: XSS detected correctly")
                results['blocked'] += 1
            elif response.status_code == 200 and any(x in payload for x in ["Hello", "normal", "https://"]):
                print("✅ GET: Valid input passed correctly")
                results['passed'] += 1
            else:
                print("❌ GET: Unexpected response")
                results['failed'] += 1
        except Exception as e:
            print(f"❌ GET: Error - {str(e)}")
            results['failed'] += 1

        # Test POST request
        try:
            response = test_post_request(payload)
            if response.status_code == 400 and "XSS payload detected" in response.text:
                print("✅ POST: XSS detected correctly")
                results['blocked'] += 1
            elif response.status_code == 200 and any(x in payload for x in ["Hello", "normal", "https://"]):
                print("✅ POST: Valid input passed correctly")
                results['passed'] += 1
            else:
                print("❌ POST: Unexpected response")
                results['failed'] += 1
        except Exception as e:
            print(f"❌ POST: Error - {str(e)}")
            results['failed'] += 1

        time.sleep(0.1)  # Prevent rate limiting

    # Check metrics
    print("\nChecking metrics...")
    try:
        metrics = check_metrics()
        print("\nMetrics Summary:")
        print(f"Total Requests: {metrics.get('total_requests', 'N/A')}")
        print(f"Blocked Requests: {metrics.get('blocked_requests', 'N/A')}")
        print("\nUnique Attackers:")
        for ip, count in metrics.get('unique_attackers', {}).items():
            print(f"  {ip}: {count} attempts")
        print("\nCommon Payloads:")
        for payload, count in metrics.get('common_payloads', {}).items():
            print(f"  {payload[:50]}... : {count} times")
    except Exception as e:
        print(f"❌ Error fetching metrics: {str(e)}")

    # Print summary
    print("\nTest Summary:")
    print("-" * 50)
    print(f"Total Tests Run: {len(payloads) * 2}")  # *2 for GET and POST
    print(f"Attacks Blocked: {results['blocked']}")
    print(f"Valid Inputs Passed: {results['passed']}")
    print(f"Failed Tests: {results['failed']}")

if __name__ == "__main__":
    test_xss_detection()
