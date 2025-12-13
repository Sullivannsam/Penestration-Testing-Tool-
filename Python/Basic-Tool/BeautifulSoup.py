import requests
import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

def extract_login_parameters(url):
    """
    Extract all parameters from a login page
    Returns: Dictionary with all found parameters
    """
    params = {
        'url': url,
        'forms': [],
        'query_params': {},
        'endpoints': []
    }
    
    try:
        session = requests.Session()
        response = session.get(url, timeout=10)
        
        # Parse query parameters from URL
        parsed = urlparse(url)
        params['query_params'] = parse_qs(parsed.query)
        
        # Parse HTML for forms
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all forms
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Get all input fields
            inputs = form.find_all('input')
            for inp in inputs:
                input_data = {
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'value': inp.get('value', ''),
                    'placeholder': inp.get('placeholder', '')
                }
                form_data['inputs'].append(input_data)
            
            params['forms'].append(form_data)
        
        # Also look for JavaScript endpoints
        js_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]/[^"\']+)["\']',
            r'["\'](/auth/[^"\']+)["\']',
            r'["\'](/login[^"\']*)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, response.text)
            params['endpoints'].extend(matches)
        
        return params
        
    except Exception as e:
        print(f"Error: {e}")
        return params

# Usage example
if __name__ == "__main__":
    # Example URL (use your own test server)
    test_url = "https://example.com/login"  # Replace with actual test URL
    
    print(f"Extracting parameters from: {test_url}")
    print("-" * 50)
    
    result = extract_login_parameters(test_url)
    
    print(f"Found {len(result['forms'])} form(s)")
    
    for i, form in enumerate(result['forms'], 1):
        print(f"\nForm #{i}:")
        print(f"  Action: {form['action']}")
        print(f"  Method: {form['method']}")
        print("  Input fields:")
        
        for inp in form['inputs']:
            if inp['name']:  # Only show fields with names
                print(f"    • {inp['name']} (type: {inp['type']}, value: '{inp['value']}')")
    
    if result['query_params']:
        print(f"\nQuery parameters in URL:")
        for param, values in result['query_params'].items():
            print(f"  • {param} = {values}")
    
    if result['endpoints']:
        print(f"\nFound {len(result['endpoints'])} API endpoints:")
        for endpoint in result['endpoints'][:5]:  # Show first 5
            print(f"  • {endpoint}")