import re
import requests
from bs4 import BeautifulSoup
import csv
from urllib.parse import urljoin, urlparse
from datetime import datetime
import warnings
import random
import time

# ======================
# CONFIGURATION
# ======================
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

HEADERS = {
    'Accept-Language': 'en-US,en;q=0.9',
    'DNT': '1',
    'Connection': 'keep-alive'
}

MAX_RETRIES = 2
TIMEOUT = 15

# API Configuration (Add your keys here)
API_CONFIG = {
    'email_verification': {
        'endpoint': 'https://api.hunter.io/v2/email-verifier',
        'key': 'YOUR_HUNTER_API_KEY'  # Get from https://hunter.io
    },
    'phone_validation': {
        'endpoint': 'https://lookups.twilio.com/v1/PhoneNumbers/',
        'sid': 'YOUR_TWILIO_SID',     # Get from https://twilio.com
        'token': 'YOUR_TWILIO_TOKEN'
    }
}

# ======================
# CONFIDENCE CALCULATION (Hybrid API + Local)
# ======================
class ConfidenceCalculator:
    @staticmethod
    def get_random_agent():
        return {'User-Agent': random.choice(USER_AGENTS)}

    @staticmethod
    def email_confidence(email):
        """Hybrid scoring: Try API first, fallback to local checks"""
        try:
            # API verification attempt
            params = {
                'email': email,
                'api_key': API_CONFIG['email_verification']['key']
            }
            response = requests.get(
                API_CONFIG['email_verification']['endpoint'],
                params=params,
                timeout=3
            )
            data = response.json().get('data', {})
            
            if data.get('status') == 'valid':
                # Score based on verification quality
                score = 85
                if data.get('sources', []):
                    score += 5  # Bonus for being referenced online
                if data.get('first_name') and data.get('last_name'):
                    score += 5  # Bonus for personal identification
                return min(100, score)
                
        except (requests.RequestException, KeyError):
            pass  # Fall through to local checks

        # Local scoring fallback
        domain = email.split('@')[-1].lower()
        if domain.endswith(('.edu', '.gov')):
            return 80
        if any(d in domain for d in ['gmail', 'yahoo', 'outlook']):
            return 60
        if '.' in domain and len(domain.split('.')[0]) > 3:
            return 70  # Likely corporate
        return 50  # Default

    @staticmethod
    def phone_confidence(phone):
        """Phone validation with Twilio API fallback"""
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        try:
            # Twilio API attempt
            response = requests.get(
                f"{API_CONFIG['phone_validation']['endpoint']}{cleaned}",
                auth=(API_CONFIG['phone_validation']['sid'], API_CONFIG['phone_validation']['token']),
                timeout=3
            )
            data = response.json()
            
            # Score based on carrier info
            score = 70 if data.get('carrier', {}).get('type') == 'mobile' else 60
            if data.get('country_code') in ('US', 'CA', 'GB'):
                score += 15  # Bonus for trusted countries
            return min(100, score)
                
        except (requests.RequestException, KeyError):
            # Local fallback
            if cleaned.startswith('+1') and len(cleaned) == 12:
                return 75  # US/Canada numbers
            if len(cleaned) > 8:
                return 65  # Valid length
            return 45  # Suspicious

    @staticmethod
    def social_confidence(url):
        """Social media profile scoring"""
        domain = urlparse(url).netloc.lower()
        
        # Platform base scores
        if 'linkedin.com' in domain:
            username = url.split('/')[-1]
            if len(username) > 5 and '_' not in username:
                return 85  # Professional profile
            return 70
            
        elif 'twitter.com' in domain:
            return 65
            
        return 50  # Other platforms

# ======================
# SCAM DETECTION 
# ======================
def is_potential_scam(url):
    """Analyze website for scam indicators"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        domain = urlparse(url).netloc.lower()
        score = 0
        
        # Domain age indicators (simplified)
        if any(x in domain for x in ['new', 'fresh', 'recent', '202', 'update']):
            score += 30
            
        # Suspicious URL patterns
        if re.search(r'\d{5,}', domain) or '-' in domain or len(domain) > 30:
            score += 25
            
        # Try to get page content
        try:
            response = requests.get(url, headers={**HEADERS, **get_random_agent()}, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()
            
            # Poor grammar indicators
            poor_grammar = ['urgent', 'immediately', 'limited time', 'congratulation', 'winner']
            if any(x in text[:1000] for x in poor_grammar):
                score += 20
                
            # Check for contact info
            contact_patterns = [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
            ]
            has_contact = any(re.search(pattern, text) for pattern in contact_patterns)
            if not has_contact:
                score += 15
                
        except:
            pass
            
        # HTTPS check
        if not url.startswith('https://'):
            score += 10
            
        return score >= 70
        
    except Exception as e:
        print(f"Scam detection error: {e}")
        return False

# ======================
# CORE FUNCTIONS 
# ======================
def get_random_agent():
    """Return a random user agent to avoid detection"""
    return {'User-Agent': random.choice(USER_AGENTS)}

def is_valid_url(url):
    """Check if URL has valid format"""
    return re.match(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url)

def extract_emails(text):
    """More permissive email extraction"""
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))

def extract_phones(text):
    """More permissive phone number extraction"""
    pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
    return list(set(re.findall(pattern, text)))

def extract_social_links(soup, base_url):
    """Extract social media profiles with reduced validation"""
    social_links = {
        'linkedin': [],
        'twitter': [],
        'facebook': [],
        'instagram': []
    }
    
    for link in soup.find_all('a', href=True):
        href = link['href'].lower()
        if 'linkedin.com' in href:
            social_links['linkedin'].append(urljoin(base_url, href))
        elif 'twitter.com' in href:
            social_links['twitter'].append(urljoin(base_url, href))
        elif 'facebook.com' in href:
            social_links['facebook'].append(urljoin(base_url, href))
        elif 'instagram.com' in href:
            social_links['instagram'].append(urljoin(base_url, href))
    
    # Deduplicate
    for key in social_links:
        social_links[key] = list(set(social_links[key]))
    
    return social_links

def scrape_website(url):
    """Main scraping function with retry logic"""
    headers = {**HEADERS, **get_random_agent()}
    calculator = ConfidenceCalculator()
    
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Attempt {attempt + 1}: Scraping {url}")
            response = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            
            # Also check meta tags for contact info
            meta_content = ' '.join([meta.get('content', '') for meta in soup.find_all('meta')])
            all_text = text + ' ' + meta_content
            
            # Extract data with reduced validation
            emails = extract_emails(all_text)
            phones = extract_phones(all_text)
            social_links = extract_social_links(soup, url)
            
            # Process contacts with hybrid confidence
            contacts = []
            for email in emails:
                contacts.append({
                    'type': 'email',
                    'value': email,
                    'valid': 'yes',
                    'confidence': calculator.email_confidence(email)
                })
                
            for phone in phones:
                contacts.append({
                    'type': 'phone',
                    'value': phone,
                    'valid': 'yes',
                    'confidence': calculator.phone_confidence(phone)
                })
                
            for platform, urls in social_links.items():
                for url in urls:
                    contacts.append({
                        'type': platform,
                        'value': url,
                        'valid': 'yes',
                        'confidence': calculator.social_confidence(url)
                    })
            
            return {
                'contacts': contacts,
                'success': True
            }
            
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == MAX_RETRIES - 1:
                return {'success': False, 'error': str(e)}
            time.sleep(2)

# ======================
# REPORT GENERATION 
# ======================
def generate_report(data, filename='contacts.csv'):
    """Generate CSV report with all contacts"""
    if not data['success']:
        print(f"Failed to generate report: {data.get('error', 'Unknown error')}")
        return False
    
    contacts = data.get('contacts', [])
    
    if contacts:
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            fieldnames = ['type', 'value', 'valid', 'confidence']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(contacts)
        print(f"\nSuccessfully generated {filename} with {len(contacts)} contacts")
        return True
    else:
        print("\nNo contacts found - empty report")
        return False

# ======================
# MAIN EXECUTION (Unchanged)
# ======================
if __name__ == "__main__":
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    print("""
    ███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗ 
    ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
    ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██████╔╝
    ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
    ███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██║  ██║
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
    """)
    
    while True:
        url = input("\nEnter company URL (or 'quit' to exit): ").strip()
        
        if url.lower() in ('quit', 'exit'):
            break
            
        if not is_valid_url(url):
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            else:
                print("Invalid URL format. Please include http:// or https://")
                continue
        
        # Check for potential scam first
        if is_potential_scam(url):
            print("\n⚠️ WARNING: This website appears to be a potential scam/fake site!")
        else:
            print("\nThis website doesn't appear to be a scam.")
        
        # Proceed with scraping
        data = scrape_website(url)
        if data['success']:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"contacts_{timestamp}.csv"
            generate_report(data, filename)
        else:
            print("Scraping failed. Possible reasons:")
            print("- Website requires JavaScript (try Selenium)")
            print("- IP blocked (try VPN/proxy)")
            print("- Site has strong anti-bot protection")
            
        print("\n" + "="*50)