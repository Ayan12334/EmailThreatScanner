import re
import base64
from typing import Dict, List, Any

# Matches standard HTTP/HTTPS URLs while ignoring trailing punctuation
URL_REGEX = r'https?://[^\s<>"\')]+'

def decode_payload_data(encoded_data: str) -> str:
    """Decodes standard base64url data returned by the Gmail API."""
    try:
        decoded_bytes = base64.urlsafe_b64decode(encoded_data.encode('ASCII'))
        return decoded_bytes.decode('utf-8', errors='replace')
    except Exception:
        return ""

def extract_body(payload: Dict[str, Any]) -> str:
    """Traverses MIME tree parts to extract all text/plain or text/html content."""
    body_text = ""
    
    # Direct body (single-part email)
    if 'data' in payload.get('body', {}):
        return decode_payload_data(payload['body']['data'])
    
    # Multipart email traversal
    parts = payload.get('parts', [])
    for part in parts:
        mime_type = part.get('mimeType', '')
        if mime_type in ['text/plain', 'text/html'] and 'data' in part.get('body', {}):
            body_text += decode_payload_data(part['body']['data']) + "\n"
        elif 'parts' in part:
            body_text += extract_body(part) + "\n"
            
    return body_text

def extract_urls(text: str) -> List[str]:
    """Extracts unique embedded URLs from decoded message text."""
    urls = re.findall(URL_REGEX, text)
    cleaned = [re.sub(r'[\.,;]$', '', url) for url in urls]
    return sorted(list(set(cleaned)))

def analyse_headers(headers: List[Dict[str, str]]) -> Dict[str, Any]:
    """Inspects routing and authentication headers for spoofing flags."""
    header_map = {h['name'].lower(): h['value'] for h in headers}
    
    from_header = header_map.get('from', '')
    reply_to = header_map.get('reply-to', '')
    auth_results = header_map.get('authentication-results', '')

    flags = []

    # Check for From / Reply-To mismatch
    if reply_to and reply_to not in from_header:
        flags.append(f"Reply-To mismatch detected: From '{from_header}' vs Reply-To '{reply_to}'")

    # Parse basic SPF/DKIM/DMARC status
    spf_pass = "spf=pass" in auth_results.lower() # Sender Policy Framework - dns record 
    dkim_pass = "dkim=pass" in auth_results.lower() # Domainkeys Identified Mail - private key used to make signatures
    dmarc_pass = "dmarc=pass" in auth_results.lower() # Domain-based Message Authentication, Reporting, and Conformance

    if auth_results and not spf_pass:
        flags.append("SPF check failed or missing")
    if auth_results and not dkim_pass:
        flags.append("DKIM check failed or missing")

    return {
        "from": from_header,
        "reply_to": reply_to,
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "dmarc_pass": dmarc_pass,
        "flags": flags
    }