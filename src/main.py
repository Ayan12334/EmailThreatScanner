import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from analyse import extract_body, extract_urls, analyse_headers

#least priviledge 
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token: #when you log in, google gives the access token (short lived) and a refresh token (long token)to request for a new access token
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0) #temp server that waits to receive the authorisation code from google to then get the access token and refresh token
        with open('token.json', 'w') as token: # w is write permission to os
            token.write(creds.to_json()) # method to convert all of creds attr.s to a json string which is written to the file descriptor 
    return creds

def scan_inbox():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    print("Fetching the 5 most recent emails for threat analysis...\n")
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=5).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No messages found.")
        return

    for idx, msg in enumerate(messages, 1):
        #retrieves the full rfc 822 and mime structure
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute() 

        #rfc 822 is the structure of emails with a header and body
        # mime expands on this with more features in the header and transforms the body from a flat string into a nested tree of parts (multipart/mixed, multipart/alternative)
        
        # threats in the header target authenticty and origin
        # threats in body target interaction
        
        payload = msg_data.get('payload', {})
        headers = payload.get('headers', [])

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
        
        # Threat Engine parsing
        header_intel = analyse_headers(headers)
        body = extract_body(payload)
        extracted_urls = extract_urls(body)

        print(f"[{idx}] Subject: {subject}")
        print(f"    Sender:  {header_intel['from']}")
        print(f"    SPF:     {'PASS' if header_intel['spf_pass'] else 'FAIL/NONE'} | DKIM: {'PASS' if header_intel['dkim_pass'] else 'FAIL/NONE'}")
        if header_intel['flags']:
            print(f"    [!] Flags: {', '.join(header_intel['flags'])}")
        print(f"    Found {len(extracted_urls)} unique URL(s):")
        for url in extracted_urls[:3]:
            print(f"      - {url}")
        if len(extracted_urls) > 3:
            print(f"      ... and {len(extracted_urls) - 3} more")
        print("-" * 60)

if __name__ == '__main__':
    scan_inbox()