import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Restrict scope to read-only access
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    creds = None
    
    # Check for an existing local session token
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        
    # If no valid token exists, initiate the OAuth 2.0 flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES
            )
            creds = flow.run_local_server(port=0)
            
        # Cache the token for automated subsequent runs
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
            
    return creds

def fetch_recent_emails():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    print("Fetching the 5 most recent emails from INBOX...\n")
    results = service.users().messages().list(
        userId='me', labelIds=['INBOX'], maxResults=5
    ).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No messages found in the inbox.")
        return

    for idx, msg in enumerate(messages, 1):
        msg_data = service.users().messages().get(
            userId='me', id=msg['id'], format='full'
        ).execute()
        
        # Extract headers (From, Subject)
        headers = msg_data.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), '(Unknown Sender)')
        snippet = msg_data.get('snippet', '')

        print(f"[{idx}] ID: {msg['id']}")
        print(f"    From: {sender}")
        print(f"    Subject: {subject}")
        print(f"    Snippet: {snippet}\n")

if __name__ == '__main__':
    fetch_recent_emails()