from flask import Flask, render_template, request, jsonify
import anthropic
import json
import imaplib
import email
from email.header import decode_header
import re
#2 imports needed to make API key environmental and not read on Github
import os
from dotenv import load_dotenv

app = Flask(__name__)

#load .env file with API Key in it
load_dotenv()
#Initialize Anthropic API
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

#Defining my Rule-Based Detector with functions from the notebook
class RuleBasedScamDetector:
    #ALL FUNCTIONS COPY AND PASTED DIRECTLY FROM THE NOTEBOOK FILE
    def __init__(self):
        self.urgent_words = ['urgent', 'immediate', 'action required', 'suspended', 'verify now',
                            'act now', 'limited time', 'expires', 'last chance']
        self.money_words = ['won', 'winner', 'prize', 'claim', 'lottery', 'million', 
                           'cash', 'reward', 'free', 'bonus']
        self.threat_words = ['suspended', 'closed', 'compromised', 'unauthorized', 'failed', 
                            'blocked', 'locked', 'terminate']
        self.vulgar_words = ['penis', 'vagina', 'erection', 'dick']

        #suspicious domain patterns
        self.suspicious_domains = ['lottery', 'prize', 'winner', 'alert', 'security', 'verify',
                                   'urgent', 'payment', 'billing', 'account']
        #check for any urgent emails (ie: ACTION REQUIRED NOW)
    def check_urgency(self, text):
        text_lower = text.lower()
        return any(word in text_lower for word in self.urgent_words)
    
        #check for spammy/sexually vulgar words
    def check_vulgar(self, text):
        text_lower = text.lower()
        return any(word in text_lower for word in self.vulgar_words)

        #check for any promises of money or prizes
    def check_money_offers(self, text):
        text_lower = text.lower()
        return any(word in text_lower for word in self.money_words)
        
        #check for threats
    def check_threats(self, text):
        text_lower = text.lower()
        return any(word in text_lower for word in self.threat_words)
        
        #check for excessive capitilization
    def check_excessive_caps(self, text):
        if len(text) == 0:
            return False
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
        return caps_ratio > 0.3
        
        #check for excessive exclamation points
    def check_exclamation(self, text):
        return text.count('!') >= 3
    
    #check suspicious domains (and any 1s replaces with ls, or 0s with os)
    def check_suspicious_domain(self, sender):
        sender_lower = sender.lower()
        if '@' in sender_lower:
            domain = sender_lower.split('@')[-1]
            if re.search(r'[0-9]', domain):
                return True
        return any(domain in sender_lower for domain in self.suspicious_domains)

    #analyze the emails and add points to the scam score based on the previous 
    #check functions. (more points for the more suspicious infractions) 
    def analyze(self, subject, sender, body):
        flags = []
        score = 0
        
        full_text = f"{subject} {body}"
        
        if self.check_urgency(full_text):
            flags.append("Urgency/pressure tactics detected")
            score += 25
        if self.check_vulgar(full_text):
            flags.append("Sexually Explicit language detected")
            score += 25
        if self.check_money_offers(full_text):
            flags.append("Money/prize offer detected")
            score += 25
        
        if self.check_threats(full_text):
            flags.append("Threatening language detected")
            score += 25
        
        if self.check_excessive_caps(subject):
            flags.append("Excessive capitalization")
            score += 15
        
        if self.check_exclamation(full_text):
            flags.append("Excessive exclamation marks")
            score += 10
        
        if self.check_suspicious_domain(sender):
            flags.append("Suspicious sender domain")
            score += 30
        
        return {
            'scam_score': min(score, 100),
            'is_scam': score >= 50,
            'red_flags': flags
        }

#define for testing
rule_detector = RuleBasedScamDetector()

#Defining the prompt to send to the API to test each email input/read in
def analyze_email_with_claude(subject, sender, body):
    prompt = f"""Analyze this email for scam/phishing indicators:

SUBJECT: {subject}
FROM: {sender}
BODY: {body}

Evaluate for common scam indicators:
- Urgency/pressure tactics
- Requests for personal/financial info
- Suspicious links or attachments mentioned
- Grammar/spelling errors
- Sender legitimacy
- Too good to be true sounding offers
- Impersonation attempts

Return your analysis as JSON with:
- scam_score: 0-100 (0=definitely legitimate, 100=definitely scam)
- is_scam: true/false (true if score > 70)
- red_flags: list of specific concerns found
- explanation: brief summary

Return ONLY the JSON, no other text."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    #parse the response for the score and flags
    response_text = message.content[0].text.strip()
    
    #prevents formatting issues I was having with the JSON file response
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    if response_text.startswith("```"):
        response_text = response_text[3:]
    if response_text.endswith("```"):
        response_text = response_text[:-3]
    response_text = response_text.strip()
    
    return json.loads(response_text)

#Connect to the users email using IMAP server (REQUIRES APP PASSWORD FOR GMAIL)
#debug print statements added in because of connection issues 
def connect_to_email(email_address, password, imap_server):
    print(f"=== Attempting to connect ===")
    print(f"Email: {email_address}")
    print(f"Server: {imap_server}")
    print(f"Password length: {len(password)}")
    
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        print("SSL connection made ")
        
        mail.login(email_address, password)
        print("Logged in")
        return mail
    except Exception as e:
        print(f"Connection failed with error: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return None

#Fetch recent emails from the users inbox to send to the API and detector functions (default is 5)
def fetch_emails(mail, num_emails=5):
    mail.select("INBOX")
    status, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()
    recent_ids = email_ids[-num_emails:]
    
    #RFC822 is the standard email format with sender domain, subject, and body
    emails = []
    for email_id in recent_ids:
        status, msg_data = mail.fetch(email_id, "(RFC822)")
        
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                #decode subject line
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                
                sender = msg.get("From")
                
                #put the body of the email into the body var for analysis
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode()
                            except:
                                body = str(part.get_payload())
                            break
                else:
                    try:
                        body = msg.get_payload(decode=True).decode()
                    except:
                        body = str(msg.get_payload())
                
		#clean email formatted for the API and detector
                emails.append({
                    "subject": subject,
                    "sender": sender,
                    "body": body[:1000]
                })
    
    return emails

#display the main page
@app.route('/')
def index():
    return render_template('index.html')

#analyze a single email that the user inputs the information for manually
@app.route('/analyze_single', methods=['POST'])
def analyze_single():
    data = request.json
    
    try:
        #implement detector 
        rule_result = rule_detector.analyze(
            data['subject'],
            data['sender'],
            data['body']
        )
        
        #analyze with the API
        claude_result = analyze_email_with_claude(
            data['subject'],
            data['sender'],
            data['body']
        )
        
        #combined results (legacy function)
        combined = {
            'rule_based': rule_result,
            'claude': claude_result,
            'final_verdict': {
                'scam_score': claude_result['scam_score'],
                'is_scam': claude_result['is_scam'],
                'explanation': claude_result['explanation']
            }
        }
        
        return jsonify(combined)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze_batch', methods=['POST'])
def analyze_batch():
    data = request.json
    

	#connect to user's email with information input
    try:
        mail = connect_to_email(
            data['email_address'],
            data['password'],
            data['imap_server']
        )
        
        if not mail:
            return jsonify({"error": "Failed to connect to email"}), 400
       
        
        #Fetch X most recent emails input by the user
        emails = fetch_emails(mail, int(data['num_emails']))
        mail.logout()
        
        #analyze each email with sent with both API and detector functions
        results = []
        for email_data in emails:
            #Detector analysis
            rule_result = rule_detector.analyze(
                email_data['subject'],
                email_data['sender'],
                email_data['body']
            )
            
            #API analysis
            claude_result = analyze_email_with_claude(
                email_data['subject'],
                email_data['sender'],
                email_data['body']
            )
            
	    #store results for display later
            results.append({
                "email": email_data,
                "rule_based": rule_result,
                "claude": claude_result,
                "analysis": claude_result  
            })
        
        return jsonify({"results": results})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)