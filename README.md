# Email-Scam-Detector
Uploaded to this repository is all of the files needed to run the email scam detector.

**This site will allow the user to upload the subject, sender, and body of an email that they may be suspicious about. Returned will be the results of the Anthropic API's** **analysis along with the results my own created rule-based detector. The user can also link their email for batch analysis of the user's X most recent emails that they**
**input (requires app password (instructions above))**

# YouTube Links: 

PowerPoint Presentation

https://youtu.be/xQVUs4-QVtg

Demo Video

https://youtu.be/YINBZPi5W-A

# Steps to run the project:

-Clone repository

-Install Dependencies: pip install flask anthropic python-dotenv

-create .env file in root with format: ANTHROPIC_API_KEY="your-key"

-Create Anthropic API key from https://console.anthropic.com/ 

^^^(this must be done to keep API key confidential)

-save all files, cd to project root in terminal

-Run: python app.py

-Open: http://localhost:5000

-For Batch Check App Password: Must have 2FA enabled. Create app password at https://myaccount.google.com/apppasswords . Paste this into the password field.


# Notebook File with Detector Functions 

https://colab.research.google.com/drive/1Jx9Fu1Q_7kM2RDi5QJXrIof1xrOSQtaR?usp=drive_link

**The notebook file runs with a CSV file that cannot be uploaded to the repository but it will be submitted on Canvas and can also be downloaded at the link below**

https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset?resource=download
