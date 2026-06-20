import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

load_dotenv()

# Email Configuration (same as config.py)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.hostinger.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "465"))
EMAIL_USER = os.environ.get("EMAIL_USER", "contact@securitigpt.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "contact@securitigpt.com")

def test_email_sending():
    """Test email sending with current configuration."""
    print("=" * 50)
    print("EMAIL SENDING TEST")
    print("=" * 50)
    print(f"EMAIL_HOST: {EMAIL_HOST}")
    print(f"EMAIL_PORT: {EMAIL_PORT}")
    print(f"EMAIL_USER: {EMAIL_USER}")
    print(f"EMAIL_PASSWORD: {'SET' if EMAIL_PASSWORD else 'NOT SET'}")
    print(f"EMAIL_FROM: {EMAIL_FROM}")
    print("=" * 50)
    
    if not EMAIL_PASSWORD:
        print("ERROR: EMAIL_PASSWORD environment variable is not set!")
        print("Please set it in Render dashboard or locally.")
        return False
    
    # Test email recipient (change to your email for testing)
    test_email = "contact@securitigpt.com"  # Change to your test email
    
    try:
        # Create test email
        message = MIMEMultipart("alternative")
        message["Subject"] = "Test Email - CyberGuard Password Reset"
        message["From"] = EMAIL_FROM
        message["To"] = test_email
        
        html = """
        <html>
        <body>
            <h2>Test Email</h2>
            <p>This is a test email from CyberGuard password reset system.</p>
            <p>If you receive this, email sending is working correctly!</p>
        </body>
        </html>
        """
        
        message.attach(MIMEText(html, "html"))
        
        print(f"\nAttempting to send test email to: {test_email}")
        print("Using SMTP_SSL connection...")
        
        # Send email using SSL
        with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT) as server:
            print("Connecting to SMTP server...")
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            print("Login successful!")
            server.sendmail(EMAIL_FROM, test_email, message.as_string())
            print("Email sent successfully!")
        
        print("\n" + "=" * 50)
        print("SUCCESS: Email sent without errors")
        print("=" * 50)
        print(f"Please check your inbox (and spam folder) at: {test_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"\nERROR: SMTP Authentication Failed")
        print(f"Details: {e}")
        print("\nPossible causes:")
        print("- Wrong email password")
        print("- Hostinger requires App Password instead of regular password")
        print("- Email account locked or requires additional verification")
        return False
        
    except smtplib.SMTPConnectError as e:
        print(f"\nERROR: Could not connect to SMTP server")
        print(f"Details: {e}")
        print("\nPossible causes:")
        print("- Wrong SMTP host or port")
        print("- Firewall blocking connection")
        print("- Hostinger SMTP service down")
        return False
        
    except Exception as e:
        print(f"\nERROR: Unexpected error occurred")
        print(f"Error type: {type(e).__name__}")
        print(f"Details: {e}")
        return False

if __name__ == "__main__":
    test_email_sending()
