import smtplib
from email.mime.text import MIMEText

def send_alert(file_path, virus_info):
    try:
        msg = MIMEText(f"Virus detected in {file_path}: {virus_info}")
        msg['Subject'] = 'Virus Alert'
        msg['From'] = 'your_email@example.com'
        msg['To'] = 'recipient@example.com'

        with smtplib.SMTP('smtp.example.com') as server:
            server.login('your_email@example.com', 'your_password')
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
    except Exception as e:
        print(f"Error sending alert: {e}")
