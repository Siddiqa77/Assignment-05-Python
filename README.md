Secure Data Encryption App

📖 Overview
The Secure Data Encryption App is a Streamlit-based web application designed for secure user registration, data encryption, and retrieval using a secret passkey. It prioritizes data privacy with robust encryption and user authentication, featuring a lockout mechanism for enhanced security and an intuitive interface.
✨ Features

User Authentication:
Register with a unique username and password.
Secure login with a 3-attempt lockout (60 seconds).


Data Encryption & Storage:
Encrypt text data with a user-defined passkey.
Store encrypted data persistently in a JSON file.


Data Retrieval:
View and decrypt stored entries with the correct passkey.
Option to delete all user data.


Security Mechanisms:
Passwords hashed using PBKDF2-HMAC-SHA256.
Data encrypted with Fernet symmetric encryption.
Static salt for consistent key derivation.


User Interface:
Clean, responsive Streamlit UI with sidebar navigation.
Clear feedback for user actions (success, error, warnings).



📦 Prerequisites

Python: Version 3.8 or higher.
Dependencies:
streamlit (for the web interface)
cryptography (for encryption)
pyOpenSSL (optional, for additional security)



Install dependencies with:
pip install streamlit cryptography pyOpenSSL

🚀 Installation

Clone the repository or download the project files:
git clone https://github.com/your-username/secure-data-encryption-app.git
cd secure-data-encryption-app


Install dependencies:
pip install -r requirements.txt


Run the application:
streamlit run app.py


Open your browser and navigate to http://localhost:8501.


📂 File Structure
secure-data-encryption-app/
├── app.py              # Main Streamlit application script
├── secure_data.json    # Stores user data and encrypted entries
├── requirements.txt    # Python package dependencies
├── README.md           # Project documentation
└── LICENSE             # MIT License file

🖥️ Usage

Home: Read the welcome message and app overview.
Register: Create an account with a username and password.
Login: Authenticate with your credentials. Avoid 3 failed attempts to prevent a 60-second lockout.
Store Data: Input text and a passkey to encrypt and save data (login required).
Retrieve Data:
View all encrypted entries.
Paste an entry and provide the passkey to decrypt.
Delete all stored data if needed.



Example Workflow

Register as user1 with password pass123.
Login with the same credentials.
Store data: Enter "My secret note" with passkey "key123".
Retrieve data: Copy the encrypted entry, paste it, and decrypt with "key123".

🔒 Security Details

Password Hashing: Uses PBKDF2-HMAC-SHA256 with 100,000 iterations and a static salt (secure_salt_value).
Data Encryption: Employs Fernet (AES-128 in CBC mode) with a key derived from the user’s passkey.
Storage: User data and encrypted entries are saved in secure_data.json. Protect this file from unauthorized access.
Lockout: After 3 failed login attempts, the user is locked out for 60 seconds to deter brute-force attacks.

Security Recommendations

Use a unique, strong passkey for encryption.
Store secure_data.json in a secure location.
For production, replace JSON storage with a database and use environment variables for sensitive data.

📸 Screenshots



Home Page
Register
Store Data








Note: Screenshots are placeholders. Add actual images to a screenshots/ folder.
⚠️ Limitations

Local Storage: JSON file storage is not suitable for multi-user or production environments.
Single-User Focus: Designed for local, single-user access.
No Recovery: No password recovery mechanism is implemented.
Static Salt: Uses a fixed salt for key derivation, which may be less secure in some contexts.

🌟 Future Enhancements

Database Integration: Use SQLite or PostgreSQL for scalable, multi-user storage.
Password Recovery: Add email-based or security-question-based recovery.
Multi-User Support: Implement session isolation for concurrent users.
UI Improvements: Enhance styling with custom CSS and improve mobile responsiveness.
Dynamic Salt: Generate unique salts per user for better security.

📜 License
This project is licensed under the MIT License.
🤝 Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit your changes (git commit -m 'Add YourFeature').
Push to the branch (git push origin feature/YourFeature).
Open a pull request.

Please report bugs or suggest features via GitHub Issues.
📬 Contact
For questions or feedback, contact [Your Name] via [your.email@example.com] or GitHub Profile.

⭐ If you find this project useful, give it a star on GitHub!
