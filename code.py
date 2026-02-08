import hashlib
from cryptography.fernet import Fernet

# -------------------------------
# Key generation for encryption
# -------------------------------
key = Fernet.generate_key()
cipher = Fernet(key)

# -------------------------------
# In-memory database
# -------------------------------
users = {}
logs = []

# -------------------------------
# Utility Functions
# -------------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def log_activity(activity):
    logs.append(activity)

# -------------------------------
# User Registration
# -------------------------------
def register_user(username, password, role):
    if role not in ["staff", "student"]:
        return "Invalid role"

    users[username] = {
        "password": hash_password(password),
        "role": role
    }
    log_activity(f"{username} registered as {role}")
    return "Registration successful"

# -------------------------------
# Authentication
# -------------------------------
def login(username, password):
    if username not in users:
        return "User not found"

    hashed_input = hash_password(password)
    if hashed_input == users[username]["password"]:
        log_activity(f"{username} logged in")
        return "Login successful"
    else:
        return "Invalid credentials"

# -------------------------------
# Secure Data Access
# -------------------------------
def secure_data_access(username, data):
    role = users[username]["role"]

    encrypted_data = cipher.encrypt(data.encode())

    if role == "staff":
        log_activity(f"Staff {username} accessed encrypted data")
        return encrypted_data
    else:
        return "Access denied: Students cannot access this data"

# -------------------------------
# Decryption (Authorized Only)
# -------------------------------
def decrypt_data(username, encrypted_data):
    if users[username]["role"] == "staff":
        decrypted = cipher.decrypt(encrypted_data).decode()
        return decrypted
    else:
        return "Unauthorized decryption attempt"

# -------------------------------
# Example Usage
# -------------------------------
print(register_user("john_staff", "secure123", "staff"))
print(register_user("mary_student", "mypassword", "student"))

print(login("john_staff", "secure123"))

encrypted = secure_data_access("john_staff", "Student Results Data")
print("Encrypted Data:", encrypted)

print("Decrypted Data:", decrypt_data("john_staff", encrypted))

print("\nSystem Logs:")
for log in logs:
    print(log)
