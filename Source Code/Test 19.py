import os

# Access the environment variables
sender_email = os.getenv('SENDER_EMAIL')
receiver_email = os.getenv('RECEIVER_EMAIL')
email_password = os.getenv('EMAIL_PASSWORD')

# Print the environment variables to verify
print(f"SENDER_EMAIL: {sender_email}")
print(f"RECEIVER_EMAIL: {receiver_email}")
print(f"EMAIL_PASSWORD: {email_password}")
