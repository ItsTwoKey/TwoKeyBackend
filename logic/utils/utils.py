from __future__ import print_function
import time
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from pprint import pprint
import secrets
import string
from backend.settings import BREVO_KEY,DEPLOY_URL

configuration = sib_api_v3_sdk.Configuration()

configuration.api_key['api-key'] = BREVO_KEY

# Initialize the SendinBlue API instance
api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))


def generate_strong_password(length=8):
    # Define character sets for different types of characters
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    special_characters = string.punctuation

    # Combine all character sets
    all_characters = lowercase_letters + uppercase_letters + digits + special_characters

    # Ensure at least one character from each set
    password = (secrets.choice(lowercase_letters) +
                secrets.choice(uppercase_letters) +
                secrets.choice(digits) +
                secrets.choice(special_characters))

    # Fill the remaining length with random characters from all sets
    password += ''.join(secrets.choice(all_characters) for _ in range(length - 4))

    # Shuffle the password to make it more random
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    password = ''.join(password_list)

    return password


def generate_confirmation_token(length=27):
    token_bytes = secrets.token_bytes(length)
    token_hex = token_bytes.hex()
    return str(token_hex)



def send_email(to_address,password,confirmation_token):
    # SendinBlue mailing parameters
    sender = {"name": "Twokey", "email": "pushkarjadhav2@gmail.com"}
    template_id=3
    email = to_address
    link = f"https://cderhtrlfxroiyqqzytr.supabase.co/auth/v1/verify?token={confirmation_token}&type=signup&redirect_to={DEPLOY_URL}/onboarding"


    # Define the recipient(s)
    if to_address:
        # You can add multiple email accounts to which you want to send the mail in this list of dicts
        to = [{"email": to_address}]
    else:
        to = [{"email": "hrishikeshj572@gmail.com", "name": "no email given"}]

    # Create a SendSmtpEmail object
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=to,template_id=template_id, params={"email": email, "password": password,"link":link})

    try:
        # Send the email
        api_response = api_instance.send_transac_email(send_smtp_email)
        print(api_response)
        return {"message": "Email sent successfully!"}
    except ApiException as e:
        print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)




