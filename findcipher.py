import requests
from bs4 import BeautifulSoup

def cipher_strength(ciphers):
    for cipher in ciphers:
        url = "https://ciphersuite.info/cs/"+cipher["openssl_name"]

        response = requests.get(url)

        cipher_strength = "Unsure"

        if response.status_code == 200:
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')

            class_to_strength = {
                'text-warning': 'Weak',
                'text-danger': 'Insecure',
                'text-secure': 'Secure',
                'text-success': 'Recommended'
            }

            cipher["strength"] = "Unsure"

            for class_name, strength in class_to_strength.items():
                if soup.find('span', class_=class_name):
                    cipher["strength"] = strength
                    break
