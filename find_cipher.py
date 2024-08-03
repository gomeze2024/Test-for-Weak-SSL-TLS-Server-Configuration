import requests
from bs4 import BeautifulSoup

def cipher_strength(ciphers):
    for cipher in ciphers:
        url = "https://ciphersuite.info/cs/"+cipher["openssl_name"]

        response = requests.get(url)

        if response.status_code == 200:
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            text = soup.get_text()

            strengths = ['Weak','Insecure', 'Secure', 'recommended']

            cipher["strength"] = "Unsure"

            for strength in strengths:
                if strength in text:
                    cipher["strength"] = strength
                    break