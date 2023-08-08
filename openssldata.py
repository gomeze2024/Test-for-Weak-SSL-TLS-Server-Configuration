import re
import subprocess
from urllib.parse import urlparse

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False
    
def get_ciphers(website_url):
    if not validate_url(website_url):
        raise ValueError("Invalid website URL. Please provide a valid URL starting with http:// or https://")
    try:
        command = ["testssl -U -E " + website_url]

        p1 = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout_text = p1.stdout
        lines = stdout_text.split("\n")

        ciphers = []

        start_index = None
        for i, line in enumerate(lines):
            if "Hexcode  Cipher Suite Name (OpenSSL)" in line:
                start_index = i + 2
                break
        
        tls_version = None

        for line in lines[start_index:]:
            items = line.split()

            if len(items) > 1 and "x" in items[0] :
                ciphers.append({
                "tls_version": tls_version,
                "name": items[1],
                "openssl_name":items[len(items)-1],
                "strength": "Unsure"
                })
            else:
                tls_version = " ".join(item for item in items)

        return ciphers
    
    except subprocess.CalledProcessError as e:
        print(f"Command returned a non-zero exit status:")
    except Exception as e:
        print("An error occurred:")
        print(e)

def get_website_and_port(url):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc

    if scheme == 'http':
        port = parsed_url.port or 80
    elif scheme == 'https':
        port = parsed_url.port or 443
    else:
        raise ValueError("Invalid URL scheme. Supported schemes are 'http' and 'https'.")

    website = netloc.split(':')[0] if ':' in netloc else netloc
    return website, port

def nmap_ciphers(website_url):
    website, port = get_website_and_port(website_url)

    try:
        command = ["nmap -sT -p " + str(port) + " " + str(website)+" --script ssl-enum-ciphers "]
        p1 = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout_text = p1.stdout

        return stdout_text, command[0]
    
    except subprocess.CalledProcessError as e:
        print(f"Command returned a non-zero exit status:")
    except Exception as e:
        print("An error occurred:")
        print(e)

def parse_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme == 'https':
        host_with_port = parsed_url.netloc
        host_without_port = parsed_url.netloc
        return host_with_port, host_without_port
    else:
        raise ValueError("The provided URL is not using the 'https' scheme.")
    
def get_website_and_netloc(url):
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc

    if scheme != 'http' and scheme != 'https':
        raise ValueError("Invalid URL scheme. Supported schemes are 'http' and 'https'.")

    website = netloc.split(':')[0] if ':' in netloc else netloc
    return netloc, website

def openssl_ciphers(website_url, cipher):
    with_port, without_port = get_website_and_netloc(website_url)

    input_string = cipher['tls_version']
    extracted_string = re.search(r'\x1b\[.*?m(.*?)\x1b\[.*?m', input_string).group(1)
    extracted_string = "-" + extracted_string.lower().replace(" ", "").replace(".", "_")
    
    try:
        command = ["echo | openssl s_client -connect " + str(with_port) + " -servername " +
                    str(without_port) + " " + extracted_string +" -cipher " + cipher['name']]
        
        p1 = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout_text = p1.stdout

        pattern = r"(?<=CONNECTED\(00000005\))[\s\S]*?SSL handshake has read([\s\S]*)"
        match = re.search(pattern, stdout_text)

        if match:
            extracted_data = "CONNECTED(00000005)\n---\n"+ match.group(1).strip()
        else:
            print("Could not establish connection")

        return extracted_data, command[0]
    
    
    except subprocess.CalledProcessError as e:
        print(f"Command returned a non-zero exit status:")
    except Exception as e:
        print("An error occurred:")
        print(e)
    
if __name__ == "__main__":
    we = {'tls_version': '\x1b[4mTLS 1\x1b[m', 'name': 'ECDHE-RSA-AES256-SHA', 'openssl_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'strength': 'Weak'}
    wah,woh = openssl_ciphers("https://localhost:8000/", we)
    print(wah)
    print(woh)


