from openssldata import get_ciphers, nmap_ciphers, openssl_ciphers
from findcipher import cipher_strength
from urllib.parse import urlparse
        
def main():
    #get the URL, input validation inside the functions that run commands
    website_url = input("Enter the website URL (starting with http:// or https://): ")

    print("--- Conducting TestSSL scan for " + website_url + " ---")
    ciphers = get_ciphers(website_url)

    print("--- Searching Cipher Strength and Validating Connection ---")
    nmapdata, nmapcmd = nmap_ciphers(website_url)
    cipher_strength(ciphers)

    severity_ranking = "Not Vulnerable"
    current_version = None

    #Weakest Cipher for OpenSSL Connection
    weakest_cipher = None
    if (len(ciphers) >= 1):
        weakest_cipher = ciphers[0]
    
    output = ""

    for current_cipher in ciphers:
        if (current_cipher['strength'] == "Weak" or current_cipher['strength'] == "Insecure"):
            if (current_cipher['tls_version'] != current_version):
                output += current_cipher['tls_version'] + "\n"
                current_version = current_cipher['tls_version']
            output += current_cipher['name'] + "\n"
            if (current_cipher['strength'] == "Weak" and severity_ranking == "Not Vulnerable"):
                severity_ranking = "Low" 
                weakest_cipher = current_cipher
            if (current_cipher['strength'] == "Insecure" and severity_ranking != "Medium"):
                severity_ranking = "Medium"
                weakest_cipher = current_cipher

    #Print the Severity Ranking, the weak ciphers under their version, and the nmap data
    print("Severity Ranking: " + severity_ranking)
    print(output)
    print("Supporting Evidence")
    print(nmapcmd)
    print(nmapdata)

    #If there is a weak or insecure cipher, then OpenSSL connect to it
    if (weakest_cipher != None):
        print("OpenSSL Connection")
        openssldata, opensslcmd = openssl_ciphers(website_url, weakest_cipher)
        print(opensslcmd)
        print(openssldata)

if __name__ == "__main__":
    main()
