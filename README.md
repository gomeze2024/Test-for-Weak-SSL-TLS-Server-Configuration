# Test-Weak-SSL-TLS-Server-Configuration
A Python script that automates identifying and reporting weak SSL and TLS Server Configuration.

Nmap has a script called "SSL-enum-ciphers," specifically designed to discover supported cipher suites on a target server. It's good at identifying the ciphers but could be better at rating them.
My script scrapes ciphersuite.info to find up-to-date information on whether each is weak. It then connects to each of the weak/ insecure ones to ensure that it's not a false positive.
The script outputs the weak/ insecure ciphers along with the supporting evidence needed for an ASA report, including the nmap command + output and openssl command + output.

Setup for Mac/Linux Machines:

1. Clone and cd into the repository.
2. Make sure OpenSSL is installed and install the other requirements
pip install -r requirements.txt
3. Optional: For a test website: 
    1. Generate key and cert files:         
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
    More info here: https://www.suse.com/support/kb/doc/?id=000018152
    2. Run the insecure or secure website.
    python insecure_https_server.py 
    OR
    python secure_https_server.py.
1. Run the TLSTest
python tls_test.py
Input your website (ie. https://localhost:8000)

How To Interpret Results
Severity Ranking-
Not Vulnerable- All the cipher suites were recommended or secure.
Low- One or more cipher suites were weak.
Medium- One or more cipher suites was insecure.
