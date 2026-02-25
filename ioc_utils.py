from ioc_finder import find_iocs
import socket

def get_ip_from_domain(domain):
    try:
        # socket หา IP
        return socket.gethostbyname(domain)
    except:
        return None

def identify_and_clean_ioc(user_input):
    """
    ioc-finder กรอง IoCs IP, Domain, SHA256 
    """
    # 1. กรอง IoCs
    iocs = find_iocs(user_input)

    # 2. ตรวจสอบ IP
    if iocs.get('ipv4s'):
        return "ip", iocs['ipv4s'][0]

    # 3. ตรวจสอบ Hash (SHA256)
    if iocs.get('sha256s'):
        return "hash", iocs['sha256s'][0]
    
    if iocs.get('md5s') or iocs.get('sha1s'):
        return "unknown", None

    # 4. ตรวจสอบ Domain 
    if iocs.get('domains'):
        return "domain", iocs['domains'][0]

    return "unknown", None
