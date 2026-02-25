import requests
import os
from dotenv import load_dotenv

load_dotenv()
ABUSE_API_KEY = os.getenv("abuse_api_key")

def check_abuse(ip_address):
    """
    ตรวจสอบข้อมูล IP จาก AbuseIPDB
    """
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'verbose': True  
    }

    headers = {
        'Accept': 'application/json',
        'Key': ABUSE_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=15)
        
        if response.status_code == 200:
            data = response.json()['data']
            
            # Normalization
            confidence_score = data.get('abuseConfidenceScore', 0)
            
            total_reports = data.get('totalReports', 0)
            country = data.get('countryCode', 'N/A')
            isp = data.get('isp', 'N/A')
            domain = data.get('domain', 'N/A')
            last_reported = data.get('lastReportedAt', 'N/A')

            return {
                "status": "success",
                "abuse_score": confidence_score,  # % 
                "total_reports": total_reports,
                "country": country,
                "isp": isp,
                "domain": domain,
                "last_reported": last_reported
            }
        elif response.status_code == 401:
            return {"status": "error", "message": "Invalid API Key"}
        elif response.status_code == 429:
            return {"status": "error", "message": "Rate limit exceeded"}
        else:
            return {"status": "error", "message": f"AbuseIPDB Error: {response.status_code}"}

    except Exception as e:
        return {"status": "error", "message": str(e)}
