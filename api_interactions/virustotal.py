import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("virus_total_api_key")

def check_vt(ioc_type, value):
    if not VT_API_KEY:
        print("DEBUG ERROR:NO API Key")
        return {"status": "error", "message": "API Key missing"}

    mapping = {
        "ip": "ip_addresses",
        "domain": "domains",
        "hash": "files"
    }
    
    endpoint = mapping.get(ioc_type)
    if not endpoint:
        return {"status": "error", "message": f"Unsupported IOC type: {ioc_type}"}

    url = f"https://www.virustotal.com/api/v3/{endpoint}/{value}"
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            result = response.json()
            attr = result.get('data', {}).get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            
            # attributes
            data_out = {
                "status": "success",
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "clean": stats.get('harmless', 0) + stats.get('undetected', 0),
                "total": sum(stats.values()) if stats else 0,
                "reputation": attr.get('reputation', 0),
                "last_analysis_date": attr.get('last_analysis_date'),
                "provider": attr.get('as_owner', 'Unknown'),
                "tags": attr.get('tags', []),
                "names": attr.get('names', []),                
                "last_analysis_results": attr.get('last_analysis_results', {})
            }

            # Domain, IP
            if ioc_type in ["domain", "ip"]:
                data_out["categories"] = list(set(attr.get('categories', {}).values()))
                if ioc_type == "ip":
                    data_out["country"] = attr.get('country', 'Unknown')

            # Hash
            if ioc_type == "hash":
                raw_size = attr.get('size', 0)
                data_out["size"] = f"{raw_size / (1024*1024):.2f} MB" if raw_size > 0 else "0 MB"
                data_out["type_description"] = attr.get('type_description', 'Unknown')
                data_out["sha256"] = attr.get('sha256')
                data_out["signature"] = attr.get('magic', 'N/A')
                
            return data_out

        elif response.status_code == 404:
            return {"status": "success", "malicious": 0, "total": 0, "message": "No record found"}
        else:
            return {"status": "error", "message": f"API Error: {response.status_code}"}

    except Exception as e:
        return {"status": "error", "message": f"Connection Error: {str(e)}"}