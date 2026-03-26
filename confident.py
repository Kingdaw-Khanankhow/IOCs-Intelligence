def confidence(ioc_type, details):
    """
    ฟังก์ชันคำนวณระดับความเชื่อมั่น (Confidence Score) 
    โดยใช้หลักการ Normalization และ Weighted Sum
    """
    norm = {}
    weights = {}
    is_any_malicious = False
    
    bazaar = details.get("malwarebazaar", {})
    vt = details.get("virustotal", {})
    abuse = details.get("abuseipdb", {})

    # 2. แยกคำนวณตามประเภทของ IOC
    
    # กรณีที่ 1: Hash (ถ่วงน้ำหนัก Bazaar 50% และ VT 50%)
    if ioc_type == "hash":
        # MalwareBazaar
        if bazaar.get("status") == "success":
            norm["bazaar"] = 100.0 if bazaar.get("found") else 0.0
            weights["bazaar"] = 0.5
            if bazaar.get("found"): 
                is_any_malicious = True

        # VirusTotal
        if vt.get("status") == "success":
            m_count = vt.get("malicious", 0)
            t_count = vt.get("total", 0)
            
            if m_count > 5: # เกณฑ์: ถ้าเกิน 5 ค่ายถือว่าอันตรายสูง
                norm["vt"] = 100.0
                is_any_malicious = True
            elif m_count > 0:
                # ป้องกันการหารด้วย 0 โดยเช็ค t_count
                norm["vt"] = (m_count / t_count * 100) if t_count > 0 else 0.0
                is_any_malicious = True
            else:
                norm["vt"] = 0.0
            weights["vt"] = 0.5

    # กรณีที่ 2: IP Address (ถ่วงน้ำหนัก VT 50% และ AbuseIPDB 50%)
    elif ioc_type == "ip":
        # VirusTotal
        if vt.get("status") == "success":
            t_count = vt.get("total", 0)
            m_count = vt.get("malicious", 0)
            norm["vt"] = (m_count / t_count * 100) if t_count > 0 else 0.0
            weights["vt"] = 0.5
            if m_count > 0: 
                is_any_malicious = True

        # AbuseIPDB
        if abuse.get("status") == "success":
            # รับค่า Confidence Score มาตรงๆ (0-100)
            score = float(abuse.get("abuse_score", 0))
            norm["abuse"] = score
            weights["abuse"] = 0.5
            if score > 0: 
                is_any_malicious = True

    # กรณีที่ 3: Domain (ใช้ค่าจาก VT เป็นหลัก 100%)
    elif ioc_type == "domain":
        if vt.get("status") == "success":
            t_count = vt.get("total", 0)
            m_count = vt.get("malicious", 0)
            norm["vt"] = (m_count / t_count * 100) if t_count > 0 else 0.0
            weights["vt"] = 1.0 
            if m_count > 0: 
                is_any_malicious = True

    # 3. สรุปคะแนน (Final Score Calculation)
    # ถ้าไม่มีน้ำหนัก หรือ ตรวจไม่เจอความอันตรายเลย ให้คืนค่า 0
    if not weights or not is_any_malicious:
        return 0.0, norm

    # คำนวณแบบ Weighted Sum
    # สูตร: Sum(คะแนนแต่ละแหล่ง * ค่าน้ำหนักแต่ละแหล่ง) / ผลรวมค่าน้ำหนัก
    weighted_sum = sum(norm[k] * weights[k] for k in norm if k in weights)
    total_weight = sum(weights[k] for k in norm if k in weights)
    
    final_score = weighted_sum / total_weight if total_weight > 0 else 0.0
   
    return round(final_score, 2), norm

def get_likelihood_score(final_score):
    """
    จัดกลุ่มระดับความรุนแรงตามช่วงคะแนน
    """
    if final_score >= 80:
        return 3, "High"     # 🔴 สีแดง
    elif final_score >= 21:
        return 2, "Medium"   # 🟡 สีเหลือง
    elif final_score > 0:
        return 1, "Low"      # 🟢 สีเขียว
    else:
        return 0, "Clean"    # 🟢 สีเขียว