# 🛡️ IOCs Intelligence
โปรเจกต์สำหรับตรวจสอบ IP, Domain และ Hash เพื่อวิเคราะห์ภัยคุกคาม (IOCs) โดยเชื่อมต่อกับ VirusTotal API และ AbuseIPDB และ Malwarebazaar

## ✨ Features
* **Search:** ตรวจสอบข้อมูล IOCs ได้ทันที
* **Cache System:** มีระบบเก็บข้อมูลในฐานข้อมูล 24 ชั่วโมงเพื่อประหยัด API
* **History:** บันทึกประวัติการค้นหาสำหรับผู้ใช้ที่ล็อกอิน

## 🛠️ How to run locally
1. ติดตั้ง Library: `pip install -r requirements.txt`
2. ตั้งค่าไฟล์ `.env` สำหรับ API Keys
3. รันโปรเจกต์: `uvicorn app:app --reload`