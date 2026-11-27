# CCTV Security Auditor X

منصة محلية لتدقيق أمان أجهزة كاميرات IP وDVR/NVR على الشبكات الخاصة.

## المزايا
- Web Dashboard عربية ومتجاوبة.
- وضع تشغيل عبر Terminal.
- عرض محولات الشبكة التي يتعرف عليها النظام.
- اكتشاف مضيفي IPv4 ضمن نطاق خاص بحد أقصى `/24`.
- فحص مجموعة منافذ شائعة لخدمات كاميرات المراقبة.
- فحص أولي لعناوين HTTP/HTTPS وترويسات الحماية.
- قراءة معلومات شهادة TLS عند نجاح التحقق.
- إرسال طلب RTSP `OPTIONS` غير المصادق على المنفذ 554.
- حفظ نتائج JSON داخل `reports/`.

## ما لا تدعيه الأداة
- بصمة المنفذ لا تثبت أن الجهاز كاميرا.
- نتائج الترويسات ليست إثباتاً لثغرة.
- لا يوجد تخمين كلمات مرور أو تجاوز مصادقة أو استخراج بث.
- لا يوجد استغلال تلقائي لثغرات CVE.
- لا يوجد تحكم مباشر بمحول USB من المتصفح؛ يعتمد ظهوره على تعريف النظام.

## المتطلبات
Python 3.10 أو أحدث.

### Windows PowerShell
```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

### Kali Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Android / Termux
```bash
pkg update
pkg install python
pip install -r requirements.txt
python main.py
```

ثم افتح `http://127.0.0.1:8000`.

## التشغيل عبر الشبكة المحلية
```bash
python main.py --host 0.0.0.0 --port 8000
```
افتح `http://IP-OF-HOST:8000` من جهاز آخر على الشبكة. لا تعرض المنفذ على الإنترنت العام.

## GitHub
```bash
git init
git add .
git commit -m "Initial release: CCTV Security Auditor X"
git branch -M main
git remote add origin https://github.com/Murtaza-omr/CCTV-Security-Auditor-X.git
git push -u origin main
```

## ملاحظات USB Wi-Fi
الأداة تعرض واجهات الشبكة التي يراها نظام التشغيل باستخدام `psutil`. دعم Monitor Mode أو ميزات خاصة بالمحول يعتمد على نظام التشغيل والتعريف والعتاد. توصيل محول USB إلى iPhone أو Android لا يعني أن النظام سيعرضه تلقائياً للتطبيق.

## حدود الفحص
يقتصر فحص CIDR على عناوين IPv4 الخاصة وبحد أقصى 256 عنواناً. استخدمه على شبكة تملكها أو لديك تصريح صريح بفحصها.
