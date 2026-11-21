"""Arabic UI strings and right-to-left layout (plan: Arabic/English with RTL).

`tr()` is applied inside the shared widget helpers (labels, buttons, cards,
headers, tabs, nav), so most fixed UI text is translated in one place. Text
built at run time (counts, values, tool output) stays as is. Terminology
follows docs/PROJECT_RULES.md: "target" is هدف, never "victim".
"""

from __future__ import annotations

_language = "en"

AR: dict[str, str] = {
    # navigation and chrome
    "Dashboard": "لوحة التحكم",
    "New Case": "قضية جديدة",
    "Case Workspace": "مساحة القضية",
    "INVESTIGATE": "التحقيق",
    "Made by: Omar Al-Olayan": "صُنع بواسطة: عمر العليان",
    "Modules": "الوحدات",
    "Run Console": "وحدة التشغيل",
    "Tool Library": "مكتبة الأدوات",
    "OUTPUT": "المخرجات",
    "Reports": "التقارير",
    "Settings": "الإعدادات",
    "Design System": "نظام التصميم",
    "No active case": "لا توجد قضية نشطة",
    "Minimize": "تصغير",
    "Maximize": "تكبير",
    "Restore": "استعادة",
    "Close": "إغلاق",
    # common buttons
    "New case": "قضية جديدة",
    "Open modules": "فتح الوحدات",
    "Analyze": "تحليل",
    "Clear": "مسح",
    "View all": "عرض الكل",
    "Show recent": "الأحدث فقط",
    "Back": "رجوع",
    "Create case": "إنشاء القضية",
    "Browse…": "استعراض…",
    "Add evidence": "إضافة دليل",
    "Export": "تصدير",
    "Close case": "إغلاق القضية",
    "Reopen case": "إعادة فتح القضية",
    "Delete case": "حذف القضية",
    "Run module": "تشغيل وحدة",
    "Add target": "إضافة هدف",
    "Save notes": "حفظ الملاحظات",
    "Go to dashboard": "الذهاب للوحة التحكم",
    "Cancel": "إلغاء",
    "Continue": "متابعة",
    "Send and run": "إرسال وتشغيل",
    "Run active check": "تشغيل الفحص النشط",
    "Mark verified": "تأكيد",
    "Keep as lead": "إبقاء كخيط",
    "Reject": "رفض",
    "Stop": "إيقاف",
    "Run again": "تشغيل مجدداً",
    "Open findings in case": "عرض النتائج في القضية",
    "Open run folder": "فتح مجلد التشغيل",
    "Reload catalog": "إعادة تحميل الكتالوج",
    "Details": "التفاصيل",
    "Open": "فتح",
    "Open official site": "فتح الموقع الرسمي",
    "Open settings": "فتح الإعدادات",
    "Clear filters": "مسح عوامل التصفية",
    "Open source only": "مفتوحة المصدر فقط",
    "Verify hashes": "التحقق من البصمات",
    "Open evidence folder": "فتح مجلد الأدلة",
    "Open reports folder": "فتح مجلد التقارير",
    "Change…": "تغيير…",
    "Add key": "إضافة مفتاح",
    "Replace": "استبدال",
    "Remove": "إزالة",
    "Check": "فحص",
    "Clear cache": "مسح الذاكرة المؤقتة",
    "Open folder": "فتح المجلد",
    "Show all modules": "عرض كل الوحدات",
    "Enable": "تفعيل",
    "Save key": "حفظ المفتاح",
    # headings
    "Good morning": "صباح الخير",
    "Good afternoon": "مساء الخير",
    "Good evening": "مساء الخير",
    "Recent cases": "القضايا الأخيرة",
    "Activity": "النشاط",
    "Open cases": "القضايا المفتوحة",
    "Leads to verify": "خيوط بانتظار التحقق",
    "Verified findings": "نتائج مؤكدة",
    "External lookups (7d)": "استعلامات خارجية (7 أيام)",
    "Every case starts with a purpose and an authorized scope.": "كل قضية تبدأ بغرض ونطاق مصرّح به.",
    "Scope": "النطاق",
    "Targets": "الأهداف",
    "Review": "المراجعة",
    "Case name": "اسم القضية",
    "Purpose": "الغرض",
    "Authorized scope": "النطاق المصرّح به",
    "Allowed lookup modes": "أنماط الاستعلام المسموحة",
    "First target": "الهدف الأول",
    "Case summary": "ملخص القضية",
    "Local": "محلي",
    "External · passive": "خارجي · سلبي",
    "Active (requires authorization)": "نشط (يتطلب تصريحاً)",
    "Username": "اسم مستخدم",
    "Email": "بريد إلكتروني",
    "Phone": "هاتف",
    "IP address": "عنوان IP",
    "Domain": "نطاق",
    "URL": "رابط",
    "Image / file": "صورة / ملف",
    "Other": "أخرى",
    "Auto": "تلقائي",
    "IP": "IP",
    "File": "ملف",
    "Findings": "النتائج",
    "Evidence": "الأدلة",
    "Notes": "الملاحظات",
    "Activity log": "سجل النشاط",
    "Leads": "الخيوط",
    "Evidence files": "ملفات الأدلة",
    "Finding detail": "تفاصيل النتيجة",
    "Verification note": "ملاحظة التحقق",
    "Tool detail": "تفاصيل الأداة",
    "Summary": "الملخص",
    "Run log": "سجل التشغيل",
    "Console": "الطرفية",
    "Table": "جدول",
    "Export report": "تصدير تقرير",
    "Preview": "معاينة",
    "Format": "الصيغة",
    "Include": "تضمين",
    "Redaction": "الإخفاء",
    "Save to": "الحفظ في",
    "Privacy & storage": "الخصوصية والتخزين",
    "Active modules": "الوحدات النشطة",
    "API keys": "مفاتيح API",
    "Execution": "التنفيذ",
    "Appearance": "المظهر",
    "Theme": "السمة",
    "Results view": "عرض النتائج",
    "Language": "اللغة",
    "Dark": "داكن",
    "Any": "الكل",
    "External": "خارجي",
    "Active": "نشط",
    "All": "الكل",
    "Verified": "مؤكد",
    "Rejected": "مرفوض",
    "Module": "الوحدة",
    "Tool library": "مكتبة الأدوات",
    "Search tools": "البحث في الأدوات",
    "Search modules": "البحث في الوحدات",
    "Filter findings": "تصفية النتائج",
    "Usernames": "أسماء المستخدمين",
    "Domains": "النطاقات",
    "Images": "الصور",
    "Archives": "الأرشيف",
    "Web research": "البحث على الويب",
    "General": "عام",
    "Pick a module. Labels show where your data goes before anything runs.":
        "اختر وحدة. توضّح الوسوم أين تذهب بياناتك قبل أي تشغيل.",
    "Privacy first. Everything here is stored on this computer.": "الخصوصية أولاً. كل ما هنا محفوظ على هذا الجهاز.",
    "No case open": "لا توجد قضية مفتوحة",
    "No cases yet": "لا توجد قضايا بعد",
    "No findings yet": "لا توجد نتائج بعد",
    "No run yet": "لم يتم أي تشغيل بعد",
    "No evidence files": "لا توجد ملفات أدلة",
    "No tools match": "لا توجد أدوات مطابقة",
    "No findings match": "لا توجد نتائج مطابقة",
    "Nothing matches": "لا شيء مطابق",
    "No results to show": "لا توجد نتائج لعرضها",
    "No activity yet": "لا يوجد نشاط بعد",
    "No targets yet": "لا توجد أهداف بعد",
    "Try another word, status or module, or clear the filters to see every finding.":
        "جرّب كلمة أو حالة أو وحدة أخرى، أو امسح عوامل التصفية لعرض كل النتائج.",
    "Try another word or filter, or clear them to see every module and link.":
        "جرّب كلمة أو عامل تصفية آخر، أو امسحها لعرض كل الوحدات والروابط.",
    "Results appear here when the run finishes. If it saved nothing, the console says why.":
        "تظهر النتائج هنا عند انتهاء التشغيل. إن لم يُحفظ شيء فالطرفية توضّح السبب.",
    "Open a case from Recent cases, or create one. Its targets, consents and runs show up here.":
        "افتح قضية من القضايا الأخيرة أو أنشئ واحدة. تظهر هنا أهدافها وموافقاتها وعمليات تشغيلها.",
    "Pick a type and enter a username, email, phone, IP, domain or URL above. Modules run on targets.":
        "اختر النوع وأدخل اسم مستخدم أو بريداً أو هاتفاً أو IP أو نطاقاً أو رابطاً في الأعلى. الوحدات تعمل على الأهداف.",
    # busy states
    "Reloading…": "جارٍ إعادة التحميل…",
    "Checking…": "جارٍ الفحص…",
    "Adding…": "جارٍ الإضافة…",
    # detail panels (key/value rows)
    "ID": "المعرّف",
    "Created": "أُنشئت",
    "Modes": "الأنماط",
    "Retention": "الاحتفاظ",
    "Source": "المصدر",
    "Collected": "وقت الجمع",
    "Confidence": "الثقة",
    "Result": "النتيجة",
    "Network": "الشبكة",
    "Run": "التشغيل",
    "Category": "الفئة",
    "License": "الرخصة",
    "Open source": "مفتوح المصدر",
    "API key": "مفتاح API",
    "Runs as": "يعمل كـ",
    "Location": "الموقع",
    "Limits": "الحدود",
    "Reviewed": "رُوجعت",
    "Data sent": "البيانات المرسلة",
    # tags
    "Passive": "سلبي",
    # consent
    "This lookup sends data outside your computer": "هذا الاستعلام يرسل بيانات خارج جهازك",
    "Active check: this touches the target's systems": "فحص نشط: هذا يتصل بأنظمة الهدف",
    "Sent to": "تُرسل إلى",
    "Mode": "النمط",
    "Case scope": "نطاق القضية",
    "Don't ask again for this module in this case.": "لا تسألني مجدداً عن هذه الوحدة في هذه القضية.",
    "I own this target or have written authorization to test it.": "أملك هذا الهدف أو لدي تصريح مكتوب بفحصه.",
    "Open a case first": "افتح قضية أولاً",
    # case map
    "Map": "الخريطة",
    "Open map": "فتح الخريطة",
    "Search the board": "ابحث في اللوحة",
    "Sources": "المصادر",
    "Uncertain": "غير محسوم",
    "Info": "معلومة",
    "Hide rejected": "إخفاء المرفوض",
    "Focus": "تركيز",
    "1 hop": "قفزة واحدة",
    "2 hops": "قفزتان",
    "High": "عالية",
    "Medium": "متوسطة",
    "Low": "منخفضة",
    "Add note": "إضافة ملاحظة",
    "Re-layout": "إعادة الترتيب",
    "Fit": "ملاءمة",
    "Export PNG…": "تصدير PNG…",
    "Export SVG…": "تصدير SVG…",
    "Redact contacts and IPs": "إخفاء جهات الاتصال وعناوين IP",
    "Connections are leads until verified.": "الروابط خيوط حتى يتم التحقق منها.",
    "Both findings verified — the link itself is still a lead": "النتيجتان مؤكدتان — والرابط نفسه ما زال خيطاً",
    "Low confidence": "ثقة منخفضة",
    "Analyst string": "خيط المحلل",
    "red outline = active module": "الإطار الأحمر = وحدة نشطة",
    "Nothing to map yet": "لا شيء لرسمه بعد",
    "Add a target and run a module to see findings, sources and evidence as cards here, "
    "or add a sticky note to start a board.":
        "أضف هدفاً وشغّل وحدة لترى النتائج والمصادر والأدلة كبطاقات هنا، أو أضف ملاحظة لاصقة لتبدأ لوحة.",
    "This case is closed: notes and strings are read-only. You can still arrange and pin cards.":
        "هذه القضية مغلقة: الملاحظات والخيوط للقراءة فقط. ما زال بإمكانك ترتيب البطاقات وتثبيتها.",
    "Board": "اللوحة",
    "Click a card to see its detail. Drag a card to move it; drag from its pin to another card to "
    "connect them. Right-click for more.":
        "انقر بطاقة لترى تفاصيلها. اسحب البطاقة لتحريكها، واسحب من دبوسها إلى بطاقة أخرى لربطهما. "
        "انقر بالزر الأيمن للمزيد.",
    "Sticky note": "ملاحظة لاصقة",
    "Note": "ملاحظة",
    "Delete note": "حذف الملاحظة",
    "Analyst connection": "رابط المحلل",
    "Delete connection": "حذف الرابط",
    "Verify hash": "تحقق من البصمة",
    "Card": "بطاقة",
    "Case": "القضية",
    "Target": "الهدف",
    "Evidence file": "ملف دليل",
    "Shared value": "قيمة مشتركة",
    "Type": "النوع",
    "Connected": "مرتبطة",
    "Saved": "حُفظت",
    "Read-only while the case is closed": "للقراءة فقط ما دامت القضية مغلقة",
    "Pin in place": "تثبيت في مكانها",
    "Unpin": "إلغاء التثبيت",
    "Unpin all": "إلغاء تثبيت الكل",
    "Focus here": "التركيز هنا",
    "Edit note": "تعديل الملاحظة",
    "Add note here": "إضافة ملاحظة هنا",
    "Fit board": "ملاءمة اللوحة",
}


#: Status words (StatusDot): kept apart because "Open" is also a button.
STATUS_AR = {
    "Lead": "خيط", "Verified": "مؤكد", "Rejected": "مرفوض", "Uncertain": "غير محسوم", "Info": "معلومة",
    "Open": "مفتوحة", "Closed": "مغلقة", "Found": "موجود", "No findings yet": "لا نتائج بعد",
    "All verified": "كلها مؤكدة", "Installed": "مثبتة", "Not installed": "غير مثبتة",
    "Not integrated": "غير مربوطة", "Disabled": "معطلة",
    "Built in": "مدمجة", "Web API": "واجهة ويب", "Opens browser": "تفتح المتصفح", "Needs key": "تحتاج مفتاحاً",
}


def set_language(language: str | None) -> None:
    global _language
    _language = "ar" if language == "ar" else "en"


def language() -> str:
    return _language


def is_rtl() -> bool:
    return _language == "ar"


def tr(text: str) -> str:
    if _language != "ar" or not text:
        return text
    return AR.get(text, text)


def tr_status(text: str) -> str:
    if _language != "ar" or not text:
        return text
    return STATUS_AR.get(text, text)
