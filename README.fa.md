# DNSniper | مقابله با تهدیدات مبتنی بر DNS

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-brightgreen?logo=bash&logoColor=white" alt="نسخه">
  <img src="https://img.shields.io/badge/سکو-Linux-blue?logo=linux&logoColor=white" alt="سکو">
  <img src="https://img.shields.io/badge/مجوز-MIT-success?logo=opensourceinitiative&logoColor=white" alt="مجوز">
  <img src="https://img.shields.io/github/stars/MahdiGraph/DNSniper?style=social" alt="ستاره‌ها">
  <img src="https://img.shields.io/github/forks/MahdiGraph/DNSniper?style=social" alt="فورک‌ها">
</p>

---

## 📋 معرفی

**DNSniper** یک اسکریپت **بش** سبک است که برای مقابله با تهدیدات مبتنی بر DNS طراحی شده و:

* به‌صورت دوره‌ای فهرستی از دامنه‌های مشکوک را رزولوشن می‌کند
* IPهای به‌دست‌آمده را با `iptables` و `ip6tables` بلاک می‌کند
* آخرین N IP هر دامنه را در یک پایگاه‌داده SQLite ذخیره می‌کند
* در صورت تغییر IP جدید (نشانه CDN) هشدار می‌دهد
* منوی تعاملی برای مدیریت زمان‌بندی، محدودیت‌ها و دامنه‌ها دارد
* نصب یک‌خطی با `installer.sh` و پشتیبانی از توزیع‌های مهم لینوکس

### ✨ امکانات اصلی

* **پشتیبانی Dual-Stack**: IPv4 و IPv6
* **تشخیص CDN**: مقایسهٔ دو رزولوشن اخیر برای شناسایی تغییر IP
* **پایگاه‌داده SQLite**: ذخیرهٔ N رکورد آخر برای هر دامنه (قابل تنظیم)
* **قوانین ایمن فایروال**: اضافه‌سازی با کامنت `DNSniper` برای پاک‌سازی ساده
* **منوی تعاملی**: اجرا، به‌روزرسانی، زمان‌بندی، حداکثر IP، افزودن/حذف دامنه، نمایش وضعیت، پاک‌سازی، حذف کامل
* **کرون جاب خودکار**: اجرای منظم (`--run`)، قابل تنظیم از منو

### 🔧 پیش‌نیازها

* `bash`
* `iptables`, `ip6tables`
* `curl`
* `dnsutils` (برای `dig`)
* `sqlite3`
* `cron` یا `crontab`

**توزیع‌های پشتیبانی‌شده:** Debian/Ubuntu، CentOS/RHEL، Fedora

### 🚀 نصب سریع

```bash
curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash
```

### 💻 نحوهٔ استفاده

1. **حالت تعاملی**:

   ```bash
   dnsniper
   ```
2. **گزینه‌های منو**:

   * اجرای دستی، به‌روزرسانی پیش‌فرض، زمان‌بندی، حداکثر IP
   * افزودن/حذف دامنه، نمایش وضعیت، پاک‌سازی قوانین، حذف کامل

<p align="center">
  **با DNSniper سرورهای خود را امن نگه دارید!**
</p>
