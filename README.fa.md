
# 🛡️ DNSniper | فایروال دامنه‌محور برای مقابله با تهدیدها

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.3.6--beta.1-brightgreen?logo=go&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Linux-blue?logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-success?logo=opensourceinitiative&logoColor=white" alt="License">
</p>

> نسخه انگلیسی: [README.md](README.md)

---

## 🚀 نصب سریع

```bash
bash <(curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh)
````

---

## 📖 DNSniper چیست؟

**DNSniper** یک فایروال دامنه‌محور نوشته‌شده با زبان Go است که به‌صورت خودکار دامنه‌های مشکوک یا سوء‌استفاده‌گر را شناسایی و آی‌پی‌های آن‌ها را از طریق iptables مسدود می‌کند. این ابزار برای مدیران سیستم و سرورها طراحی شده تا امنیت شبکه را به‌صورت هوشمند مدیریت کنند.

### ✨ امکانات کلیدی

* توسعه‌یافته با زبان Go (سبک و سریع)
* ذخیره تاریخچه دامنه‌ها و آی‌پی‌ها در SQLite
* تشخیص دامنه‌هایی که از CDN استفاده می‌کنند
* مدیریت قوانین فایروال به‌صورت خودکار (IPv4 و IPv6)
* برنامه‌ریزی اجرای خودکار با cron
* منوی تعاملی برای مدیریت و نصب/حذف آسان

### 🧰 پیش‌نیازها

* Go (برای ساخت دستی) یا استفاده از باینری آماده
* `iptables`, `ip6tables`
* `curl`
* `sqlite3`
* `cron`

---

## 💻 نحوه استفاده

```bash
dnsniper            # اجرای منوی تعاملی
sudo dnsniper run   # اجرای فوری و مسدودسازی آی‌پی‌ها
```

### گزینه‌های منو:

* اجرای سریع
* بروزرسانی لیست دامنه‌های مشکوک
* برنامه‌ریزی با کران
* تنظیم حداکثر آی‌پی برای هر دامنه
* اضافه/حذف دامنه
* مشاهده وضعیت و لاگ
* حذف قوانین و حذف کامل برنامه

---

## 📦 نسخه‌ها و دانلود

هر نسخه شامل فایل اجرایی متناسب با سیستم‌عامل، به‌همراه فایل `.sha256` برای بررسی صحت است.

---

## 💬 مشارکت

اگر لیستی از دامنه‌های مخرب دارید یا پیشنهادی برای بهبود DNSniper، خوشحال می‌شویم در گیت‌هاب ثبت کنید.

---

**از زیرساخت خود محافظت کنید — بگذارید DNSniper نگهبان دامنه‌ها باشد.**
