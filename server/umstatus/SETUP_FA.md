# راه‌اندازی سرویس umstatus روی میکروتیک (RouterOS 7.23.2)

این سرویس داخل کانتینر روی خود روتر اجرا می‌شه. اپ اندروید یوزر و پسورد رو بهش می‌فرسته و حجم و روز باقی‌مونده رو می‌گیره.

- آدرس عمومی: `https://91.207.18.201:8443/v1/status`
- آی‌پی کانتینر: `172.17.0.2`، گیت‌وی (خود روتر): `172.17.0.1`
- دو پسورد جدید لازم دارید. دو تا رشته‌ی تصادفی و طولانی بسازید:
  - **API_PASS**: پسورد اکانت فقط‌خواندنی که سرویس با اون به روتر وصل می‌شه
  - **CERT_PASS**: رمز فایل کلید گواهی

---

## ۱. پوشه‌ی سرویس

```
/file add name=umstatus type=directory
```

## ۲. اکانت فقط‌خواندنی برای سرویس

```
/user group add name=umstatus policy=read,api,rest-api,web,sensitive
/user add name=umstatus group=umstatus address=172.17.0.2/32 password="API_PASS"
```

- `sensitive` لازمه تا سرویس بتونه پسورد کاربرها رو برای مقایسه بخونه.
- `address=172.17.0.2/32` باعث می‌شه این اکانت فقط از داخل کانتینر قابل استفاده باشه.
- REST در این نسخه علاوه بر `rest-api` به `api` و `web` هم نیاز داره؛ هیچ‌کدوم اجازه‌ی تغییر (`write`) نمی‌دن.

## ۳. گواهی TLS (روی خود روتر ساخته می‌شه)

```
/certificate add name=umstatus common-name=91.207.18.201 subject-alt-name=IP:91.207.18.201 key-size=2048 days-valid=3650
/certificate sign umstatus
/certificate export-certificate umstatus type=pem export-passphrase="CERT_PASS" file-name=umstatus/umstatus
/file print where name~"umstatus"
```

دستور آخر باید `umstatus/umstatus.crt` و `umstatus/umstatus.key` رو نشون بده.

## ۴. آپلود فایل‌ها

1. فایل `config.json` رو باز کنید و `CHANGE_ME_API_PASSWORD` رو با **API_PASS** و `CHANGE_ME_CERT_PASSPHRASE` رو با **CERT_PASS** عوض کنید.
2. فایل‌های `umstatus.py` و `config.json` رو با Winbox (بخش Files) داخل پوشه‌ی `umstatus` بکشید.

## ۵. شبکه‌ی کانتینر

```
/interface veth add name=veth-umstatus address=172.17.0.2/24 gateway=172.17.0.1
/interface bridge add name=br-containers
/ip address add address=172.17.0.1/24 interface=br-containers
/interface bridge port add bridge=br-containers interface=veth-umstatus
```

## ۶. فایروال و NAT

```
/ip firewall nat add chain=dstnat dst-address=91.207.18.201 protocol=tcp dst-port=8443 action=dst-nat to-addresses=172.17.0.2 to-ports=8443 comment=umstatus
/ip firewall filter add chain=input src-address=172.17.0.2 protocol=tcp dst-port=64 action=accept comment=umstatus place-before=0
/ip firewall filter add chain=forward dst-address=172.17.0.2 protocol=tcp dst-port=8443 action=accept comment=umstatus place-before=0
```

اگه هیچ رول فیلتری ندارید، `place-before=0` خطا می‌ده. در این صورت دو دستور آخر رو بدون اون بزنید.

## ۷. ساخت و اجرای کانتینر

```
/container config set registry-url=https://registry-1.docker.io tmpdir=container-tmp
/container mounts add list=umstatus src=/umstatus dst=/app
/container add remote-image=library/python:3.12-alpine interface=veth-umstatus root-dir=containers/umstatus mountlists=umstatus cmd="python3 /app/umstatus.py serve" logging=yes start-on-boot=yes comment=umstatus
```

دانلود و استخراج ایمیج (حدود ۵۰ مگابایت) چند دقیقه طول می‌کشه. با دستور زیر وضعیت رو چک کنید تا از `extracting` به `stopped` برسه:

```
/container print
```

بعد کانتینر رو استارت کنید و لاگ رو ببینید:

```
/container start [find comment=umstatus]
/log print where topics~"container"
```

اگه همه‌چیز درست باشه، تو لاگ خط `umstatus listening on 0.0.0.0:8443` دیده می‌شه.

## ۸. تست داخلی (خیلی مهم)

```
/container shell [find comment=umstatus]
```

داخل shell بزنید:

```
python3 /app/umstatus.py selftest 25g8282
exit
```

خروجی این تست رو برای من بفرستید. پسورد کاربر توش نمایش داده نمی‌شه و فقط تعداد کاراکترهاش رو نشون می‌ده.

## ۹. تست از بیرون (cmd ویندوز)

```
curl -k -X POST https://91.207.18.201:8443/v1/status -H "Content-Type: application/json" -d "{\"username\":\"25g8282\",\"password\":\"PASSWORD\"}"
```

## ۱۰. امنیت (پیشنهادی)

سرویس `www` روی پورت 64 الان برای کل اینترنت بازه. بهتره فقط به کانتینر و IPهای خودتون محدود بشه. **قبل از زدن این دستور، IP خودتون رو جای `YOUR_IP` بذارید**، وگرنه دسترسی WebFig خودتون قطع می‌شه:

```
/ip service set www address=172.17.0.0/24,YOUR_IP
```

---

## خطاهای احتمالی

| خطا | علت |
|---|---|
| `router_unavailable` (503) | سرویس به REST روتر نمی‌رسه: رول input فایروال یا محدودیت `address` سرویس www |
| `server_config` (503) | اکانت umstatus پالیسی `sensitive` نداره |
| `invalid_credentials` (401) | یوزر یا پسورد اشتباهه |
| `too_many_attempts` (429) | بیش از ۱۰ بار پسورد اشتباه از یک IP در ۱۵ دقیقه |
