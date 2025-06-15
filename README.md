# Nmap-LLM
Bu proje, Nmap tarama sonuçlarını analiz eden ve yerel çalışan bir LLM (büyük dil modeli) ile detaylı siber güvenlik değerlendirmesi sunan bir araçtır

```markdown
# 🛡️ NmapLLM – Nmap + LLM ile Otomatik Güvenlik Analizi

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Nmap](https://img.shields.io/badge/Nmap-Installed-success)
![Ollama](https://img.shields.io/badge/Ollama-Required-orange)
![LLM](https://img.shields.io/badge/LLM-Local-lightgrey)

## 📌 Proje Özeti

**NmapLLM**, ağ taraması sonucunda elde edilen verileri yerel çalışan bir LLM (büyük dil modeli) ile analiz ederek Türkçe açıklamalar sunan bir güvenlik analiz aracıdır.

Bu araç, siber güvenlik uzmanlarının iş yükünü azaltmayı ve potansiyel açıklara dair hızlı değerlendirme yapabilmeyi hedefler.

## 🚀 Özellikler

- ✅ Nmap ile port ve servis taraması
- ✅ LLM (Ollama üzerinden) ile Türkçe açıklamalı güvenlik analizi
- ✅ Her port için:
  - Sömürülebilirlik değerlendirmesi (CVE, exploit, PoC)
  - Sızma senaryoları (Metasploit, bypass teknikleri)
  - Post-exploitation önerileri (kalıcılık, yanal hareket)
  - Savunma önlemleri (hardening, IDS/IPS)
  - OPSEC uyarıları (log temizleme, gizlilik)

## 📷 Ekran Görüntüsü

```

🎯 Hedef IP veya domain girin: 192.168.1.10
🔍 Port aralığı girin (varsayılan: 22-443):

\[\*] Tarama başlatılıyor...

\[\*] Güvenlik analizi başlatılıyor...
\[+] Analiz başarıyla tamamlandı!

➡️ Port 22/tcp (SSH): OpenSSH 7.9

* CVE-2018-15473 ile kullanıcı adı doğrulama bypass edilebilir.
* Metasploit modülü mevcuttur.
* Güçlü parola denemesi, ardından root yetki yükseltme önerilir.
* SSH root erişimi devre dışı bırakılmalı.

````

## 🔧 Gereksinimler

- [Python 3.x](https://www.python.org/)
- [Nmap](https://nmap.org/download.html) (CLI aracı olarak sistemde yüklü olmalı)
- Python bağımlılıkları:
  ```bash
  pip install python-nmap requests
````

* [Ollama](https://ollama.com/download) kurulu ve `ollama serve` komutu ile çalışır durumda olmalı
* En az bir yerel model yüklü olmalı (örnekler: `mistral`, `llama2`, `phi`)

## 🛠️ Kurulum

```bash
git clone https://github.com/kullaniciadi/NmapLLM.git
cd NmapLLM
pip install -r requirements.txt
```

> Not: `requirements.txt` yoksa şu iki kütüphane yeterlidir:
>
> ```bash
> pip install python-nmap requests
> ```

## ▶️ Kullanım

```bash
python3 NmapLLM.py
```

Komut satırında hedef IP ve port aralığını girmeniz istenir. Tarama tamamlandıktan sonra LLM tabanlı analiz başlar.

## 💡 Neden Bu Proje?

* 🧠 AI destekli güvenlik değerlendirmesi
* 🔍 Otomasyon ile hızlı analiz
* 🗣️ Tamamen Türkçe çıktı desteği
* 👨‍💻 Öğrenme ve portföy geliştirme için harika bir örnek

## 📄 Lisans

Bu proje MIT lisansı ile lisanslanmıştır.
