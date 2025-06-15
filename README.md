# NmapLLM: Nmap Tarama ve Otomatik Güvenlik Analizi Aracı

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Nmap](https://img.shields.io/badge/Nmap-Required-orange.svg)
![Ollama](https://img.shields.io/badge/Ollama-Optional-yellow.svg)

NmapLLM, Nmap ile ağ taraması gerçekleştiren ve tarama sonuçlarını yerel bir LLM (Ollama) kullanarak analiz eden bir Python aracıdır. Bu araç, açık portlar ve servisler üzerinden sömürülebilirlik analizi yapar, sızma senaryoları önerir, savunma taktikleri sunar ve OPSEC ipuçları sağlar. **Yalnızca eğitim amaçlı ve yetkili sızma testleri için tasarlanmıştır.**

> **UYARI**: Bu araç yalnızca yetkili sistemlerde ve eğitim amaçlı kullanılmalıdır. Yetkisiz ağ taraması veya sızma testi yasa dışıdır ve ciddi yasal sonuçlar doğurabilir.

## Özellikler

- **Nmap Taraması**: Belirtilen IP veya domain üzerinde port taraması yapar (`-sV -T4` argümanlarıyla).
- **XML Çıktı**: Tarama sonuçlarını `last_scan.xml` dosyasına kaydeder.
- **LLM Analizi**: Ollama API'si ile tarama sonuçlarını analiz ederek:
  - Sömürülebilirlik analizi (CVEs, exploitler, PoC'ler)
  - Adım adım sızma senaryoları (Metasploit, manuel exploitler)
  - Post-exploitation taktikleri (lateral movement, persistence, veri sızdırma)
  - Savunma önerileri (IDS/IPS kuralları, sistem sertleştirme, yamalar)
  - OPSEC uyarıları (log temizleme, alarm tetiklememe)
- **Türkçe Çıktı**: Tüm analiz sonuçları tamamen Türkçe olarak sunulur.
- **Esnek Kullanım**: Ollama analizini atlama seçeneği sunar.

## Gereksinimler

- **Python 3.8+**
- **Nmap**: Sisteme kurulu olmalı ([Nmap İndir](https://nmap.org/download.html)).
- **Python Kütüphaneleri**:
  ```bash
  pip install python-nmap requests
  ```
- **Ollama** (Opsiyonel, analiz için):
  - [Ollama'yı indirin](https://ollama.com/download) ve kurun.
  - Desteklenen modeller: `mistral`, `llama2`, `gemma`, `deepseek`, `openhermes`, `phi`.
  - Ollama servisini başlatın:
    ```bash
    ollama serve
    ```

## Kurulum

1. Depoyu klonlayın:
   ```bash
   git clone https://github.com/<kullanici-adi>/NmapLLM.git
   cd NmapLLM
   ```

2. Gerekli Python kütüphanelerini yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

3. Nmap'in kurulu olduğundan emin olun:
   ```bash
   nmap --version
   ```

4. Ollama'yı (analiz için) kurun ve servisi başlatın:
   ```bash
   ollama serve
   ```

5. **Önemli Not**: Kodda `your_api(ollama serve)` olarak geçen kısımlar bir hata içerir. Bu ifadeleri `http://localhost:11434` ile değiştirmeniz gerekir. Aşağıdaki komutla dosyayı düzeltebilirsiniz:
   ```bash
   sed -i 's|your_api(ollama serve)|http://localhost:11434|g' NmapLLM.py
   ```

## Kullanım

1. Script'i çalıştırın:
   ```bash
   python NmapLLM.py
   ```

2. Hedef IP veya domain ile port aralığını girin:
   ```
   🎯 Hedef IP veya domain girin: 192.168.1.1
   🔍 Port aralığı girin (varsayılan: 22-443): 22-80
   ```

3. Tarama sonuçları konsolda görüntülenir ve `last_scan.xml` dosyasına kaydedilir.

4. LLM analizi yapmak isteyip istemediğiniz sorulur:
   ```
   ➤ LLM ile güvenlik analizi yapmak istiyor musunuz? (E/h): 
   ```
   - `E` veya Enter: Analizi başlatır.
   - `h`: Analizi atlar.

## Örnek Çıktı

```
============================================================
      NMAP Tarama ve Otomatik Güvenlik Analizi Aracı
============================================================
[*] Sistem gereksinimleri kontrol ediliyor...
[+] Nmap kurulu: Nmap version 7.94
[+] Ollama API çalışıyor. Mevcut modeller: mistral, llama2

🎯 Hedef IP veya domain girin: 192.168.1.1
🔍 Port aralığı girin (varsayılan: 22-443): 22-80

[*] Nmap taraması başlatılıyor: 192.168.1.1 (22-80 portları)...
[+] Tarama tamamlandı!
----------------------------------------------------
Host : 192.168.1.1 (example.local)
Durum : up
----------
Protokol : tcp
port : 22   durum : open   servis : ssh   sürüm : OpenSSH 8.2p1
port : 80   durum : open   servis : http  sürüm : Apache 2.4.41
[+] Tarama sonuçları 'last_scan.xml' dosyasına kaydedildi.

➤ LLM ile güvenlik analizi yapmak istiyor musunuz? (E/h): E
[*] Güvenlik analizi başlatılıyor...
============================================================
                    LLM ANALİZ SONUCU
============================================================
[Analiz sonucu Türkçe olarak burada görüntülenir]
```

## Güvenlik ve Etik Kullanım

- **Yetkili Kullanım**: Bu araç yalnızca izinli sistemlerde ve sızma testi anlaşmaları kapsamında kullanılmalıdır.
- **Eğitim Amaçlı**: NmapLLM, siber güvenlik eğitimi ve savunma amaçlı analizler için tasarlanmıştır.
- **Yasal Uyarı**: Yetkisiz ağ taraması veya sömürü faaliyetleri yasa dışıdır. Kullanıcı, tüm yasal sorumluluğu üstlenir.
- **Veri Güvenliği**: Tarama sonuçları (`last_scan.xml`) hassas bilgiler içerebilir. Bu dosyaları güvenli bir şekilde saklayın ve GitHub'a yüklemeyin.

## Katkıda Bulunma

1. Depoyu fork edin.
2. Yeni bir branch oluşturun (`git checkout -b feature/yeni-ozellik`).
3. Değişikliklerinizi commit edin (`git commit -m "Yeni özellik eklendi"`).
4. Branch'i push edin (`git push origin feature/yeni-ozellik`).
5. Pull Request açın.

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

## İletişim

Sorularınız veya geri bildiriminiz için GitHub Issues üzerinden iletişime geçebilirsiniz.

---

*Bu araç, siber güvenlik farkındalığını artırmak ve yetkili sızma testleri için geliştirilmiştir. Sorumlu kullanım için teşekkür ederiz!*
