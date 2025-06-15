import subprocess
import requests  
import nmap
import xml.etree.ElementTree as ET
import io
import sys
import time

def scan_target(target_ip, port_range='22-443'):
    """Performs nmap scan and returns both raw XML and parsed data"""
    print(f"\n[*] Nmap taraması başlatılıyor: {target_ip} ({port_range} portları)...")
    
    try:
        nm = nmap.PortScanner()
        
        # Perform scan with -sV and -T4 arguments
        print("[*] Tarama çalıştırılıyor, lütfen bekleyin...")
        nm.scan(target_ip, port_range, arguments='-sV -T4')
        print("[+] Tarama tamamlandı!\n")
        
        # Print scan results for user visibility
        host_found = False
        for host in nm.all_hosts():
            host_found = True
            print('----------------------------------------------------')
            print(f'Host : {host} ({nm[host].hostname()})')
            print(f'Durum : {nm[host].state()}')
            
            for proto in nm[host].all_protocols():
                print('----------')
                print(f'Protokol : {proto}')
                
                ports = list(nm[host][proto].keys())
                ports.sort()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', '')
                    version = nm[host][proto][port].get('product', '') + ' ' + nm[host][proto][port].get('version', '')
                    print(f'port : {port}\tdurum : {state}\tservis : {service}\tsürüm : {version}')
        
        if not host_found:
            print("[!] Tarama sonuçlarında herhangi bir host bulunamadı!")
            return None, None
        
        # Get the XML as string or bytes and handle conversion
        xml_data = nm.get_nmap_last_output()
        
        # Ensure XML data is string, not bytes
        if isinstance(xml_data, bytes):
            xml_data = xml_data.decode('utf-8', errors='replace')
        
        # Parse the scan results into the format needed for analysis
        scan_data = {"host": target_ip, "ports": []}
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = list(nm[host][proto].keys())
                for port in ports:
                    port_info = nm[host][proto][port]
                    scan_data["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info["state"],
                        "service": port_info.get("name", ""),
                        "version": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                    })
        
        return xml_data, scan_data
    
    except nmap.PortScannerError as e:
        print(f"[!] Nmap tarama hatası: {e}")
        print("[!] 'pip install python-nmap' ile kütüphaneyi yüklediğinizden ve nmap'in sisteminizde kurulu olduğundan emin olun.")
        return None, None
    except Exception as e:
        print(f"[!] Beklenmeyen hata: {e}")
        return None, None

def analiz_yap(scan_data):
    """Yerel Ollama API'si kullanarak tarama verisini analiz eder."""
    if scan_data is None or "ports" not in scan_data or not scan_data["ports"]:
        print("[!] Analiz için geçerli tarama verisi bulunamadı!")
        return None
    
    print("\n[*] LLM analizi hazırlanıyor...")
    
    # Burada prompt'a dil belirtmek için daha güçlü bir yönlendirme ekliyoruz
    prompt = f"""
ÖNEMLİ: Bu analizin sonucu TAMAMEN TÜRKÇE olmalıdır. Tüm yanıtını Türkçe olarak hazırla.

Sen ileri düzey bir siber güvenlik uzmanısın ve portlardan sızma konusunda en tecrübeli hacker sensin. Elinde aşağıdaki Nmap taraması sonucu var:
Hedef IP: {scan_data.get("host")}
Aşağıdaki açık portlar ve servisler listelenmiştir:
"""
    for port in scan_data.get("ports", []):
        prompt += (
            f"- Port: {port['port']}/{port['protocol']} | "
            f"Durum: {port['state']} | "
            f"Servis: {port['service']} | "
            f"Sürüm: {port['version']}\n"
        )
    prompt += """
Bu veriler ışığında SADECE TÜRKÇE olarak:
1. Her port için sömürülebilirlik analizi yap (CVEs, exploitler, PoC'ler).
2. Adım adım sızma senaryoları oluştur (Metasploit, manual exploit, bypass teknikleri).
3. Post-exploitation taktikleri ekle (lateral movement, persistence, data exfil).
4. Savunma önerileri sun (IDS/IPS kuralları, hardening, yamalar).
5. OPSEC uyarıları ver (log temizleme, alarm tetiklememe taktikleri).

UYARI: Yanıtın tamamen Türkçe dilinde olmalıdır. İngilizce kullanma! Teknik terimlerin Türkçe karşılıklarını veya açıklamalarını kullan.
"""
    
    try:
        print("[*] Yerel Ollama API'sine bağlanılıyor (your_api(ollama serve))...")
        print("[*] İstek gönderiliyor, yanıt bekleniyor...")
        
        # Ollama modelleri kontrol edelim
        models_response = requests.get('your_api(ollama serve)/api/tags', timeout=5)
        models = []
        if models_response.status_code == 200:
            models = [m.get('name', '').lower() for m in models_response.json().get('models', [])]
        
        # Varsayılan model
        model = "mistral"
        
        # Eğer mistral yüklü değilse alternatif modeller deneyelim
        if not any('mistral' in m for m in models):
            for alt_model in ["llama2", "gemma", "deepseek", "openhermes", "phi"]:
                if any(alt_model in m for m in models):
                    model = next(m for m in models if alt_model in m)
                    print(f"[*] Mistral yerine {model} modeli kullanılıyor...")
                    break
        
        print(f"[*] Kullanılan model: {model}")
        
        # Modele Türkçe çıktı verebilmesi için system prompt'u ekliyoruz
        system_prompt = "Sen Türkçe konuşan bir siber güvenlik uzmanısın. Tüm yanıtlarını Türkçe dilinde vermelisin."
        
        response = requests.post(
            'your_api(ollama serve)/api/generate',
            json={
                'model': model,
                'prompt': prompt,
                'system': system_prompt,  # System prompt ekliyoruz
                'stream': False,
                'options': {
                    'temperature': 0.3,
                    'num_predict': 1024
                }
            },
            timeout=120
        )
        
        if response.status_code == 200:
            print("[+] Analiz başarıyla tamamlandı!")
            return response.json().get('response')
        else:
            print(f"[!] API hata kodu: {response.status_code}")
            print(f"[!] API yanıtı: {response.text}")
            
            # Hata detaylarını görmeye çalışalım
            try:
                error_details = response.json()
                print(f"[!] Hata detayları: {error_details}")
            except:
                pass
                
            return None
        
    except requests.exceptions.ConnectionError as e:
        print("[!] Ollama API'sine bağlanılamadı. Ollama servisinin çalıştığından emin olun:")
        print("    - Ollama kurulumunu kontrol edin: https://ollama.com/download")
        print("    - Terminal/komut isteminde 'ollama serve' komutunu çalıştırın")
        print(f"[!] Bağlantı hatası: {e}")
        return None
    except requests.exceptions.Timeout:
        print("[!] Ollama API yanıt vermedi (timeout) - Alternatif yöntem deneniyor...")
        
        # Timeout durumunda komut satırı aracıyla deneme
        try:
            import subprocess
            print("[*] Komut satırından Ollama çalıştırılıyor...")
            
            # System prompt'u da ekleyelim
            full_prompt = f"{system_prompt}\n\n{prompt}"
            cmd = ["ollama", "run", model, full_prompt]
            
            # Subprocess timeout'u 60 saniye
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("[+] Analiz başarıyla tamamlandı! (komut satırı yöntemi)")
                return result.stdout
            else:
                print(f"[!] Komut satırı hatası: {result.stderr}")
                return None
        except Exception as subprocess_error:
            print(f"[!] Komut satırı yöntemi de başarısız oldu: {subprocess_error}")
            
            # Son çare: curl kullanmayı deneyelim
            try:
                import json
                curl_cmd = [
                    "curl", "-X", "POST", "your_api(ollama serve)/api/generate",
                    "-d", json.dumps({
                        "model": model,
                        "prompt": prompt,
                        "system": system_prompt,  # System prompt ekliyoruz
                        "stream": False,
                        "options": {"temperature": 0.3}
                    })
                ]
                curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=60)
                
                if curl_result.returncode == 0:
                    print("[+] Analiz başarıyla tamamlandı! (curl yöntemi)")
                    response_json = json.loads(curl_result.stdout)
                    return response_json.get('response')
                else:
                    print("[!] Curl ile istek gönderme başarısız oldu.")
            except Exception as curl_error:
                print(f"[!] Curl yöntemi de başarısız oldu: {curl_error}")
                
        return None
    except Exception as e:
        print(f"[!] Analiz hatası: {e}")
        return None

def check_requirements():
    """Gerekli bağımlılıkların kontrolünü yapar"""
    requirements_met = True
    
    print("\n[*] Sistem gereksinimleri kontrol ediliyor...")
    
    # Nmap kontrolü
    try:
        result = subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            version = result.stdout.split('\n')[0]
            print(f"[+] Nmap kurulu: {version}")
        else:
            print("[!] Nmap kurulu değil veya PATH'te bulunamadı!")
            requirements_met = False
    except FileNotFoundError:
        print("[!] Nmap kurulu değil! https://nmap.org/download.html adresinden indirip kurabilirsiniz.")
        requirements_met = False
    
    # Ollama API kontrolü  
    try:
        response = requests.get('your_api(ollama serve)/api/tags', timeout=5)
        if response.status_code == 200:
            models = response.json().get('models', [])
            models_list = [m.get('name', '') for m in models]
            print(f"[+] Ollama API çalışıyor. Mevcut modeller: {', '.join(models_list) if models_list else 'Hiç model yüklü değil'}")
        else:
            print(f"[!] Ollama API yanıt verdi fakat hata kodu döndü: {response.status_code}")
            requirements_met = False
    except requests.exceptions.ConnectionError:
        print("[!] Ollama API'sine bağlanılamadı (localhost:11434).")
        print("    - Ollama servisini başlatmak için terminal/komut isteminde 'ollama serve' çalıştırın.")
        print("    - Alternatif olarak, analiz kısmını atlamak için ilerleyebilirsiniz.")
        # İsteğe bağlı hale getirildi, requirements_met = False kaldırıldı
    except Exception as e:
        print(f"[!] Ollama API kontrolünde hata: {e}")
        print("    - Analiz kısmını geçerek devam edebilirsiniz.")
        # İsteğe bağlı hale getirildi, requirements_met = False kaldırıldı
        
    return requirements_met

if __name__ == "__main__":
    print("=" * 60)
    print("      NMAP Tarama ve Otomatik Güvenlik Analizi Aracı")
    print("=" * 60)
    
    # Gereksinimleri kontrol et
    if not check_requirements():
        print("\n[!] Bazı gereksinimler karşılanmadı. Yukarıdaki hataları düzeltin ve tekrar deneyin.")
        sys.exit(1)
    
    # Kullanıcıdan hedef bilgileri al
    target_ip = input("\n🎯 Hedef IP veya domain girin: ").strip()
    
    if not target_ip:
        print("[!] Geçerli bir hedef girilmedi. Program sonlandırılıyor.")
        sys.exit(1)
    
    port_range = input("🔍 Port aralığı girin (varsayılan: 22-443): ").strip()
    if not port_range:
        port_range = "22-443"
        
    print("\n[*] Tarama başlatılıyor, lütfen bekleyin...")
    
    # Taramayı gerçekleştir
    xml_data, scan_data = scan_target(target_ip, port_range)
    
    if xml_data and scan_data:
        # Tarama sonuçlarını kaydet
        try:
            with open("last_scan.xml", "w", encoding="utf-8") as f:
                f.write(xml_data)
            print(f"[+] Tarama sonuçları 'last_scan.xml' dosyasına kaydedildi.")
        except Exception as e:
            print(f"[!] XML dosyası kaydedilirken hata: {e}")
            print("[*] XML dosyasını binary modda kaydetmeyi deniyorum...")
            try:
                # Binary olarak kaydetmeyi dene
                with open("last_scan.xml", "wb") as f:
                    if isinstance(xml_data, str):
                        f.write(xml_data.encode('utf-8'))
                    else:
                        f.write(xml_data)
                print(f"[+] Tarama sonuçları 'last_scan.xml' dosyasına başarıyla kaydedildi.")
            except Exception as e2:
                print(f"[!] XML dosyası binary modda kaydedilirken de hata: {e2}")
        
        # Kullanıcıya analiz yapmak isteyip istemediğini sor
        analiz_secim = input("\n➤ LLM ile güvenlik analizi yapmak istiyor musunuz? (E/h): ").strip().lower()
        
        if analiz_secim == "" or analiz_secim.startswith("e"):
            print("\n[*] Güvenlik analizi başlatılıyor...")
            analiz_sonucu = analiz_yap(scan_data)
            
            if analiz_sonucu:
                print("\n" + "=" * 60)
                print("                    LLM ANALİZ SONUCU")
                print("=" * 60)
                print(analiz_sonucu)
            else:
                print("\n[!] Analiz gerçekleştirilemedi veya sonuç alınamadı.")
        else:
            print("\n[*] Analiz işlemi atlandı.")
    else:
        print("\n[!] Tarama başarısız oldu veya sonuç alınamadı.")
    
    print("\n[*] Program sonlandırılıyor...")
