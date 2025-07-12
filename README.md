# EML Extractor

📧 **EML Extractor**: E-posta (.eml) dosyalarındaki içerikleri ve ekleri kolayca çıkarmanızı sağlayan, kullanıcı dostu bir masaüstü uygulamadır.

## Özellikler
- Birden fazla .eml dosyasını toplu seçip işleyebilme
- E-posta gövdesini (metin ve HTML) ayrı ayrı kaydetme
- Tüm ekleri orijinal isimleriyle ve güvenli şekilde çıkarma
- E-posta başlıklarını (From, To, Subject, Date, vb.) ayrı dosyada saklama
- Modern ve sade Türkçe arayüz
- İşlem durumu ve log takibi

## Kurulum

### 1. Python ile Çalıştırmak için
1. Python 3.8–3.11 arası bir sürüm kurulu olmalı.
2. Gerekli paketleri yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
3. Uygulamayı başlatın:
   ```bash
   python eml_extractor_v2.py
   ```

### 2. Exe Olarak Derlemek için
1. Python 3.8–3.11 ve PyInstaller kurulu olmalı.
2. Exe oluşturmak için:
   ```bash
   pyinstaller eml_extractor_v2.py --name=EML_Extractor --noconfirm --clean --windowed
   ```
   veya
   ```bash
   pyinstaller EML_Extractor.spec
   ```
3. `dist/EML_Extractor/` klasörü altında çalıştırılabilir dosyanız oluşur.

## Kullanım
1. Uygulamayı başlatın.
2. "EML Dosyalarını Seç" ile bir veya birden fazla .eml dosyası seçin.
3. "Çıktı Dizini Seç" ile çıktıların kaydedileceği klasörü belirleyin.
4. Çıkarma seçeneklerini işaretleyin (ekler, içerik, başlıklar).
5. "ÇIKARMAYI BAŞLAT" butonuna tıklayın.
6. Sonuçlar, seçtiğiniz klasörde her e-posta için ayrı klasörlerde saklanır.

## Notlar
- Python 3.12 ve sonrası ile exe derlemesi için PyInstaller henüz tam uyumlu olmayabilir. Python 3.11 veya altı önerilir.
- EML dosyalarınızda özel karakterler varsa, dosya isimleri otomatik olarak güvenli hale getirilir.

## Lisans
MIT

---

🔗 Powered by [FSK Labs](https://fsklabs.com)
