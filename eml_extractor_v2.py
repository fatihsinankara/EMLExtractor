import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import email
import os
import re
from pathlib import Path
import mimetypes

class EMLExtractor:
    def __init__(self, root):
        self.root = root
        self.root.title("EML Extractor - Email İçerik Çıkarıcı")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        self.eml_files = []
        self.output_dir = ""
        
        self.create_widgets()
    
    def create_widgets(self):
        # Ana frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0', padx=12, pady=12)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        title_label = tk.Label(main_frame, text="📧 EML Extractor", 
                              font=('Arial', 16, 'bold'), 
                              bg='#f0f0f0', fg='#2c3e50')
        title_label.pack(pady=(0, 10))
        
        # EML dosyalarını seçme bölümü
        eml_frame = tk.LabelFrame(main_frame, text="EML Dosyalarını Seç", 
                                 font=('Arial', 11, 'bold'), 
                                 bg='#f0f0f0', fg='#34495e', padx=6, pady=6)
        eml_frame.pack(fill=tk.X, pady=(0, 8))
        
        select_eml_btn = tk.Button(eml_frame, text="📁 EML Dosyalarını Seç", 
                                  command=self.select_eml_files,
                                  bg='#3498db', fg='white', 
                                  font=('Arial', 9, 'bold'),
                                  padx=12, pady=5)
        select_eml_btn.pack(side=tk.LEFT)
        
        self.eml_count_label = tk.Label(eml_frame, text="Seçilen dosya: 0", 
                                       bg='#f0f0f0', fg='#7f8c8d',
                                       font=('Arial', 9))
        self.eml_count_label.pack(side=tk.LEFT, padx=(12, 0))
        
        # Çıktı dizini seçme bölümü
        output_frame = tk.LabelFrame(main_frame, text="Çıktı Dizinini Seç", 
                                   font=('Arial', 11, 'bold'), 
                                   bg='#f0f0f0', fg='#34495e', padx=6, pady=6)
        output_frame.pack(fill=tk.X, pady=(0, 8))
        
        select_output_btn = tk.Button(output_frame, text="📂 Çıktı Dizini Seç", 
                                     command=self.select_output_dir,
                                     bg='#e67e22', fg='white', 
                                     font=('Arial', 9, 'bold'),
                                     padx=12, pady=5)
        select_output_btn.pack(side=tk.LEFT)
        
        self.output_dir_label = tk.Label(output_frame, text="Dizin seçilmedi", 
                                        bg='#f0f0f0', fg='#7f8c8d',
                                        font=('Arial', 9))
        self.output_dir_label.pack(side=tk.LEFT, padx=(12, 0))
        
        # Çıkarma seçenekleri
        options_frame = tk.LabelFrame(main_frame, text="Çıkarma Seçenekleri", 
                                    font=('Arial', 11, 'bold'), 
                                    bg='#f0f0f0', fg='#34495e', padx=6, pady=6)
        options_frame.pack(fill=tk.X, pady=(0, 8))
        
        self.extract_attachments = tk.BooleanVar(value=True)
        self.extract_body = tk.BooleanVar(value=True)
        self.extract_headers = tk.BooleanVar(value=True)
        
        tk.Checkbutton(options_frame, text="📎 Ekleri çıkar", 
                      variable=self.extract_attachments,
                      bg='#f0f0f0', font=('Arial', 9)).pack(anchor=tk.W, pady=(0, 1))
        tk.Checkbutton(options_frame, text="📄 Email içeriğini çıkar", 
                      variable=self.extract_body,
                      bg='#f0f0f0', font=('Arial', 9)).pack(anchor=tk.W, pady=(0, 1))
        tk.Checkbutton(options_frame, text="ℹ️ Email başlıklarını çıkar", 
                      variable=self.extract_headers,
                      bg='#f0f0f0', font=('Arial', 9)).pack(anchor=tk.W, pady=(0, 1))
        
        # Çıkarma butonu
        extract_btn = tk.Button(main_frame, text="🚀 ÇIKARMAYI BAŞLAT", 
                               command=self.extract_emails,
                               bg='#27ae60', fg='white', 
                               font=('Arial', 12, 'bold'),
                               padx=18, pady=8)
        extract_btn.pack(pady=10)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(0, 6))
        
        # Log alanı
        log_frame = tk.LabelFrame(main_frame, text="İşlem Durumu", 
                                font=('Arial', 11, 'bold'), 
                                bg='#f0f0f0', fg='#34495e')
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        
        self.log_text = tk.Text(log_frame, height=8, wrap=tk.WORD,
                               bg='#ecf0f1', fg='#2c3e50',
                               font=('Consolas', 9), bd=0, relief='flat')
        scrollbar = tk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3, pady=3)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=3)
        
        # Footer - FSK Labs
        footer_frame = tk.Frame(main_frame, bg='#f0f0f0')
        footer_frame.pack(fill=tk.X, pady=(0, 2))
        # FSK Labs linki
        fsk_label = tk.Label(footer_frame, text="🔗 Powered by FSK Labs", 
                            font=('Arial', 9, 'underline'), 
                            bg='#f0f0f0', fg='#3498db',
                            cursor='hand2')
        fsk_label.pack(side=tk.RIGHT, padx=(0, 2))
        fsk_label.bind("<Button-1>", lambda e: self.open_fsk_link())
    
    def log_message(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def open_fsk_link(self):
        import webbrowser
        webbrowser.open("https://fsklabs.com")
    
    def select_eml_files(self):
        files = filedialog.askopenfilenames(
            title="EML Dosyalarını Seç",
            filetypes=[("EML Files", "*.eml"), ("All Files", "*.*")]
        )
        if files:
            self.eml_files = list(files)
            self.eml_count_label.config(text=f"Seçilen dosya: {len(self.eml_files)}")
            self.log_message(f"✓ {len(self.eml_files)} EML dosyası seçildi")
    
    def select_output_dir(self):
        directory = filedialog.askdirectory(title="Çıktı Dizinini Seç")
        if directory:
            self.output_dir = directory
            short_path = directory if len(directory) < 50 else "..." + directory[-47:]
            self.output_dir_label.config(text=short_path)
            self.log_message(f"✓ Çıktı dizini seçildi: {directory}")
    
    def sanitize_filename(self, filename):
        # Geçersiz karakterleri temizle
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        filename = filename.strip()
        if len(filename) > 100:
            filename = filename[:100]
        return filename
    
    def extract_emails(self):
        if not self.eml_files:
            messagebox.showerror("Hata", "Lütfen en az bir EML dosyası seçin!")
            return
        
        if not self.output_dir:
            messagebox.showerror("Hata", "Lütfen çıktı dizini seçin!")
            return
        
        self.progress['maximum'] = len(self.eml_files)
        self.progress['value'] = 0
        
        self.log_message("🚀 Çıkarma işlemi başlatılıyor...")
        
        success_count = 0
        error_count = 0
        
        for i, eml_file in enumerate(self.eml_files):
            try:
                self.log_message(f"📧 İşleniyor ({i+1}/{len(self.eml_files)}): {os.path.basename(eml_file)}")
                self.process_eml_file(eml_file, i + 1)
                success_count += 1
                self.log_message(f"✅ Başarılı: {os.path.basename(eml_file)}")
            except Exception as e:
                error_count += 1
                self.log_message(f"❌ Hata: {os.path.basename(eml_file)} - {str(e)}")
            finally:
                # Progress bar'ı her durumda güncelle
                self.progress['value'] = i + 1
                self.root.update()
        
        # Final mesajları
        self.log_message("=" * 50)
        self.log_message(f"✅ İşlem tamamlandı!")
        self.log_message(f"📊 Başarılı: {success_count}, Hatalı: {error_count}, Toplam: {len(self.eml_files)}")
        
        if error_count > 0:
            messagebox.showwarning("Tamamlandı", f"İşlem tamamlandı!\n\nBaşarılı: {success_count}\nHatalı: {error_count}")
        else:
            messagebox.showinfo("Tamamlandı", f"Tüm dosyalar başarıyla işlendi! ({success_count} dosya)")
    
    def process_eml_file(self, eml_file, file_number):
        # Farklı encoding'leri dene
        encodings_to_try = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'utf-16']
        msg = None
        
        for encoding in encodings_to_try:
            try:
                with open(eml_file, 'r', encoding=encoding, errors='ignore') as f:
                    msg = email.message_from_file(f)
                    self.log_message(f"  ✅ Encoding başarılı: {encoding}")
                    break
            except Exception as e:
                continue
        
        if msg is None:
            # Son çare: binary mode'da aç
            try:
                with open(eml_file, 'rb') as f:
                    msg = email.message_from_bytes(f.read())
                self.log_message(f"  ✅ Binary mode ile açıldı")
            except Exception as e:
                raise Exception(f"Dosya hiçbir şekilde okunamadı: {str(e)}")
        
        # Dosya adını oluştur
        subject = msg.get('Subject', f'Email_{file_number}')
        if subject:
            # Subject'i decode et
            try:
                decoded_subject = email.header.decode_header(subject)
                subject = ''.join([
                    text.decode(charset) if isinstance(text, bytes) and charset 
                    else text if isinstance(text, str) 
                    else text.decode('utf-8', errors='ignore') if isinstance(text, bytes)
                    else str(text)
                    for text, charset in decoded_subject
                ])
            except:
                subject = f'Email_{file_number}'
        else:
            subject = f'Email_{file_number}'
            
        safe_subject = self.sanitize_filename(subject)
        
        # Her email için ayrı klasör oluştur
        email_folder = os.path.join(self.output_dir, f"{file_number:03d}_{safe_subject}")
        os.makedirs(email_folder, exist_ok=True)
        
        # Email başlıklarını çıkar
        if self.extract_headers.get():
            self.extract_email_headers(msg, email_folder)
        
        # Email içeriğini çıkar
        if self.extract_body.get():
            self.extract_email_body(msg, email_folder)
        
        # Ekleri çıkar
        if self.extract_attachments.get():
            self.extract_email_attachments(msg, email_folder)
    
    def extract_email_headers(self, msg, output_folder):
        headers_file = os.path.join(output_folder, "headers.txt")
        with open(headers_file, 'w', encoding='utf-8') as f:
            f.write("EMAIL BAŞLIKLARI\n")
            f.write("=" * 50 + "\n\n")
            
            important_headers = ['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Reply-To']
            
            for header in important_headers:
                value = msg.get(header, '')
                if value:
                    f.write(f"{header}: {value}\n")
            
            f.write("\nTÜM BAŞLIKLAR\n")
            f.write("=" * 50 + "\n\n")
            
            for key, value in msg.items():
                f.write(f"{key}: {value}\n")
    
    def extract_email_body(self, msg, output_folder):
        body_text = ""
        body_html = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text += payload.decode('utf-8', errors='ignore')
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html += payload.decode('utf-8', errors='ignore')
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                decoded_payload = payload.decode('utf-8', errors='ignore')
                if content_type == "text/plain":
                    body_text = decoded_payload
                elif content_type == "text/html":
                    body_html = decoded_payload
        
        # Metin içeriğini kaydet
        if body_text:
            text_file = os.path.join(output_folder, "body.txt")
            with open(text_file, 'w', encoding='utf-8') as f:
                f.write(body_text)
        
        # HTML içeriğini kaydet
        if body_html:
            html_file = os.path.join(output_folder, "body.html")
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(body_html)
    
    def extract_email_attachments(self, msg, output_folder):
        attachment_count = 0
        attachments_folder = os.path.join(output_folder, "attachments")
        
        for part in msg.walk():
            # Ek kontrolü için daha kapsamlı yaklaşım
            content_disposition = part.get_content_disposition()
            filename = part.get_filename()
            content_type = part.get_content_type()
            
            # Ek olabilecek durumları kontrol et
            is_attachment = False
            
            # 1. Content-Disposition: attachment
            if content_disposition == 'attachment':
                is_attachment = True
            
            # 2. Inline ama dosya adı var (bazı emailler böyle gönderir)
            elif content_disposition == 'inline' and filename:
                is_attachment = True
            
            # 3. Dosya adı var ve text/plain veya text/html değil
            elif filename and content_type not in ['text/plain', 'text/html']:
                is_attachment = True
            
            # 4. Multipart değil ve ana content type'ı binary/octet gibi ise
            elif (not part.is_multipart() and 
                  content_type in ['application/octet-stream', 'application/pdf', 
                                 'image/jpeg', 'image/png', 'image/gif', 
                                 'application/msword', 'application/vnd.ms-excel',
                                 'application/zip', 'application/x-zip-compressed']):
                is_attachment = True
                # Eğer dosya adı yoksa content type'tan oluştur
                if not filename:
                    extensions = {
                        'application/pdf': '.pdf',
                        'image/jpeg': '.jpg',
                        'image/png': '.png',
                        'image/gif': '.gif',
                        'application/msword': '.doc',
                        'application/vnd.ms-excel': '.xls',
                        'application/zip': '.zip',
                        'application/x-zip-compressed': '.zip',
                        'application/octet-stream': '.bin'
                    }
                    ext = extensions.get(content_type, '.bin')
                    filename = f"attachment_{attachment_count + 1}{ext}"
            
            if is_attachment and filename:
                try:
                    if not os.path.exists(attachments_folder):
                        os.makedirs(attachments_folder)
                    
                    safe_filename = self.sanitize_filename(filename)
                    filepath = os.path.join(attachments_folder, safe_filename)
                    
                    # Aynı isimde dosya varsa numaralandır
                    counter = 1
                    base_name, ext = os.path.splitext(safe_filename)
                    while os.path.exists(filepath):
                        safe_filename = f"{base_name}_{counter}{ext}"
                        filepath = os.path.join(attachments_folder, safe_filename)
                        counter += 1
                    
                    # Payload'ı al ve kaydet
                    payload = part.get_payload(decode=True)
                    if payload:
                        with open(filepath, 'wb') as f:
                            f.write(payload)
                        
                        attachment_count += 1
                        file_size = len(payload)
                        self.log_message(f"  📎 Ek kaydedildi: {safe_filename} ({file_size} bytes)")
                    else:
                        self.log_message(f"  ⚠️ Ek payload'ı boş: {filename}")
                        
                except Exception as e:
                    self.log_message(f"  ❌ Ek kaydetme hatası: {filename} - {str(e)}")
        
        if attachment_count > 0:
            self.log_message(f"  ✅ {attachment_count} ek çıkarıldı")
        else:
            self.log_message(f"  ℹ️ Bu emailde ek bulunamadı")

def main():
    root = tk.Tk()
    app = EMLExtractor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
