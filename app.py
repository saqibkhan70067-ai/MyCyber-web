import ipaddress
import re
from urllib.parse import unquote, urlparse
from flask import Flask, flash, redirect, render_template, request, url_for

app = Flask(__name__)
# سیکیورٹی کیز اور فلیکسیبل ٹیمپلیٹ ری لوڈنگ
app.secret_key = "mycyber-tool-dev-key-change-in-production"
app.config['TEMPLATES_AUTO_RELOAD'] = True

# ڈینجرس کی ورڈز جو ویب سائٹ ہیکنگ یا فشنگ کو پکڑتے ہیں
DANGEROUS_KEYWORDS = (
    "paypal", "secure-login", "update-account", "verify", 
    "banking", "signin", "wp-admin", "checkpoint"
)

@app.route('/')
def home():
    # یہ لائن فرنٹ اینڈ کے ۳۵۴ لائنوں والے ڈیزائن کو لائیو رینڈر کرے گی
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url', '').strip()
    if not url:
        flash("Please enter a valid URL to scan.", "warning")
        return redirect(url_for('home'))
    
    # یو آر ایل ویلیڈیشن اور سیکیورٹی چیکس کا بنیادی لاجک
    is_dangerous = False
    reasons = []
    
    try:
        parsed_url = urlparse(url)
        decoded_url = unquote(url).lower()
        
        # ۱. کی ورڈز چیک کرنا
        for keyword in DANGEROUS_KEYWORDS:
            if keyword in decoded_url:
                is_dangerous = True
                reasons.append(f"Dangerous keyword detected: '{keyword}'")
                
        # ۲. آئی پی ایڈریس چیک کرنا (اگر یو آر ایل میں ڈومین کی جگہ آئی پی ہو)
        hostname = parsed_url.hostname
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_dangerous = True
                reasons.append("URL uses a raw IP address instead of a domain name.")
            except ValueError:
                pass
                
    except Exception as e:
        flash(f"Error parsing URL: {str(e)}", "danger")
        return redirect(url_for('home'))
        
    return render_template('index.html', scan_result=True, url=url, is_dangerous=is_dangerous, reasons=reasons)

if __name__ == '__main__':
    app.run(debug=True)
    # ورسیل کو سرور ہینڈل کرنے کے لیے یہ لائن لازمی چاہیے
app = app