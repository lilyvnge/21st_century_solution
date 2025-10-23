from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from functools import wraps
import os
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import re
import requests
import whois
import dns.resolver
import json
import hashlib
import threading
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import socket
import subprocess
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
app.config['PGHOST'] = os.environ.get('PGHOST')
app.config['PGDATABASE'] = os.environ.get('PGDATABASE')
app.config['PGUSER'] = os.environ.get('PGUSER')
app.config['PGPASSWORD'] = os.environ.get('PGPASSWORD')
app.config['PGPORT'] = os.environ.get('PGPORT', 5432)
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT') or 'dev-salt-change-in-production'
app.config['SCAN_TIMEOUT'] = 10
app.config['MAX_REDIRECTS'] = 5

def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(
            host=app.config['PGHOST'],
            database=app.config['PGDATABASE'],
            user=app.config['PGUSER'],
            password=app.config['PGPASSWORD'],
            port=app.config['PGPORT']
        )
    return g.db

def init_db(db):
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'user',
            email_verified BOOLEAN DEFAULT FALSE,
            verification_token VARCHAR(255),
            reset_token VARCHAR(255),
            reset_token_expiry TIMESTAMP,
            created_at TIMESTAMP NOT NULL,
            last_login TIMESTAMP,
            profile_image VARCHAR(255),
            company VARCHAR(255),
            phone VARCHAR(50),
            title VARCHAR(255)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            session_token TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            ip_address TEXT,
            attempted_at TIMESTAMP NOT NULL,
            success BOOLEAN NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activities (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            activity_type TEXT NOT NULL,
            description TEXT,
            ip_address TEXT,
            performed_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            service_type TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            purchased_on TIMESTAMP NOT NULL,
            expires_on TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS support_tickets (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    cursor.execute('SELECT COUNT(*) as count FROM users')
    result = cursor.fetchone()
    if result['count'] == 0:
        hashed_password = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'changeme123'))
        cursor.execute(
            'INSERT INTO users (name, email, password_hash, role, email_verified, created_at) VALUES (%s, %s, %s, %s, %s, %s)',
            ('Admin User', 'admin@21centurysolutions.com', hashed_password, 'admin', True, datetime.now())
        )
        print("Default admin user created: admin@21centurysolutions.com / adminpassword")
    init_scan_results_table(db)
    db.commit()

def init_scan_results_table(db):
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id SERIAL PRIMARY KEY,
            user_id INT,
            tool_type VARCHAR(100) NOT NULL,
            target_url VARCHAR(500),
            scan_data JSON,
            results TEXT,
            risk_level VARCHAR(50),
            created_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    db.commit()

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def log_activity(user_id, activity_type, description, ip_address=None):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO user_activities (user_id, activity_type, description, ip_address, performed_at) VALUES (%s, %s, %s, %s, %s)',
            (user_id, activity_type, description, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")

def log_login_attempt(email, success, ip_address=None):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO login_attempts (email, ip_address, attempted_at, success) VALUES (%s, %s, %s, %s)',
            (email, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), success)
        )
        db.commit()
    except Exception as e:
        print(f"Error logging login attempt: {e}")

def is_brute_force(email, ip_address):
     try:
         db = get_db()
         cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
         cursor.execute(
             'SELECT COUNT(*) as count FROM login_attempts WHERE email = %s AND ip_address = %s AND success = FALSE AND attempted_at > %s',
             (email, ip_address, (datetime.now() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S'))
         )
         recent_failures = cursor.fetchone()
         return recent_failures['count'] >= 5 if recent_failures else False
     except Exception as e:
         print(f"Error checking brute force: {e}")
         return False

def generate_token():
    return str(uuid.uuid4())

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def safe_get(d, key, default=None):
    try:
        return d[key] if key in d else default
    except (KeyError, TypeError, IndexError):
        return default

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        try:
            db = get_db()
            cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                'SELECT role FROM users WHERE id = %s', (session['user_id'],)
            )
            user = cursor.fetchone()
            if user and safe_get(user, 'role') != 'admin':
                flash('Administrator access required.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        except Exception as e:
            flash('Database error. Please try again.', 'danger')
            return redirect(url_for('home'))
    return decorated_function

def safe_request(url, method='GET', data=None, headers=None, timeout=10):
    """Make safe HTTP requests with error handling"""
    try:
        if method.upper() == 'GET':
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        else:
            response = requests.post(url, data=data, timeout=timeout, verify=False, allow_redirects=True)
        return response
    except requests.RequestException as e:
        return None

def extract_forms(url):
    """Extract all forms from a webpage"""
    try:
        response = safe_request(url)
        if not response:
            return []
        
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                input_details = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', '')
                }
                form_details['inputs'].append(input_details)
            
            forms.append(form_details)
        
        return forms
    except Exception as e:
        print(f"Error extracting forms: {e}")
        return []

def scan_sql_injection(target_url):
    """Scan for SQL Injection vulnerabilities"""
    vulnerabilities = []
    payloads = [
        "'",
        "';",
        "' OR '1'='1",
        "' UNION SELECT 1,2,3--",
        "'; DROP TABLE users--",
        "' AND 1=1--",
        "' AND 1=2--"
    ]
    
    try:
        # Test URL parameters
        parsed_url = urlparse(target_url)
        if parsed_url.query:
            params = dict([p.split('=') for p in parsed_url.query.split('&') if '=' in p])
            for param in params:
                for payload in payloads:
                    test_url = target_url.replace(f"{param}={params[param]}", f"{param}={params[param]}{payload}")
                    response = safe_request(test_url)
                    
                    if response and any(error in response.text.lower() for error in [
                        'sql', 'syntax', 'mysql', 'ora', 'microsoft odbc', 'postgresql',
                        'warning', 'error', 'exception', 'database'
                    ]):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': 'Database error found in response'
                        })
                        break
        
        # Test forms
        forms = extract_forms(target_url)
        for form in forms:
            form_action = urljoin(target_url, form['action'])
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'password', 'search']:
                    for payload in payloads:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                data[field['name']] = payload if field['name'] == input_field['name'] else 'test'
                        
                        response = safe_request(form_action, method=form['method'], data=data)
                        
                        if response and any(error in response.text.lower() for error in [
                            'sql', 'syntax', 'mysql', 'ora', 'microsoft odbc', 'postgresql',
                            'warning', 'error', 'exception', 'database'
                        ]):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'parameter': input_field['name'],
                                'payload': payload,
                                'url': form_action,
                                'method': form['method'],
                                'evidence': 'Database error found in response'
                            })
                            break
        
        return vulnerabilities
    
    except Exception as e:
        print(f"SQL Injection scan error: {e}")
        return []

def scan_xss_vulnerabilities(target_url):
    """Scan for Cross-Site Scripting (XSS) vulnerabilities"""
    vulnerabilities = []
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')"
    ]
    
    try:
        # Test URL parameters
        parsed_url = urlparse(target_url)
        if parsed_url.query:
            params = dict([p.split('=') for p in parsed_url.query.split('&') if '=' in p])
            for param in params:
                for payload in payloads:
                    test_url = target_url.replace(f"{param}={params[param]}", f"{param}={payload}")
                    response = safe_request(test_url)
                    
                    if response and payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': 'Payload reflected in response without sanitization'
                        })
        
        # Test forms
        forms = extract_forms(target_url)
        for form in forms:
            form_action = urljoin(target_url, form['action'])
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'password', 'search', 'textarea']:
                    for payload in payloads:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                data[field['name']] = payload if field['name'] == input_field['name'] else 'test'
                        
                        response = safe_request(form_action, method=form['method'], data=data)
                        
                        if response and payload in response.text:
                            vulnerabilities.append({
                                'type': 'XSS',
                                'parameter': input_field['name'],
                                'payload': payload,
                                'url': form_action,
                                'method': form['method'],
                                'evidence': 'Payload reflected in response without sanitization'
                            })
        
        return vulnerabilities
    
    except Exception as e:
        print(f"XSS scan error: {e}")
        return []

def scan_csrf_vulnerabilities(target_url):
    """Scan for Cross-Site Request Forgery (CSRF) vulnerabilities"""
    vulnerabilities = []
    
    try:
        forms = extract_forms(target_url)
        
        for form in forms:
            if form['method'] == 'POST':
                has_csrf_token = False
                csrf_indicators = ['csrf', 'token', 'nonce', 'authenticity']
                
                for input_field in form['inputs']:
                    field_name = input_field['name'].lower() if input_field['name'] else ''
                    if any(indicator in field_name for indicator in csrf_indicators):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    vulnerabilities.append({
                        'type': 'CSRF',
                        'form_action': urljoin(target_url, form['action']),
                        'method': form['method'],
                        'evidence': 'No CSRF token found in POST form',
                        'risk': 'Medium'
                    })
        
        return vulnerabilities
    
    except Exception as e:
        print(f"CSRF scan error: {e}")
        return []

def calculate_vulnerability_risk(vulnerabilities):
    """Calculate overall risk level based on vulnerabilities found"""
    if not vulnerabilities:
        return 'Low'
    
    high_severity = any(vuln['type'] in ['SQL Injection', 'XSS'] for vuln in vulnerabilities)
    medium_severity = any(vuln['type'] == 'CSRF' for vuln in vulnerabilities)
    
    if high_severity:
        return 'High'
    elif medium_severity:
        return 'Medium'
    else:
        return 'Low'

def is_valid_ip(target):
    """Validate if the target is a valid IP address or domain"""
    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Check if it's a valid domain name
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return True
        return False

def scan_port(target, port, timeout=2):
    """Scan a single port on the target"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return (port, result == 0)  # Return tuple directly
    except Exception as e:
        return (port, False)

def port_scanner_scan(target, ports, max_workers=50):
    """Perform port scanning on target with multiple threads"""
    open_ports = []
    
    try:
        # Resolve domain to IP if needed
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return [], f"Could not resolve hostname: {target}"
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(scan_port, target_ip, port): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                try:
                    port, is_open = future.result()  # Directly unpack the tuple
                    if is_open:
                        open_ports.append(port)
                except Exception as e:
                    print(f"Error scanning port: {e}")
                    continue
        
        return open_ports, None
        
    except Exception as e:
        return [], f"Error during port scanning: {str(e)}"

def get_service_name(port):
    """Get common service name for a port"""
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
        995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        27017: "MongoDB", 6379: "Redis"
    }
    return common_ports.get(port, "Unknown")

def ping_host(target, count=4):
    """Ping a host and return results"""
    try:
        # Determine the ping command based on the OS
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", str(count), target]
        else:
            cmd = ["ping", "-c", str(count), target]
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        return result.returncode == 0, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        return False, "", "Ping command timed out"
    except Exception as e:
        return False, "", f"Error executing ping: {str(e)}"

def traceroute_host(target, max_hops=30):
    """Perform traceroute to a host"""
    try:
        # Determine the traceroute command based on the OS
        if platform.system().lower() == "windows":
            cmd = ["tracert", "-h", str(max_hops), target]
        else:
            cmd = ["traceroute", "-m", str(max_hops), "-w", "1", target]
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        
        return result.returncode == 0, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        return False, "", "Traceroute command timed out"
    except Exception as e:
        return False, "", f"Error executing traceroute: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/cybersecurity')
def cybersecurity():
    return render_template('cybersecurity.html')

@app.route('/other_solutions')
def other_solutions():
    return render_template('other_solutions.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/network_security')
def network_security():
    return render_template('network_security.html')

@app.route('/endpoint_protection')
def endpoint_protection():
    return render_template('endpoint_protection.html')

@app.route('/cloud_security')
def cloud_security():
    return render_template('cloud_security.html')

@app.route('/threat_intelligence')
def threat_intelligence():
    return render_template('threat_intelligence.html')

@app.route('/incident_response')
def incident_response():
    return render_template('incident_response.html')

@app.route('/security_audits')
def security_audits():
    return render_template('security_audits.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember_me = 'remember_me' in request.form
        ip_address = request.remote_addr
        if is_brute_force(email, ip_address):
            flash('Too many failed login attempts. Please try again later.', 'danger')
            log_login_attempt(email, False, ip_address)
            return render_template('login.html')
        try:
            db = get_db()
            cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                'SELECT * FROM users WHERE email = %s', (email,)
            )
            user = cursor.fetchone()
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = safe_get(user, 'id')
                session['user_email'] = safe_get(user, 'email')
                session['user_name'] = safe_get(user, 'name')
                session['user_role'] = safe_get(user, 'role', 'user')
                cursor.execute(
                    'UPDATE users SET last_login = %s WHERE id = %s',
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), safe_get(user, 'id'))
                )
                if remember_me:
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(days=30)
                else:
                    session.permanent = False
                db.commit()
                log_activity(safe_get(user, 'id'), 'login', 'User logged in successfully', ip_address)
                log_login_attempt(email, True, ip_address)
                flash('Login successful!', 'success')
                if safe_get(user, 'role') == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('client_portal'))
            else:
                log_login_attempt(email, False, ip_address)
                flash('Invalid email or password.', 'danger')
        except Exception as e:
            flash('Database error. Please try again.', 'danger')
            print(f"Database error during login: {e}")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        company = request.form.get('company', '')
        if not validate_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('register.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash('Email already registered. Please login instead.', 'danger')
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(password)
        verification_token = generate_token()
        cursor.execute(
            'INSERT INTO users (name, email, password_hash, company, verification_token, created_at) VALUES (%s, %s, %s, %s, %s, %s)',
            (name, email, hashed_password, company, verification_token, datetime.now())
        )
        db.commit()
        verification_url = url_for('verify_email', token=verification_token, _external=True)
        print(f"Verification URL: {verification_url}")
        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT id, email FROM users WHERE verification_token = %s', (token,)
    )
    user = cursor.fetchone()
    if user:
        cursor.execute(
            'UPDATE users SET email_verified = TRUE, verification_token = NULL WHERE id = %s',
            (user['id'],)
        )
        db.commit()
        log_activity(user['id'], 'email_verification', 'User verified their email address')
        flash('Email verified successfully! You can now log in.', 'success')
    else:
        flash('Invalid verification token.', 'danger')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute(
            'SELECT id FROM users WHERE email = %s', (email,)
        )
        user = cursor.fetchone()
        if user:
            reset_token = generate_token()
            reset_token_expiry = datetime.now() + timedelta(hours=1)
            cursor.execute(
                'UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE id = %s',
                (reset_token, reset_token_expiry.strftime('%Y-%m-%d %H:%M:%S'), user['id'])
            )
            db.commit()
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            print(f"Password reset URL: {reset_url}")
            flash('Password reset instructions have been sent to your email.', 'success')
        else:
            flash('If that email address is in our system, we\'ve sent a password reset link to it.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT id, reset_token_expiry FROM users WHERE reset_token = %s', (token,)
    )
    user = cursor.fetchone()
    if not user or not user['reset_token_expiry']:
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('login'))
    expiry_str = str(user['reset_token_expiry'])
    try:
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S.%f')
    if datetime.now() > expiry:
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('reset_password.html', token=token)
        hashed_password = generate_password_hash(password)
        cursor.execute(
            'UPDATE users SET password_hash = %s, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = %s',
            (hashed_password, token)
        )
        db.commit()
        log_activity(user['id'], 'password_reset', 'User reset their password')
        flash('Password reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/client_portal')
@login_required
def client_portal():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM services WHERE user_id = %s', (session['user_id'],)
    )
    user_services = cursor.fetchall()
    return render_template('client_portal.html', services=user_services)

@app.route('/profile')
@login_required
def profile():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (session['user_id'],)
    )
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    name = request.form['name']
    email = request.form['email']
    company = request.form.get('company', '')
    phone = request.form.get('phone', '')
    title = request.form.get('title', '')
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT id FROM users WHERE email = %s AND id != %s', (email, session['user_id'])
    )
    existing_user = cursor.fetchone()
    if existing_user:
        flash('Email already taken by another account.', 'danger')
        return redirect(url_for('profile'))
    cursor.execute(
        'UPDATE users SET name = %s, email = %s, company = %s, phone = %s, title = %s WHERE id = %s',
        (name, email, company, phone, title, session['user_id'])
    )
    db.commit()
    session['user_name'] = name
    session['user_email'] = email
    log_activity(session['user_id'], 'profile_update', 'User updated their profile')
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'danger')
            return render_template('change_password.html')
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute(
            'SELECT password_hash FROM users WHERE id = %s', (session['user_id'],)
        )
        user = cursor.fetchone()
        if user and check_password_hash(user['password_hash'], current_password):
            hashed_password = generate_password_hash(new_password)
            cursor.execute(
                'UPDATE users SET password_hash = %s WHERE id = %s',
                (hashed_password, session['user_id'])
            )
            db.commit()
            log_activity(session['user_id'], 'password_change', 'User changed their password')
            flash('Password changed successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Current password is incorrect.', 'danger')
    return render_template('change_password.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('SELECT COUNT(*) as count FROM users')
    total_users = cursor.fetchone()['count']
    cursor.execute('SELECT COUNT(*) as count FROM users WHERE last_login > %s', 
                   ((datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S'),))
    total_active_users = cursor.fetchone()['count']
    cursor.execute('SELECT COUNT(*) as count FROM services')
    total_services = cursor.fetchone()['count']
    cursor.execute("SELECT COUNT(*) as count FROM support_tickets WHERE status = 'open'")
    open_tickets = cursor.fetchone()['count']
    cursor.execute('''
        SELECT ua.*, u.name, u.email 
        FROM user_activities ua 
        JOIN users u ON ua.user_id = u.id 
        ORDER BY ua.performed_at DESC 
        LIMIT 10
    ''')
    recent_activities = cursor.fetchall()
    cursor.execute('''
        SELECT name, email, created_at 
        FROM users 
        ORDER BY created_at DESC 
        LIMIT 5
    ''')
    recent_signups = cursor.fetchall()
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         total_active_users=total_active_users,
                         total_services=total_services,
                         open_tickets=open_tickets,
                         recent_activities=recent_activities,
                         recent_signups=recent_signups)

@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT id, name, email, role, email_verified, created_at, last_login FROM users ORDER BY created_at DESC'
    )
    users = cursor.fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )
    user = cursor.fetchone()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    cursor.execute(
        'SELECT * FROM services WHERE user_id = %s', (user_id,)
    )
    user_services = cursor.fetchall()
    cursor.execute(
        'SELECT * FROM user_activities WHERE user_id = %s ORDER BY performed_at DESC LIMIT 20', (user_id,)
    )
    user_activities = cursor.fetchall()
    cursor.execute(
        'SELECT * FROM support_tickets WHERE user_id = %s ORDER BY created_at DESC', (user_id,)
    )
    user_tickets = cursor.fetchall()
    return render_template('admin_user_detail.html', 
                         user=user,
                         services=user_services,
                         activities=user_activities,
                         tickets=user_tickets)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )
    user = cursor.fetchone()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        company = request.form.get('company', '')
        phone = request.form.get('phone', '')
        title = request.form.get('title', '')
        role = request.form.get('role', 'user')
        email_verified = 1 if 'email_verified' in request.form else 0
        if email != user['email']:
            cursor.execute(
                'SELECT id FROM users WHERE email = %s AND id != %s', (email, user_id)
            )
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Email already taken by another account.', 'danger')
                return redirect(url_for('admin_edit_user', user_id=user_id))
        cursor.execute(
            'UPDATE users SET name = %s, email = %s, company = %s, phone = %s, title = %s, role = %s, email_verified = %s WHERE id = %s',
            (name, email, company, phone, title, role, email_verified, user_id)
        )
        db.commit()
        log_activity(session['user_id'], 'admin_user_edit', f'Admin edited user {user_id}')
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )
    user = cursor.fetchone()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    cursor.execute('DELETE FROM user_activities WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM services WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM support_tickets WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    db.commit()
    log_activity(session['user_id'], 'admin_user_delete', f'Admin deleted user {user_id}')
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/impersonate')
@admin_required
def admin_impersonate_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot impersonate yourself.', 'danger')
        return redirect(url_for('admin_users'))
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )
    user = cursor.fetchone()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    session['original_admin_id'] = session['user_id']
    session['original_admin_name'] = session['user_name']
    session['original_admin_email'] = session['user_email']
    session['user_id'] = user['id']
    session['user_email'] = user['email']
    session['user_name'] = user['name']
    session['user_role'] = user['role']
    session['is_impersonating'] = True
    log_activity(session['original_admin_id'], 'admin_impersonate', f'Admin impersonated user {user_id}')
    flash(f'Now impersonating {user["name"]}.', 'info')
    return redirect(url_for('client_portal'))

@app.route('/admin/stop-impersonating')
def admin_stop_impersonating():
    if 'original_admin_id' not in session or not session.get('is_impersonating'):
        flash('Not currently impersonating any user.', 'warning')
        return redirect(url_for('home'))
    session['user_id'] = session['original_admin_id']
    session['user_email'] = session['original_admin_email']
    session['user_name'] = session['original_admin_name']
    session['user_role'] = 'admin'
    session.pop('original_admin_id', None)
    session.pop('original_admin_name', None)
    session.pop('original_admin_email', None)
    session.pop('is_impersonating', None)
    flash('Stopped impersonating. Welcome back!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/services')
@admin_required
def admin_services():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        SELECT s.*, u.name as user_name, u.email as user_email 
        FROM services s 
        JOIN users u ON s.user_id = u.id 
        ORDER BY s.purchased_on DESC
    ''')
    services = cursor.fetchall()
    return render_template('admin_services.html', services=services)

@app.route('/admin/tickets')
@admin_required
def admin_tickets():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        SELECT t.*, u.name as user_name, u.email as user_email 
        FROM support_tickets t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC
    ''')
    tickets = cursor.fetchall()
    return render_template('admin_tickets.html', tickets=tickets)

@app.route('/admin/ticket/<int:ticket_id>')
@admin_required
def admin_ticket_detail(ticket_id):
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        SELECT t.*, u.name as user_name, u.email as user_email 
        FROM support_tickets t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.id = %s
    ''', (ticket_id,))
    ticket = cursor.fetchone()
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('admin_tickets'))
    return render_template('admin_ticket_detail.html', ticket=ticket)

@app.route('/admin/ticket/<int:ticket_id>/update', methods=['POST'])
@admin_required
def admin_update_ticket(ticket_id):
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM support_tickets WHERE id = %s', (ticket_id,)
    )
    ticket = cursor.fetchone()
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('admin_tickets'))
    status = request.form['status']
    notes = request.form.get('notes', '')
    cursor.execute(
        'UPDATE support_tickets SET status = %s, updated_at = %s, notes = %s WHERE id = %s',
        (status, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), notes, ticket_id)
    )
    db.commit()
    log_activity(session['user_id'], 'admin_ticket_update', f'Admin updated ticket {ticket_id} to {status}')
    flash('Ticket updated successfully!', 'success')
    return redirect(url_for('admin_ticket_detail', ticket_id=ticket_id))

@app.route('/admin/activities')
@admin_required
def admin_activities():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        SELECT ua.*, u.name, u.email 
        FROM user_activities ua 
        JOIN users u ON ua.user_id = u.id 
        ORDER BY ua.performed_at DESC 
        LIMIT 100
    ''')
    activities = cursor.fetchall()
    return render_template('admin_activities.html', activities=activities)

@app.route('/admin/login-attempts')
@admin_required
def admin_login_attempts():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('''
        SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 100
    ''')
    attempts = cursor.fetchall()
    return render_template('admin_login_attempts.html', attempts=attempts)

@app.route('/initdb')
def init_database():
    try:
        db = get_db()
        init_db(db)
        return 'Database initialized successfully!'
    except Exception as e:
        return f'Error initializing database: {str(e)}'

@app.route('/tools/sqli_scanner', methods=['GET', 'POST'])
def sqli_scanner():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash('Please enter a URL', 'danger')
            return render_template('sqli_scanner.html')
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            flash('SQL Injection scan started. This may take a few moments...', 'info')
            
            # Perform SQL Injection scan
            vulnerabilities = scan_sql_injection(url)
            risk_level = calculate_vulnerability_risk(vulnerabilities)
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'sql_injection', url, json.dumps(vulnerabilities), 
                 f"Found {len(vulnerabilities)} SQL Injection vulnerabilities", 
                 risk_level, datetime.now())
            )
            db.commit()
            
            return render_template('sqli_scanner.html', 
                                 url=url, 
                                 vulnerabilities=vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True)
            
        except Exception as e:
            flash(f'Error during SQL Injection scan: {str(e)}', 'danger')
            print(f"SQL Injection scan error: {e}")
    
    return render_template('sqli_scanner.html')

@app.route('/tools/xss_scanner', methods=['GET', 'POST'])
def xss_scanner():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash('Please enter a URL', 'danger')
            return render_template('xss_scanner.html')
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            flash('XSS scan started. This may take a few moments...', 'info')
            
            # Perform XSS scan
            vulnerabilities = scan_xss_vulnerabilities(url)
            risk_level = calculate_vulnerability_risk(vulnerabilities)
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'xss', url, json.dumps(vulnerabilities), 
                 f"Found {len(vulnerabilities)} XSS vulnerabilities", 
                 risk_level, datetime.now())
            )
            db.commit()
            
            return render_template('xss_scanner.html', 
                                 url=url, 
                                 vulnerabilities=vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True)
            
        except Exception as e:
            flash(f'Error during XSS scan: {str(e)}', 'danger')
            print(f"XSS scan error: {e}")
    
    return render_template('xss_scanner.html')

@app.route('/tools/csrf_scanner', methods=['GET', 'POST'])
def csrf_scanner():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash('Please enter a URL', 'danger')
            return render_template('csrf_scanner.html')
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            flash('CSRF scan started. This may take a few moments...', 'info')
            
            # Perform CSRF scan
            vulnerabilities = scan_csrf_vulnerabilities(url)
            risk_level = calculate_vulnerability_risk(vulnerabilities)
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'csrf', url, json.dumps(vulnerabilities), 
                 f"Found {len(vulnerabilities)} CSRF vulnerabilities", 
                 risk_level, datetime.now())
            )
            db.commit()
            
            return render_template('csrf_scanner.html', 
                                 url=url, 
                                 vulnerabilities=vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True)
            
        except Exception as e:
            flash(f'Error during CSRF scan: {str(e)}', 'danger')
            print(f"CSRF scan error: {e}")
    
    return render_template('csrf_scanner.html')

@app.route('/tools/comprehensive_scan', methods=['GET', 'POST'])
def comprehensive_scan():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        scan_types = request.form.getlist('scan_types')
        
        if not url:
            flash('Please enter a URL', 'danger')
            return render_template('comprehensive_scan.html')
        
        if not scan_types:
            flash('Please select at least one scan type', 'danger')
            return render_template('comprehensive_scan.html')
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            flash('Comprehensive vulnerability scan started. This may take a few moments...', 'info')
            
            all_vulnerabilities = []
            
            if 'sql' in scan_types:
                all_vulnerabilities.extend(scan_sql_injection(url))
            
            if 'xss' in scan_types:
                all_vulnerabilities.extend(scan_xss_vulnerabilities(url))
            
            if 'csrf' in scan_types:
                all_vulnerabilities.extend(scan_csrf_vulnerabilities(url))
            
            risk_level = calculate_vulnerability_risk(all_vulnerabilities)
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'comprehensive_scan', url, json.dumps(all_vulnerabilities), 
                 f"Found {len(all_vulnerabilities)} vulnerabilities in comprehensive scan", 
                 risk_level, datetime.now())
            )
            db.commit()
            
            return render_template('comprehensive_scan.html', 
                                 url=url, 
                                 vulnerabilities=all_vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True,
                                 scan_types=scan_types)
            
        except Exception as e:
            flash(f'Error during comprehensive scan: {str(e)}', 'danger')
            print(f"Comprehensive scan error: {e}")
    
    return render_template('comprehensive_scan.html')

@app.route('/tools/port_scanner', methods=['GET', 'POST'])
def port_scanner():
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        port_range = request.form.get('port_range', 'common')
        custom_ports = request.form.get('custom_ports', '').strip()
        
        if not target:
            flash('Please enter a target IP or domain', 'danger')
            return render_template('port_scanner.html')
        
        if not is_valid_ip(target):
            flash('Please enter a valid IP address or domain name', 'danger')
            return render_template('port_scanner.html')
        
        try:
            # Determine which ports to scan
            if port_range == 'common':
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 27017, 6379]
            elif port_range == 'custom' and custom_ports:
                try:
                    ports = []
                    for port_str in custom_ports.split(','):
                        port_str = port_str.strip()
                        if '-' in port_str:
                            start, end = map(int, port_str.split('-'))
                            ports.extend(range(start, end + 1))
                        else:
                            ports.append(int(port_str))
                    ports = list(set(ports))  # Remove duplicates
                    if len(ports) > 100:
                        flash('Too many ports specified. Maximum 100 ports allowed.', 'warning')
                        ports = ports[:100]
                except ValueError:
                    flash('Invalid port format. Use commas and/or ranges (e.g., 80,443 or 1-100)', 'danger')
                    return render_template('port_scanner.html')
            else:
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 27017, 6379]
            
            flash(f'Port scan started for {target}. Scanning {len(ports)} ports...', 'info')
            
            # Perform port scan
            open_ports, error = port_scanner_scan(target, ports)
            
            if error:
                flash(f'Scan error: {error}', 'danger')
                return render_template('port_scanner.html')
            
            # Prepare results
            port_results = []
            for port in open_ports:
                port_results.append({
                    'port': port,
                    'service': get_service_name(port),
                    'status': 'Open'
                })
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'port_scanner', target, json.dumps(port_results), 
                 f"Found {len(open_ports)} open ports on {target}", 
                 'Medium' if len(open_ports) > 0 else 'Low', datetime.now())
            )
            db.commit()
            
            return render_template('port_scanner.html', 
                                 target=target,
                                 port_results=port_results,
                                 total_ports=len(ports),
                                 scan_completed=True)
            
        except Exception as e:
            flash(f'Error during port scan: {str(e)}', 'danger')
            print(f"Port scan error: {e}")
    
    return render_template('port_scanner.html')

@app.route('/tools/network_diagnostics', methods=['GET', 'POST'])
def network_diagnostics():
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        diagnostic_type = request.form.get('diagnostic_type', 'ping')
        
        if not target:
            flash('Please enter a target IP or domain', 'danger')
            return render_template('network_diagnostics.html')
        
        if not is_valid_ip(target):
            flash('Please enter a valid IP address or domain name', 'danger')
            return render_template('network_diagnostics.html')
        
        try:
            results = {}
            
            if diagnostic_type in ['ping', 'both']:
                flash(f'Pinging {target}...', 'info')
                ping_success, ping_output, ping_error = ping_host(target)
                results['ping'] = {
                    'success': ping_success,
                    'output': ping_output,
                    'error': ping_error
                }
            
            if diagnostic_type in ['traceroute', 'both']:
                flash(f'Running traceroute to {target}...', 'info')
                trace_success, trace_output, trace_error = traceroute_host(target)
                results['traceroute'] = {
                    'success': trace_success,
                    'output': trace_output,
                    'error': trace_error
                }
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'network_diagnostics', target, json.dumps(results), 
                 f"Network diagnostics for {target}", 
                 'Info', datetime.now())
            )
            db.commit()
            
            return render_template('network_diagnostics.html', 
                                 target=target,
                                 diagnostic_type=diagnostic_type,
                                 results=results,
                                 scan_completed=True)
            
        except Exception as e:
            flash(f'Error during network diagnostics: {str(e)}', 'danger')
            print(f"Network diagnostics error: {e}")
    
    return render_template('network_diagnostics.html')

@app.route('/security_tools')
@app.route('/security-tools')
def security_tools():
    return render_template('security_tools.html')

@app.route('/tools/security_headers', methods=['GET', 'POST'])
def security_headers_tool():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash('Please enter a URL', 'danger')
            return render_template('security_headers_tool.html')
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Make HEAD request to get headers
            response = requests.head(url, timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            
            # Analyze security headers
            security_headers = {
                'Content-Security-Policy': {
                    'present': 'Content-Security-Policy' in headers,
                    'value': headers.get('Content-Security-Policy', 'Not set'),
                    'risk': 'high' if 'Content-Security-Policy' not in headers else 'low'
                },
                'Strict-Transport-Security': {
                    'present': 'Strict-Transport-Security' in headers,
                    'value': headers.get('Strict-Transport-Security', 'Not set'),
                    'risk': 'medium' if 'Strict-Transport-Security' not in headers else 'low'
                },
                'X-Frame-Options': {
                    'present': 'X-Frame-Options' in headers,
                    'value': headers.get('X-Frame-Options', 'Not set'),
                    'risk': 'medium' if 'X-Frame-Options' not in headers else 'low'
                },
                'X-Content-Type-Options': {
                    'present': 'X-Content-Type-Options' in headers,
                    'value': headers.get('X-Content-Type-Options', 'Not set'),
                    'risk': 'low' if 'X-Content-Type-Options' not in headers else 'low'
                },
                'Referrer-Policy': {
                    'present': 'Referrer-Policy' in headers,
                    'value': headers.get('Referrer-Policy', 'Not set'),
                    'risk': 'low' if 'Referrer-Policy' not in headers else 'low'
                }
            }
            
            # Calculate overall risk
            risk_count = sum(1 for header in security_headers.values() if header['risk'] in ['high', 'medium'])
            overall_risk = 'high' if risk_count >= 3 else 'medium' if risk_count >= 1 else 'low'
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'security_headers', url, json.dumps(security_headers), 
                 f"Found {len([h for h in security_headers.values() if h['present']])} security headers", 
                 overall_risk, datetime.now())
            )
            db.commit()
            
            return render_template('security_headers_tool.html', 
                                 url=url, 
                                 headers=security_headers, 
                                 overall_risk=overall_risk,
                                 all_headers=headers)
            
        except requests.RequestException as e:
            flash(f'Error scanning URL: {str(e)}', 'danger')
        except Exception as e:
            flash('An unexpected error occurred', 'danger')
            print(f"Security headers scan error: {e}")
    
    return render_template('security_headers_tool.html')

@app.route('/tools/dns_lookup', methods=['GET', 'POST'])
def dns_lookup_tool():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        record_type = request.form.get('record_type', 'A')
        
        if not domain:
            flash('Please enter a domain name', 'danger')
            return render_template('dns_lookup_tool.html')
        
        try:
            results = {}
            
            if record_type == 'all' or record_type == 'A':
                try:
                    answers = dns.resolver.resolve(domain, 'A')
                    results['A'] = [str(rdata) for rdata in answers]
                except:
                    results['A'] = ['No records found']
            
            if record_type == 'all' or record_type == 'AAAA':
                try:
                    answers = dns.resolver.resolve(domain, 'AAAA')
                    results['AAAA'] = [str(rdata) for rdata in answers]
                except:
                    results['AAAA'] = ['No records found']
            
            if record_type == 'all' or record_type == 'MX':
                try:
                    answers = dns.resolver.resolve(domain, 'MX')
                    results['MX'] = [str(rdata) for rdata in answers]
                except:
                    results['MX'] = ['No records found']
            
            if record_type == 'all' or record_type == 'TXT':
                try:
                    answers = dns.resolver.resolve(domain, 'TXT')
                    results['TXT'] = [str(rdata) for rdata in answers]
                except:
                    results['TXT'] = ['No records found']
            
            if record_type == 'all' or record_type == 'NS':
                try:
                    answers = dns.resolver.resolve(domain, 'NS')
                    results['NS'] = [str(rdata) for rdata in answers]
                except:
                    results['NS'] = ['No records found']
            
            # Get WHOIS information
            try:
                whois_info = whois.whois(domain)
                results['WHOIS'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date),
                    'name_servers': whois_info.name_servers
                }
            except:
                results['WHOIS'] = {'error': 'WHOIS information not available'}
            
            # Log the scan
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'dns_lookup', domain, json.dumps({'record_type': record_type}), 
                 f"DNS lookup for {record_type} records", 
                 'info', datetime.now())
            )
            db.commit()
            
            return render_template('dns_lookup_tool.html', 
                                 domain=domain, 
                                 record_type=record_type,
                                 results=results)
            
        except Exception as e:
            flash(f'Error performing DNS lookup: {str(e)}', 'danger')
            print(f"DNS lookup error: {e}")
    
    return render_template('dns_lookup_tool.html')

@app.route('/tools/password-checker')
def password_checker_tool():
    return render_template('password_checker_tool.html')

@app.route('/tools/hash-generator')
def hash_generator_tool():
    return render_template('hash_generator_tool.html')

@app.route('/scan_history')
@login_required
def scan_history():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT * FROM scan_results WHERE user_id = %s ORDER BY created_at DESC', (session['user_id'],)
    )
    scans = cursor.fetchall()
    return render_template('scan_history.html', scans=scans)

@app.route('/admin/scan_results')
@admin_required
def admin_scan_results():
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        'SELECT sr.*, u.name, u.email FROM scan_results sr LEFT JOIN users u ON sr.user_id = u.id ORDER BY sr.created_at DESC LIMIT 100'
    )
    scans = cursor.fetchall()
    return render_template('admin_scan_results.html', scans=scans)

if __name__ == '__main__':
    app.run(debug=True, threaded=False)
