from flask import Flask, render_template, request, redirect, url_for, session, flash, g  # import Flask and common helpers
from functools import wraps  # import decorator helper
import os  # operating system utilities
import psycopg2  # PostgreSQL driver
import psycopg2.extras  # extras for RealDictCursor
from datetime import datetime, timedelta  # date/time utilities
from werkzeug.security import generate_password_hash, check_password_hash  # password hashing utilities
import uuid  # for generating tokens
import re  # regular expressions
import requests  # HTTP requests
import whois  # WHOIS lookup
import dns.resolver  # DNS queries
import json  # JSON encoding/decoding
import hashlib  # hashing utilities
import threading  # threading (not heavily used)
import time  # time utilities
from urllib.parse import urljoin, urlparse  # URL parsing/joining
from bs4 import BeautifulSoup  # HTML parsing
import socket  # network sockets
import subprocess  # run system commands
import platform  # detect OS platform
import ipaddress  # validate IP addresses
from concurrent.futures import ThreadPoolExecutor, as_completed  # thread pool for concurrent tasks
from dotenv import load_dotenv  # load .env files
load_dotenv()  # load environment variables from .env

app = Flask(__name__)  # create Flask app
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'  # secret for sessions
# session configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Required for HTTPS on Render
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['PGHOST'] = os.environ.get('PGHOST')  # Postgres host from env
app.config['PGDATABASE'] = os.environ.get('PGDATABASE')  # Postgres database name
app.config['PGUSER'] = os.environ.get('PGUSER')  # Postgres user
app.config['PGPASSWORD'] = os.environ.get('PGPASSWORD')  # Postgres password
app.config['PGPORT'] = os.environ.get('PGPORT', 5432)  # Postgres port with default
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT') or 'dev-salt-change-in-production'  # salt fallback
app.config['SCAN_TIMEOUT'] = 10  # default scan timeout seconds
app.config['MAX_REDIRECTS'] = 5  # max redirects for requests

def get_db():
    """Get or create DB connection stored in Flask g"""
    if 'db' not in g:
        try:
            # Try connecting with the provided credentials
            g.db = psycopg2.connect(
                host=app.config['PGHOST'],
                database=app.config['PGDATABASE'],
                user=app.config['PGUSER'],
                password=app.config['PGPASSWORD'],
                port=app.config['PGPORT']
            )
            print("Database connection established successfully")
        except Exception as e:
            print(f"Database connection failed: {e}")
            # Try alternative connection method for Render
            try:
                # Render sometimes provides a DATABASE_URL instead of separate vars
                database_url = os.environ.get('DATABASE_URL')
                if database_url:
                    g.db = psycopg2.connect(database_url, sslmode='require')
                    print("Connected using DATABASE_URL")
                else:
                    # Re-raise the original error
                    raise e
            except Exception as e2:
                print(f"All connection attempts failed: {e2}")
                raise e2
    return g.db

def init_db(db):  # initialize DB schema and default data
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
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
    ''')  # create users table if missing
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
    ''')  # create user_sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            ip_address TEXT,
            attempted_at TIMESTAMP NOT NULL,
            success BOOLEAN NOT NULL
        )
    ''')  # create login_attempts table
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
    ''')  # create user_activities table
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
    ''')  # create services table
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
    ''')  # create support_tickets table
    cursor.execute('SELECT COUNT(*) as count FROM users')  # check if any users exist
    result = cursor.fetchone()  # fetch count
    if result['count'] == 0:  # if no users, create default admin
        hashed_password = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'changeme123'))  # hash admin pw
        cursor.execute(
            'INSERT INTO users (name, email, password_hash, role, email_verified, created_at) VALUES (%s, %s, %s, %s, %s, %s)',
            ('Admin User', 'admin@21centurysolutions.com', hashed_password, 'admin', 1, datetime.now())
        )  # insert default admin user
        print("Default admin user created: admin@21centurysolutions.com / changeme123")  # print notice
    init_scan_results_table(db)  # ensure scan_results table exists
    db.commit()  # commit changes

def init_scan_results_table(db):  # create scan_results table
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
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
    ''')  # create scan_results schema
    db.commit()  # commit

def close_db(e=None):  # close DB connection on teardown
    db = g.pop('db', None)  # remove db from g if present
    if db is not None:  # if connection existed
        db.close()  # close it

app.teardown_appcontext(close_db)  # register teardown handler

def log_activity(user_id, activity_type, description, ip_address=None):  # insert a user activity record
    try:
        db = get_db()  # get DB connection
        cursor = db.cursor()  # standard cursor
        cursor.execute(
            'INSERT INTO user_activities (user_id, activity_type, description, ip_address, performed_at) VALUES (%s, %s, %s, %s, %s)',
            (user_id, activity_type, description, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )  # insert activity row
        db.commit()  # commit
    except Exception as e:
        print(f"Error logging activity: {e}")  # print error on failure

def log_login_attempt(email, success, ip_address=None):  # record login attempts
    try:
        db = get_db()  # get DB
        cursor = db.cursor()  # cursor
        cursor.execute(
            'INSERT INTO login_attempts (email, ip_address, attempted_at, success) VALUES (%s, %s, %s, %s)',
            (email, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), int(success))
        )  # insert login attempt
        db.commit()  # commit
    except Exception as e:
        print(f"Error logging login attempt: {e}")  # print error

def is_brute_force(email, ip_address):  # simple brute-force detection using recent failures
    try:
        db = get_db()  # get DB
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
        cursor.execute(
            'SELECT COUNT(*) as count FROM login_attempts WHERE email = %s AND ip_address = %s AND success = 0 AND attempted_at > %s',
            (email, ip_address, (datetime.now() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S'))
        )  # count failures in last 15 minutes
        recent_failures = cursor.fetchone()  # fetch result
        return recent_failures['count'] >= 5 if recent_failures else False  # consider brute-force if >=5
    except Exception as e:
        print(f"Error checking brute force: {e}")  # print error
        return False  # default to not brute force on error

def generate_token():  # generate a random UUID token
    return str(uuid.uuid4())  # return as string

def validate_email(email):  # validate email with regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'  # simple email regex
    return re.match(pattern, email) is not None  # return boolean

def safe_get(d, key, default=None):  # safe dict access helper
    try:
        return d[key] if key in d else default  # return value or default
    except (KeyError, TypeError, IndexError):
        return default  # fallback default on error

def login_required(f):  # decorator to require login
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # not logged in
            flash('Please log in to access this page.', 'warning')  # flash message
            return redirect(url_for('login'))  # redirect to login
        return f(*args, **kwargs)  # call original function
    return decorated_function  # return wrapper

def admin_required(f):  # decorator to require admin role
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # ensure logged in
            flash('Please log in to access this page.', 'warning')  # flash
            return redirect(url_for('login'))  # redirect
        try:
            db = get_db()  # get DB
            cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
            cursor.execute(
                'SELECT role FROM users WHERE id = %s', (session['user_id'],)
            )  # fetch role
            user = cursor.fetchone()  # get user row
            if user and safe_get(user, 'role') != 'admin':  # if not admin
                flash('Administrator access required.', 'danger')  # flash
                return redirect(url_for('home'))  # redirect home
            return f(*args, **kwargs)  # call protected function
        except Exception as e:
            flash('Database error. Please try again.', 'danger')  # flash on DB error
            return redirect(url_for('home'))  # redirect home
    return decorated_function  # return wrapper

def safe_request(url, method='GET', data=None, headers=None, timeout=10):  # safe HTTP request wrapper
    """Make safe HTTP requests with error handling"""  # docstring
    try:
        if method.upper() == 'GET':  # GET request
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)  # send GET
        else:
            response = requests.post(url, data=data, timeout=timeout, verify=False, allow_redirects=True)  # send POST
        return response  # return response object
    except requests.RequestException as e:
        return None  # return None on request errors

def extract_forms(url):  # parse HTML and extract form structures
    """Extract all forms from a webpage"""  # docstring
    try:
        response = safe_request(url)  # fetch page
        if not response:
            return []  # return empty list if fetch failed
        
        soup = BeautifulSoup(response.content, 'html.parser')  # parse HTML
        forms = []  # container for form data
        
        for form in soup.find_all('form'):  # iterate forms
            form_details = {
                'action': form.get('action', ''),  # action attribute
                'method': form.get('method', 'GET').upper(),  # method attribute
                'inputs': []
            }  # initialize form details
            
            for input_tag in form.find_all('input'):  # iterate input tags
                input_details = {
                    'type': input_tag.get('type', 'text'),  # input type
                    'name': input_tag.get('name', ''),  # name attribute
                    'value': input_tag.get('value', '')  # default value
                }
                form_details['inputs'].append(input_details)  # append input info
            
            forms.append(form_details)  # add form to list
        
        return forms  # return extracted forms
    except Exception as e:
        print(f"Error extracting forms: {e}")  # print error
        return []  # fallback empty list

def scan_sql_injection(target_url):  # scan URL for SQL injection patterns
    """Scan for SQL Injection vulnerabilities"""  # docstring
    vulnerabilities = []  # list to collect findings
    payloads = [
        "'",  # simple single quote
        "';",  # quote+semicolon
        "' OR '1'='1",  # tautology
        "' UNION SELECT 1,2,3--",  # union payload
        "'; DROP TABLE users--",  # destructive payload (test only)
        "' AND 1=1--",  # benign control payload
        "' AND 1=2--"  # false condition payload
    ]  # payload list
    
    try:
        # Test URL parameters
        parsed_url = urlparse(target_url)  # parse URL
        if parsed_url.query:  # if query string present
            params = dict([p.split('=') for p in parsed_url.query.split('&') if '=' in p])  # parse params
            for param in params:
                for payload in payloads:
                    test_url = target_url.replace(f"{param}={params[param]}", f"{param}={params[param]}{payload}")  # inject payload
                    response = safe_request(test_url)  # request test URL
                    
                    if response and any(error in response.text.lower() for error in [
                        'sql', 'syntax', 'mysql', 'ora', 'microsoft odbc', 'postgresql',
                        'warning', 'error', 'exception', 'database'
                    ]):  # look for DB error strings
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': 'Database error found in response'
                        })  # append finding
                        break  # stop testing this param
        
        # Test forms
        forms = extract_forms(target_url)  # extract forms
        for form in forms:
            form_action = urljoin(target_url, form['action'])  # resolve action URL
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'password', 'search']:  # relevant inputs
                    for payload in payloads:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                data[field['name']] = payload if field['name'] == input_field['name'] else 'test'  # set payload for target field
                        
                        response = safe_request(form_action, method=form['method'], data=data)  # submit form
                        
                        if response and any(error in response.text.lower() for error in [
                            'sql', 'syntax', 'mysql', 'ora', 'microsoft odbc', 'postgresql',
                            'warning', 'error', 'exception', 'database'
                        ]):  # check for DB errors
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'parameter': input_field['name'],
                                'payload': payload,
                                'url': form_action,
                                'method': form['method'],
                                'evidence': 'Database error found in response'
                            })  # add finding
                            break  # stop testing this input
        
        return vulnerabilities  # return findings
    
    except Exception as e:
        print(f"SQL Injection scan error: {e}")  # print error
        return []  # return empty list on exception

def scan_xss_vulnerabilities(target_url):  # scan for reflected XSS
    """Scan for Cross-Site Scripting (XSS) vulnerabilities"""  # docstring
    vulnerabilities = []  # store findings
    payloads = [
        "<script>alert('XSS')</script>",  # script payload
        "<img src=x onerror=alert('XSS')>",  # image onerror
        "<svg onload=alert('XSS')>",  # svg onload
        "'\"><script>alert('XSS')</script>",  # quote-escaping payload
        "javascript:alert('XSS')"  # javascript: URI
    ]  # XSS payloads
    
    try:
        # Test URL parameters
        parsed_url = urlparse(target_url)  # parse target
        if parsed_url.query:  # has query params
            params = dict([p.split('=') for p in parsed_url.query.split('&') if '=' in p])  # parse params
            for param in params:
                for payload in payloads:
                    test_url = target_url.replace(f"{param}={params[param]}", f"{param}={payload}")  # inject payload
                    response = safe_request(test_url)  # fetch
                    
                    if response and payload in response.text:  # check if payload reflected verbatim
                        vulnerabilities.append({
                            'type': 'XSS',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': 'Payload reflected in response without sanitization'
                        })  # add finding
        
        # Test forms
        forms = extract_forms(target_url)  # get forms
        for form in forms:
            form_action = urljoin(target_url, form['action'])  # resolve action
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'password', 'search', 'textarea']:  # candidate fields
                    for payload in payloads:
                        data = {}
                        for field in form['inputs']:
                            if field['name']:
                                data[field['name']] = payload if field['name'] == input_field['name'] else 'test'  # set payload
                        
                        response = safe_request(form_action, method=form['method'], data=data)  # submit
                        
                        if response and payload in response.text:  # check reflected payload
                            vulnerabilities.append({
                                'type': 'XSS',
                                'parameter': input_field['name'],
                                'payload': payload,
                                'url': form_action,
                                'method': form['method'],
                                'evidence': 'Payload reflected in response without sanitization'
                            })  # add finding
        
        return vulnerabilities  # return list
    
    except Exception as e:
        print(f"XSS scan error: {e}")  # print error
        return []  # fallback empty

def scan_csrf_vulnerabilities(target_url):  # detect missing CSRF tokens in POST forms
    """Scan for Cross-Site Request Forgery (CSRF) vulnerabilities"""  # docstring
    vulnerabilities = []  # results list
    
    try:
        forms = extract_forms(target_url)  # extract forms
        
        for form in forms:
            if form['method'] == 'POST':  # only check POST forms
                has_csrf_token = False  # assume missing
                csrf_indicators = ['csrf', 'token', 'nonce', 'authenticity']  # common token names
                
                for input_field in form['inputs']:
                    field_name = input_field['name'].lower() if input_field['name'] else ''  # lowercase field name
                    if any(indicator in field_name for indicator in csrf_indicators):
                        has_csrf_token = True  # token-like field found
                        break
                
                if not has_csrf_token:  # if missing, report
                    vulnerabilities.append({
                        'type': 'CSRF',
                        'form_action': urljoin(target_url, form['action']),
                        'method': form['method'],
                        'evidence': 'No CSRF token found in POST form',
                        'risk': 'Medium'
                    })
        
        return vulnerabilities  # return findings
    
    except Exception as e:
        print(f"CSRF scan error: {e}")  # print error
        return []  # fallback empty

def calculate_vulnerability_risk(vulnerabilities):  # simple risk aggregation
    """Calculate overall risk level based on vulnerabilities found"""  # docstring
    if not vulnerabilities:
        return 'Low'  # no vulns -> low risk
    
    high_severity = any(vuln['type'] in ['SQL Injection', 'XSS'] for vuln in vulnerabilities)  # check for high severity types
    medium_severity = any(vuln['type'] == 'CSRF' for vuln in vulnerabilities)  # check for medium
    
    if high_severity:
        return 'High'  # high if any high severity
    elif medium_severity:
        return 'Medium'  # medium if any medium
    else:
        return 'Low'  # else low

def is_valid_ip(target):  # validate IP or domain name
    """Validate if the target is a valid IP address or domain"""  # docstring
    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(target)  # try to parse as IP
        return True  # valid IP
    except ValueError:
        # Check if it's a valid domain name
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):  # basic domain regex
            return True  # looks like domain
        return False  # otherwise invalid

def scan_port(target, port, timeout=2):  # check single TCP port
    """Scan a single port on the target"""  # docstring
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  # create socket
            sock.settimeout(timeout)  # set timeout
            result = sock.connect_ex((target, port))  # attempt connect
            return (port, result == 0)  # return (port, open_bool)
    except Exception as e:
        return (port, False)  # on error treat as closed

def port_scanner_scan(target, ports, max_workers=50):  # concurrent port scanning
    """Perform port scanning on target with multiple threads"""  # docstring
    open_ports = []  # collect open ports
    
    try:
        # Resolve domain to IP if needed
        try:
            target_ip = socket.gethostbyname(target)  # DNS resolve
        except socket.gaierror:
            return [], f"Could not resolve hostname: {target}"  # return error message
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:  # thread pool
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(scan_port, target_ip, port): port 
                for port in ports
            }  # map futures to ports
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                try:
                    port, is_open = future.result()  # get result tuple
                    if is_open:
                        open_ports.append(port)  # accumulate open ports
                except Exception as e:
                    print(f"Error scanning port: {e}")  # print error
                    continue
        
        return open_ports, None  # return open ports and no error
        
    except Exception as e:
        return [], f"Error during port scanning: {str(e)}"  # return error message

def get_service_name(port):  # map common ports to service names
    """Get common service name for a port"""  # docstring
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
        995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        27017: "MongoDB", 6379: "Redis"
    }  # mapping
    return common_ports.get(port, "Unknown")  # return known name or Unknown

def ping_host(target, timeout=3):  # ping host using system ping or HTTPS check on Render
    """
    Try to ping a host. Uses the system 'ping' command locally,
    and HTTPS reachability (via requests) when running on Render.
    """  # docstring
    try:
        # Detect if running on Render
        running_on_render = os.environ.get("RENDER", "").lower() == "true"  # check env
        
        if not running_on_render:
            # Local environment → use real OS ping
            count_flag = "-n" if os.name == "nt" else "-c"  # windows vs unix flag
            output = subprocess.check_output(
                ["ping", count_flag, "4", target],
                stderr=subprocess.STDOUT,
                text=True
            )  # run ping command and capture output
            return f"✅ Ping results for {target}:\n\n{output}"  # return formatted result

        else:
            # Render environment → use HTTPS check
            try:
                response = requests.get(f"https://{target}", timeout=timeout)  # attempt HTTPS GET
                if response.status_code == 200:
                    return f"✅ {target} is reachable via HTTPS ({response.status_code})."  # reachable
                else:
                    return f"⚠️ {target} responded with status {response.status_code}."  # non-200
            except requests.exceptions.SSLError:
                return f"⚠️ SSL error when connecting to {target}."  # SSL error
            except requests.exceptions.ConnectionError:
                return f"❌ Unable to connect to {target} (connection refused)."  # connection refused
            except requests.exceptions.Timeout:
                return f"❌ Connection to {target} timed out."  # timeout
    except subprocess.CalledProcessError as e:
        return f"❌ Ping command failed:\n\n{e.output}"  # ping command failed
    except Exception as e:
        return f"⚠️ Error checking host: {e}"  # other errors

def traceroute_host(target, max_hops=30):  # perform traceroute/tracert
    """Perform traceroute to a host"""  # docstring
    try:
        # Determine the traceroute command based on the OS
        if platform.system().lower() == "windows":
            cmd = ["tracert", "-h", str(max_hops), target]  # Windows tracert
        else:
            cmd = ["traceroute", "-m", str(max_hops), "-w", "1", target]  # Unix traceroute
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=30
        )  # run traceroute command
        
        return result.returncode == 0, result.stdout, result.stderr  # return success flag, stdout, stderr
        
    except subprocess.TimeoutExpired:
        return False, "", "Traceroute command timed out"  # timeout handling
    except Exception as e:
        return False, "", f"Error executing traceroute: {str(e)}"  # other errors

@app.route('/')
def home():  # home page route
    return render_template('index.html')  # render index template

@app.route('/cybersecurity')
def cybersecurity():  # cybersecurity page
    return render_template('cybersecurity.html')  # render template

@app.route('/other_solutions')
def other_solutions():  # other solutions page
    return render_template('other_solutions.html')  # render template

@app.route('/contact')
def contact():  # contact page
    return render_template('contact.html')  # render template

@app.route('/network_security')
def network_security():  # network security page
    return render_template('network_security.html')  # render template

@app.route('/endpoint_protection')
def endpoint_protection():  # endpoint protection page
    return render_template('endpoint_protection.html')  # render template

@app.route('/cloud_security')
def cloud_security():  # cloud security page
    return render_template('cloud_security.html')  # render template

@app.route('/threat_intelligence')
def threat_intelligence():  # threat intelligence page
    return render_template('threat_intelligence.html')  # render template

@app.route('/incident_response')
def incident_response():  # incident response page
    return render_template('incident_response.html')  # render template

@app.route('/security_audits')
def security_audits():  # security audits page
    return render_template('security_audits.html')  # render template

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
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            
            if user:
                # Test password verification first
                password_correct = check_password_hash(user['password_hash'], password)
                print(f"Password check for {email}: {password_correct}")
                
                if password_correct:
                    # Clear any existing session
                    session.clear()
                    
                    # Set new session data
                    session['user_id'] = user['id']
                    session['user_email'] = user['email']
                    session['user_name'] = user['name']
                    session['user_role'] = user.get('role', 'user')
                    
                    # Update last login
                    cursor.execute(
                        'UPDATE users SET last_login = %s WHERE id = %s',
                        (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id'])
                    )
                    
                    # Set session permanence
                    session.permanent = bool(remember_me)
                    
                    db.commit()
                    
                    # Log the activity (but don't let it break login)
                    try:
                        log_activity(user['id'], 'login', 'User logged in successfully', ip_address)
                        log_login_attempt(email, True, ip_address)
                    except Exception as log_error:
                        print(f"Logging error (non-critical): {log_error}")
                    
                    flash('Login successful!', 'success')
                    
                    # Force session save
                    session.modified = True
                    
                    # Redirect based on role
                    if user.get('role') == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('client_portal'))
                else:
                    log_login_attempt(email, False, ip_address)
                    flash('Invalid email or password.', 'danger')
            else:
                log_login_attempt(email, False, ip_address)
                flash('Invalid email or password.', 'danger')
                
        except Exception as e:
            print(f"Login error: {e}")
            flash('Database error. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():  # user registration route
    if request.method == 'POST':  # handle submission
        name = request.form['name']  # get name
        email = request.form['email']  # get email
        password = request.form['password']  # get password
        confirm_password = request.form['confirm_password']  # confirm password
        company = request.form.get('company', '')  # optional company
        if not validate_email(email):  # validate email format
            flash('Please enter a valid email address.', 'danger')  # flash error
            return render_template('register.html')  # render register
        if password != confirm_password:  # check match
            flash('Passwords do not match.', 'danger')  # flash
            return render_template('register.html')  # render register
        if len(password) < 8:  # minimum length
            flash('Password must be at least 8 characters long.', 'danger')  # flash
            return render_template('register.html')  # render register
        db = get_db()  # get DB
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
        cursor.execute('SELECT id FROM users WHERE email = %s', (email,))  # check existing
        existing_user = cursor.fetchone()  # fetch
        if existing_user:  # if exists
            flash('Email already registered. Please login instead.', 'danger')  # flash
            return redirect(url_for('login'))  # redirect to login
        hashed_password = generate_password_hash(password)  # hash password
        verification_token = generate_token()  # token for email verification
        cursor.execute(
            'INSERT INTO users (name, email, password_hash, company, verification_token, created_at) VALUES (%s, %s, %s, %s, %s, %s)',
            (name, email, hashed_password, company, verification_token, datetime.now())
        )  # insert new user
        db.commit()  # commit
        verification_url = url_for('verify_email', token=verification_token, _external=True)  # build verify URL
        print(f"Verification URL: {verification_url}")  # print for dev
        flash('Registration successful! Please check your email to verify your account.', 'success')  # flash success
        return redirect(url_for('login'))  # redirect to login
    return render_template('register.html')  # render register page

@app.route('/verify/<token>')
def verify_email(token):  # email verification endpoint
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT id, email FROM users WHERE verification_token = %s', (token,)
    )  # fetch user by token
    user = cursor.fetchone()  # get user
    if user:
        cursor.execute(
            'UPDATE users SET email_verified = TRUE, verification_token = NULL WHERE id = %s',
            (user['id'],)
        )  # mark verified
        db.commit()  # commit
        log_activity(user['id'], 'email_verification', 'User verified their email address')  # log activity
        flash('Email verified successfully! You can now log in.', 'success')  # flash
    else:
        flash('Invalid verification token.', 'danger')  # flash invalid token
    return redirect(url_for('login'))  # redirect to login

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():  # forgot password workflow
    if request.method == 'POST':  # handle post
        email = request.form['email']  # get email
        db = get_db()  # get DB
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
        cursor.execute(
            'SELECT id FROM users WHERE email = %s', (email,)
        )  # find user
        user = cursor.fetchone()  # fetch
        if user:
            reset_token = generate_token()  # generate reset token
            reset_token_expiry = datetime.now() + timedelta(hours=1)  # expiry 1 hour
            cursor.execute(
                'UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE id = %s',
                (reset_token, reset_token_expiry.strftime('%Y-%m-%d %H:%M:%S'), user['id'])
            )  # store token and expiry
            db.commit()  # commit
            reset_url = url_for('reset_password', token=reset_token, _external=True)  # build reset URL
            print(f"Password reset URL: {reset_url}")  # print for dev
            flash('Password reset instructions have been sent to your email.', 'success')  # flash
        else:
            flash('If that email address is in our system, we\'ve sent a password reset link to it.', 'success')  # generic message
        return redirect(url_for('login'))  # redirect to login
    return render_template('forgot_password.html')  # render forgot password page

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):  # reset password page
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT id, reset_token_expiry FROM users WHERE reset_token = %s', (token,)
    )  # fetch by reset token
    user = cursor.fetchone()  # get user
    if not user or not user['reset_token_expiry']:  # invalid or missing expiry
        flash('Invalid or expired reset token.', 'danger')  # flash
        return redirect(url_for('login'))  # redirect
    expiry_str = str(user['reset_token_expiry'])  # get expiry as string
    try:
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')  # try parse without microseconds
    except ValueError:
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S.%f')  # parse with microseconds
    if datetime.now() > expiry:  # expired
        flash('Invalid or expired reset token.', 'danger')  # flash
        return redirect(url_for('login'))  # redirect
    if request.method == 'POST':  # handle password reset post
        password = request.form['password']  # new password
        confirm_password = request.form['confirm_password']  # confirm
        if password != confirm_password:  # mismatch
            flash('Passwords do not match.', 'danger')  # flash
            return render_template('reset_password.html', token=token)  # re-render
        if len(password) < 8:  # length check
            flash('Password must be at least 8 characters long.', 'danger')  # flash
            return render_template('reset_password.html', token=token)  # re-render
        hashed_password = generate_password_hash(password)  # hash new password
        cursor.execute(
            'UPDATE users SET password_hash = %s, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = %s',
            (hashed_password, token)
        )  # update password and clear token
        db.commit()  # commit
        log_activity(user['id'], 'password_reset', 'User reset their password')  # log activity
        flash('Password reset successfully! You can now log in with your new password.', 'success')  # flash
        return redirect(url_for('login'))  # redirect to login
    return render_template('reset_password.html', token=token)  # render reset form

@app.route('/logout')
def logout():  # logout route
    if 'user_id' in session:
        log_activity(session['user_id'], 'logout', 'User logged out')  # log logout
    session.clear()  # clear session
    flash('You have been logged out.', 'info')  # flash
    return redirect(url_for('home'))  # go home

@app.route('/client_portal')
@login_required
def client_portal():  # client portal route for logged in users
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM services WHERE user_id = %s', (session['user_id'],)
    )  # fetch user's services
    user_services = cursor.fetchall()  # fetch all
    return render_template('client_portal.html', services=user_services)  # render portal

@app.route('/profile')
@login_required
def profile():  # user profile page
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (session['user_id'],)
    )  # fetch user record
    user = cursor.fetchone()  # fetch
    return render_template('profile.html', user=user)  # render profile

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():  # update profile action
    name = request.form['name']  # new name
    email = request.form['email']  # new email
    company = request.form.get('company', '')  # company
    phone = request.form.get('phone', '')  # phone
    title = request.form.get('title', '')  # title
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT id FROM users WHERE email = %s AND id != %s', (email, session['user_id'])
    )  # check email uniqueness
    existing_user = cursor.fetchone()  # fetch
    if existing_user:
        flash('Email already taken by another account.', 'danger')  # flash
        return redirect(url_for('profile'))  # redirect back
    cursor.execute(
        'UPDATE users SET name = %s, email = %s, company = %s, phone = %s, title = %s WHERE id = %s',
        (name, email, company, phone, title, session['user_id'])
    )  # update user fields
    db.commit()  # commit
    session['user_name'] = name  # update session name
    session['user_email'] = email  # update session email
    log_activity(session['user_id'], 'profile_update', 'User updated their profile')  # log activity
    flash('Profile updated successfully!', 'success')  # flash
    return redirect(url_for('profile'))  # redirect

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():  # allow logged-in user to change password
    if request.method == 'POST':  # handle new password submission
        current_password = request.form['current_password']  # current pw
        new_password = request.form['new_password']  # new pw
        confirm_password = request.form['confirm_password']  # confirm
        if new_password != confirm_password:  # mismatch
            flash('New passwords do not match.', 'danger')  # flash
            return render_template('change_password.html')  # re-render
        if len(new_password) < 8:  # length check
            flash('New password must be at least 8 characters long.', 'danger')  # flash
            return render_template('change_password.html')  # re-render
        db = get_db()  # get DB
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
        cursor.execute(
            'SELECT password_hash FROM users WHERE id = %s', (session['user_id'],)
        )  # fetch current hash
        user = cursor.fetchone()  # fetch
        if user and check_password_hash(user['password_hash'], current_password):  # verify current password
            hashed_password = generate_password_hash(new_password)  # hash new one
            cursor.execute(
                'UPDATE users SET password_hash = %s WHERE id = %s',
                (hashed_password, session['user_id'])
            )  # update DB
            db.commit()  # commit
            log_activity(session['user_id'], 'password_change', 'User changed their password')  # log
            flash('Password changed successfully!', 'success')  # flash
            return redirect(url_for('profile'))  # redirect
        else:
            flash('Current password is incorrect.', 'danger')  # flash wrong current pw
    return render_template('change_password.html')  # render change password page

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():  # admin dashboard route
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute('SELECT COUNT(*) as count FROM users')  # total users
    total_users = cursor.fetchone()['count']  # fetch count
    cursor.execute('SELECT COUNT(*) as count FROM users WHERE last_login > %s', 
                   ((datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S'),))  # active users last 30 days
    total_active_users = cursor.fetchone()['count']  # fetch
    cursor.execute('SELECT COUNT(*) as count FROM services')  # total services
    total_services = cursor.fetchone()['count']  # fetch
    cursor.execute("SELECT COUNT(*) as count FROM support_tickets WHERE status = 'open'")  # open tickets
    open_tickets = cursor.fetchone()['count']  # fetch
    cursor.execute('''
        SELECT ua.*, u.name, u.email 
        FROM user_activities ua 
        JOIN users u ON ua.user_id = u.id 
        ORDER BY ua.performed_at DESC 
        LIMIT 10
    ''')  # recent activities query
    recent_activities = cursor.fetchall()  # fetch rows
    cursor.execute('''
        SELECT name, email, created_at 
        FROM users 
        ORDER BY created_at DESC 
        LIMIT 5
    ''')  # recent signups
    recent_signups = cursor.fetchall()  # fetch
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         total_active_users=total_active_users,
                         total_services=total_services,
                         open_tickets=open_tickets,
                         recent_activities=recent_activities,
                         recent_signups=recent_signups)  # render admin dashboard

@app.route('/admin/users')
@admin_required
def admin_users():  # list all users for admin
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT id, name, email, role, email_verified, created_at, last_login FROM users ORDER BY created_at DESC'
    )  # select users
    users = cursor.fetchall()  # fetch
    return render_template('admin_users.html', users=users)  # render users list

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):  # view user detail
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )  # fetch user
    user = cursor.fetchone()  # get user
    if not user:
        flash('User not found.', 'danger')  # flash not found
        return redirect(url_for('admin_users'))  # redirect
    cursor.execute(
        'SELECT * FROM services WHERE user_id = %s', (user_id,)
    )  # user's services
    user_services = cursor.fetchall()  # fetch
    cursor.execute(
        'SELECT * FROM user_activities WHERE user_id = %s ORDER BY performed_at DESC LIMIT 20', (user_id,)
    )  # activity history
    user_activities = cursor.fetchall()  # fetch
    cursor.execute(
        'SELECT * FROM support_tickets WHERE user_id = %s ORDER BY created_at DESC', (user_id,)
    )  # support tickets
    user_tickets = cursor.fetchall()  # fetch
    return render_template('admin_user_detail.html', 
                         user=user,
                         services=user_services,
                         activities=user_activities,
                         tickets=user_tickets)  # render user detail

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):  # edit user by admin
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )  # fetch user
    user = cursor.fetchone()  # get user
    if not user:
        flash('User not found.', 'danger')  # flash
        return redirect(url_for('admin_users'))  # redirect
    if request.method == 'POST':  # handle edit form
        name = request.form['name']  # new name
        email = request.form['email']  # new email
        company = request.form.get('company', '')  # company
        phone = request.form.get('phone', '')  # phone
        title = request.form.get('title', '')  # title
        role = request.form.get('role', 'user')  # role selection
        email_verified = 1 if 'email_verified' in request.form else 0  # checkbox
        if email != user['email']:
            cursor.execute(
                'SELECT id FROM users WHERE email = %s AND id != %s', (email, user_id)
            )  # ensure email unique
            existing_user = cursor.fetchone()  # fetch
            if existing_user:
                flash('Email already taken by another account.', 'danger')  # flash
                return redirect(url_for('admin_edit_user', user_id=user_id))  # redirect
        cursor.execute(
            'UPDATE users SET name = %s, email = %s, company = %s, phone = %s, title = %s, role = %s, email_verified = %s WHERE id = %s',
            (name, email, company, phone, title, role, email_verified, user_id)
        )  # update user
        db.commit()  # commit
        log_activity(session['user_id'], 'admin_user_edit', f'Admin edited user {user_id}')  # log admin action
        flash('User updated successfully!', 'success')  # flash
        return redirect(url_for('admin_user_detail', user_id=user_id))  # go to detail
    return render_template('admin_edit_user.html', user=user)  # render edit form

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):  # delete user by admin
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'danger')  # prevent self-delete
        return redirect(url_for('admin_users'))  # redirect
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )  # fetch user
    user = cursor.fetchone()  # get user
    if not user:
        flash('User not found.', 'danger')  # flash
        return redirect(url_for('admin_users'))  # redirect
    cursor.execute('DELETE FROM user_activities WHERE user_id = %s', (user_id,))  # delete activities
    cursor.execute('DELETE FROM services WHERE user_id = %s', (user_id,))  # delete services
    cursor.execute('DELETE FROM support_tickets WHERE user_id = %s', (user_id,))  # delete tickets
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))  # delete user
    db.commit()  # commit
    log_activity(session['user_id'], 'admin_user_delete', f'Admin deleted user {user_id}')  # log action
    flash('User deleted successfully!', 'success')  # flash
    return redirect(url_for('admin_users'))  # redirect

@app.route('/admin/user/<int:user_id>/impersonate')
@admin_required
def admin_impersonate_user(user_id):  # admin impersonation route
    if user_id == session['user_id']:
        flash('You cannot impersonate yourself.', 'danger')  # guard
        return redirect(url_for('admin_users'))  # redirect
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM users WHERE id = %s', (user_id,)
    )  # fetch target user
    user = cursor.fetchone()  # get user
    if not user:
        flash('User not found.', 'danger')  # flash
        return redirect(url_for('admin_users'))  # redirect
    session['original_admin_id'] = session['user_id']  # store original admin id
    session['original_admin_name'] = session['user_name']  # store admin name
    session['original_admin_email'] = session['user_email']  # store admin email
    session['user_id'] = user['id']  # set session to impersonated user
    session['user_email'] = user['email']  # set email
    session['user_name'] = user['name']  # set name
    session['user_role'] = user['role']  # set role
    session['is_impersonating'] = True  # mark impersonation
    log_activity(session['original_admin_id'], 'admin_impersonate', f'Admin impersonated user {user_id}')  # log
    flash(f'Now impersonating {user["name"]}.', 'info')  # flash info
    return redirect(url_for('client_portal'))  # go to client portal

@app.route('/admin/stop-impersonating')
def admin_stop_impersonating():  # stop impersonation and restore admin session
    if 'original_admin_id' not in session or not session.get('is_impersonating'):
        flash('Not currently impersonating any user.', 'warning')  # not impersonating
        return redirect(url_for('home'))  # redirect
    session['user_id'] = session['original_admin_id']  # restore admin id
    session['user_email'] = session['original_admin_email']  # restore email
    session['user_name'] = session['original_admin_name']  # restore name
    session['user_role'] = 'admin'  # restore role
    session.pop('original_admin_id', None)  # remove stored admin id
    session.pop('original_admin_name', None)  # remove stored name
    session.pop('original_admin_email', None)  # remove stored email
    session.pop('is_impersonating', None)  # remove flag
    flash('Stopped impersonating. Welcome back!', 'success')  # flash
    return redirect(url_for('admin_dashboard'))  # redirect to admin dashboard

@app.route('/admin/services')
@admin_required
def admin_services():  # admin view of all services
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute('''
        SELECT s.*, u.name as user_name, u.email as user_email 
        FROM services s 
        JOIN users u ON s.user_id = u.id 
        ORDER BY s.purchased_on DESC
    ''')  # join services with users
    services = cursor.fetchall()  # fetch records
    return render_template('admin_services.html', services=services)  # render

@app.route('/admin/tickets')
@admin_required
def admin_tickets():  # admin list support tickets
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute('''
        SELECT t.*, u.name as user_name, u.email as user_email 
        FROM support_tickets t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC
    ''')  # join tickets with users
    tickets = cursor.fetchall()  # fetch
    return render_template('admin_tickets.html', tickets=tickets)  # render

@app.route('/admin/ticket/<int:ticket_id>')
@admin_required
def admin_ticket_detail(ticket_id):  # view a specific ticket
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute('''
        SELECT t.*, u.name as user_name, u.email as user_email 
        FROM support_tickets t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.id = %s
    ''', (ticket_id,))  # fetch ticket by id
    ticket = cursor.fetchone()  # get ticket
    if not ticket:
        flash('Ticket not found.', 'danger')  # flash
        return redirect(url_for('admin_tickets'))  # redirect
    return render_template('admin_ticket_detail.html', ticket=ticket)  # render detail

@app.route('/admin/ticket/<int:ticket_id>/update', methods=['POST'])
@admin_required
def admin_update_ticket(ticket_id):  # update ticket status/notes
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM support_tickets WHERE id = %s', (ticket_id,)
    )  # fetch ticket
    ticket = cursor.fetchone()  # get
    if not ticket:
        flash('Ticket not found.', 'danger')  # flash
        return redirect(url_for('admin_tickets'))  # redirect
    status = request.form['status']  # new status
    notes = request.form.get('notes', '')  # notes
    cursor.execute(
        'UPDATE support_tickets SET status = %s, updated_at = %s, notes = %s WHERE id = %s',
        (status, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), notes, ticket_id)
    )  # update ticket
    db.commit()  # commit
    log_activity(session['user_id'], 'admin_ticket_update', f'Admin updated ticket {ticket_id} to {status}')  # log action
    flash('Ticket updated successfully!', 'success')  # flash
    return redirect(url_for('admin_ticket_detail', ticket_id=ticket_id))  # redirect back

@app.route('/admin/activities')
@admin_required
def admin_activities():  # list recent activities for admin
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute('''
        SELECT ua.*, u.name, u.email 
        FROM user_activities ua 
        JOIN users u ON ua.user_id = u.id 
        ORDER BY ua.performed_at DESC 
        LIMIT 100
    ''')  # query activities
    activities = cursor.fetchall()  # fetch
    return render_template('admin_activities.html', activities=activities)  # render

@app.route('/admin/login-attempts')
@admin_required
def admin_login_attempts():  # view recent login attempts
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute('''
        SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 100
    ''')  # fetch attempts
    attempts = cursor.fetchall()  # fetch
    return render_template('admin_login_attempts.html', attempts=attempts)  # render

@app.route('/initdb')
def init_database():  # endpoint to initialize DB (developer use)
    try:
        db = get_db()  # get DB
        init_db(db)  # initialize
        return 'Database initialized successfully!'  # success message
    except Exception as e:
        return f'Error initializing database: {str(e)}'  # error message

@app.route('/tools/sqli_scanner', methods=['GET', 'POST'])
def sqli_scanner():  # SQLi scanning UI
    if request.method == 'POST':  # handle form
        url = request.form.get('url', '').strip()  # target URL
        if not url:
            flash('Please enter a URL', 'danger')  # require URL
            return render_template('sqli_scanner.html')  # render form
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url  # default to https
            
            flash('SQL Injection scan started. This may take a few moments...', 'info')  # notify user
            
            # Perform SQL Injection scan
            vulnerabilities = scan_sql_injection(url)  # run scanner
            risk_level = calculate_vulnerability_risk(vulnerabilities)  # compute risk
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'sql_injection', url, json.dumps(vulnerabilities), 
                 f"Found {len(vulnerabilities)} SQL Injection vulnerabilities", 
                 risk_level, datetime.now())
            )  # store scan result
            db.commit()  # commit
            
            return render_template('sqli_scanner.html', 
                                 url=url, 
                                 vulnerabilities=vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True)  # render results
            
        except Exception as e:
            flash(f'Error during SQL Injection scan: {str(e)}', 'danger')  # flash error
            print(f"SQL Injection scan error: {e}")  # print error
    
    return render_template('sqli_scanner.html')  # render scanner page

@app.route('/tools/xss_scanner', methods=['GET', 'POST'])
def xss_scanner():  # XSS scanning UI
    if request.method == 'POST':
        url = request.form.get('url', '').strip()  # get URL
        if not url:
            flash('Please enter a URL', 'danger')  # require URL
            return render_template('xss_scanner.html')  # render
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url  # default scheme
            
            flash('XSS scan started. This may take a few moments...', 'info')  # notify
            
            # Perform XSS scan
            vulnerabilities = scan_xss_vulnerabilities(url)  # run scanner
            risk_level = calculate_vulnerability_risk(vulnerabilities)  # risk
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'xss', url, json.dumps(vulnerabilities), 
                 f"Found {len(vulnerabilities)} XSS vulnerabilities", 
                 risk_level, datetime.now())
            )  # store result
            db.commit()  # commit
            
            return render_template('xss_scanner.html', 
                                 url=url, 
                                 vulnerabilities=vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True)  # render results
            
        except Exception as e:
            flash(f'Error during XSS scan: {str(e)}', 'danger')  # flash
            print(f"XSS scan error: {e}")  # print error
    
    return render_template('xss_scanner.html')  # render page

@app.route('/tools/csrf_scanner', methods=['GET', 'POST'])
def csrf_scanner():  # CSRF scanning UI
    if request.method == 'POST':
        url = request.form.get('url', '').strip()  # get URL
        if not url:
            flash('Please enter a URL', 'danger')  # require
            return render_template('csrf_scanner.html')  # render
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url  # default
            
            flash('CSRF scan started. This may take a few moments...', 'info')  # notify
            
            # Perform CSRF scan
            vulnerabilities = scan_csrf_vulnerabilities(url)  # run scanner
            risk_level = calculate_vulnerability_risk(vulnerabilities)  # risk
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'csrf', url, json.dumps(vulnerabilities), 
                 f"Found {len(vulnerabilities)} CSRF vulnerabilities", 
                 risk_level, datetime.now())
            )  # store result
            db.commit()  # commit
            
            return render_template('csrf_scanner.html', 
                                 url=url, 
                                 vulnerabilities=vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True)  # render
            
        except Exception as e:
            flash(f'Error during CSRF scan: {str(e)}', 'danger')  # flash
            print(f"CSRF scan error: {e}")  # print error
    
    return render_template('csrf_scanner.html')  # render page

@app.route('/tools/comprehensive_scan', methods=['GET', 'POST'])
def comprehensive_scan():  # run multiple scanners selected by user
    if request.method == 'POST':
        url = request.form.get('url', '').strip()  # target url
        scan_types = request.form.getlist('scan_types')  # selected scan types
        
        if not url:
            flash('Please enter a URL', 'danger')  # require url
            return render_template('comprehensive_scan.html')  # render
        if not scan_types:
            flash('Please select at least one scan type', 'danger')  # require at least one
            return render_template('comprehensive_scan.html')  # render
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url  # default
            
            flash('Comprehensive vulnerability scan started. This may take a few moments...', 'info')  # notify
            
            all_vulnerabilities = []  # collect all findings
            
            if 'sql' in scan_types:
                all_vulnerabilities.extend(scan_sql_injection(url))  # add SQLi findings
            
            if 'xss' in scan_types:
                all_vulnerabilities.extend(scan_xss_vulnerabilities(url))  # add XSS findings
            
            if 'csrf' in scan_types:
                all_vulnerabilities.extend(scan_csrf_vulnerabilities(url))  # add CSRF findings
            
            risk_level = calculate_vulnerability_risk(all_vulnerabilities)  # compute overall risk
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'comprehensive_scan', url, json.dumps(all_vulnerabilities), 
                 f"Found {len(all_vulnerabilities)} vulnerabilities in comprehensive scan", 
                 risk_level, datetime.now())
            )  # store scan result
            db.commit()  # commit
            
            return render_template('comprehensive_scan.html', 
                                 url=url, 
                                 vulnerabilities=all_vulnerabilities,
                                 risk_level=risk_level,
                                 scan_completed=True,
                                 scan_types=scan_types)  # render results
            
        except Exception as e:
            flash(f'Error during comprehensive scan: {str(e)}', 'danger')  # flash
            print(f"Comprehensive scan error: {e}")  # print error
    
    return render_template('comprehensive_scan.html')  # render page

@app.route('/tools/port_scanner', methods=['GET', 'POST'])
def port_scanner():  # port scanner UI
    if request.method == 'POST':
        target = request.form.get('target', '').strip()  # target host
        port_range = request.form.get('port_range', 'common')  # preset or custom
        custom_ports = request.form.get('custom_ports', '').strip()  # custom input
        
        if not target:
            flash('Please enter a target IP or domain', 'danger')  # require
            return render_template('port_scanner.html')  # render
        
        if not is_valid_ip(target):
            flash('Please enter a valid IP address or domain name', 'danger')  # validate
            return render_template('port_scanner.html')  # render
        
        try:
            # Determine which ports to scan
            if port_range == 'common':
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 27017, 6379]  # common ports
            elif port_range == 'custom' and custom_ports:
                try:
                    ports = []
                    for port_str in custom_ports.split(','):
                        port_str = port_str.strip()  # trim
                        if '-' in port_str:
                            start, end = map(int, port_str.split('-'))  # range
                            ports.extend(range(start, end + 1))  # expand range
                        else:
                            ports.append(int(port_str))  # single port
                    ports = list(set(ports))  # deduplicate
                    if len(ports) > 100:
                        flash('Too many ports specified. Maximum 100 ports allowed.', 'warning')  # limit ports
                        ports = ports[:100]  # trim
                except ValueError:
                    flash('Invalid port format. Use commas and/or ranges (e.g., 80,443 or 1-100)', 'danger')  # invalid format
                    return render_template('port_scanner.html')  # render
            else:
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 27017, 6379]  # fallback
            
            flash(f'Port scan started for {target}. Scanning {len(ports)} ports...', 'info')  # notify
            
            # Perform port scan
            open_ports, error = port_scanner_scan(target, ports)  # run scan
            
            if error:
                flash(f'Scan error: {error}', 'danger')  # show error
                return render_template('port_scanner.html')  # render
            
            # Prepare results
            port_results = []
            for port in open_ports:
                port_results.append({
                    'port': port,
                    'service': get_service_name(port),
                    'status': 'Open'
                })  # prepare result entry
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'port_scanner', target, json.dumps(port_results), 
                 f"Found {len(open_ports)} open ports on {target}", 
                 'Medium' if len(open_ports) > 0 else 'Low', datetime.now())
            )  # store result
            db.commit()  # commit
            
            return render_template('port_scanner.html', 
                                 target=target,
                                 port_results=port_results,
                                 total_ports=len(ports),
                                 scan_completed=True)  # render results
            
        except Exception as e:
            flash(f'Error during port scan: {str(e)}', 'danger')  # flash
            print(f"Port scan error: {e}")  # print error
    
    return render_template('port_scanner.html')  # render page

@app.route('/tools/network_diagnostics', methods=['GET', 'POST'])
def network_diagnostics():  # network diagnostics UI (ping/traceroute)
    if request.method == 'POST':
        target = request.form.get('target', '').strip()  # target
        diagnostic_type = request.form.get('diagnostic_type', 'ping')  # chosen diagnostic
        
        if not target:
            flash('Please enter a target IP or domain', 'danger')  # require
            return render_template('network_diagnostics.html')  # render
        
        if not is_valid_ip(target):
            flash('Please enter a valid IP address or domain name', 'danger')  # validate
            return render_template('network_diagnostics.html')  # render
        
        try:
            results = {}  # collect results
            
            if diagnostic_type in ['ping', 'both']:
                flash(f'Pinging {target}...', 'info')  # notify
                ping_success, ping_output, ping_error = ping_host(target)  # call ping_host
                results['ping'] = {
                    'success': ping_success,
                    'output': ping_output,
                    'error': ping_error
                }  # store ping results
            
            if diagnostic_type in ['traceroute', 'both']:
                flash(f'Running traceroute to {target}...', 'info')  # notify
                trace_success, trace_output, trace_error = traceroute_host(target)  # traceroute
                results['traceroute'] = {
                    'success': trace_success,
                    'output': trace_output,
                    'error': trace_error
                }  # store trace results
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'network_diagnostics', target, json.dumps(results), 
                 f"Network diagnostics for {target}", 
                 'Info', datetime.now())
            )  # store results
            db.commit()  # commit
            
            return render_template('network_diagnostics.html', 
                                 target=target,
                                 diagnostic_type=diagnostic_type,
                                 results=results,
                                 scan_completed=True)  # render
            
        except Exception as e:
            flash(f'Error during network diagnostics: {str(e)}', 'danger')  # flash
            print(f"Network diagnostics error: {e}")  # print error
    
    return render_template('network_diagnostics.html')  # render page

@app.route('/security-tools')
def security_tools():  # security tools landing page
    return render_template('security_tools.html')  # render template

@app.route("/ping", methods=["GET", "POST"])
def ping_route():  # simple ping route for UI
    result = None  # default
    if request.method == "POST":
        target = request.form.get("target", "").strip()  # get target
        if target:
            result = ping_host(target)  # ping host
        else:
            result = "⚠️ Please enter a valid host to ping."  # validation message
    return render_template("ping.html", result=result)  # render ping page

@app.route('/tools/security_headers', methods=['GET', 'POST'])
def security_headers_tool():  # analyze HTTP security headers
    if request.method == 'POST':
        url = request.form.get('url', '').strip()  # get URL
        if not url:
            flash('Please enter a URL', 'danger')  # require
            return render_template('security_headers_tool.html')  # render
        
        try:
            # Ensure URL starts with http:// or https://
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url  # default
            
            # Make HEAD request to get headers
            response = requests.head(url, timeout=10, allow_redirects=True)  # send HEAD
            headers = dict(response.headers)  # dict of headers
            
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
            }  # build header analysis
            
            # Calculate overall risk
            risk_count = sum(1 for header in security_headers.values() if header['risk'] in ['high', 'medium'])  # count problematic headers
            overall_risk = 'high' if risk_count >= 3 else 'medium' if risk_count >= 1 else 'low'  # derive overall risk
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'security_headers', url, json.dumps(security_headers), 
                 f"Found {len([h for h in security_headers.values() if h['present']])} security headers", 
                 overall_risk, datetime.now())
            )  # store result
            db.commit()  # commit
            
            return render_template('security_headers_tool.html', 
                                 url=url, 
                                 headers=security_headers, 
                                 overall_risk=overall_risk,
                                 all_headers=headers)  # render analysis
            
        except requests.RequestException as e:
            flash(f'Error scanning URL: {str(e)}', 'danger')  # request error
        except Exception as e:
            flash('An unexpected error occurred', 'danger')  # generic error
            print(f"Security headers scan error: {e}")  # print
    
    return render_template('security_headers_tool.html')  # render page

@app.route('/tools/dns_lookup', methods=['GET', 'POST'])
def dns_lookup_tool():  # DNS lookup UI
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()  # domain input
        record_type = request.form.get('record_type', 'A')  # record type selection
        
        if not domain:
            flash('Please enter a domain name', 'danger')  # require domain
            return render_template('dns_lookup_tool.html')  # render
        
        try:
            results = {}  # collection
            
            if record_type == 'all' or record_type == 'A':
                try:
                    answers = dns.resolver.resolve(domain, 'A')  # query A records
                    results['A'] = [str(rdata) for rdata in answers]  # store
                except:
                    results['A'] = ['No records found']  # fallback
            
            if record_type == 'all' or record_type == 'AAAA':
                try:
                    answers = dns.resolver.resolve(domain, 'AAAA')  # AAAA records
                    results['AAAA'] = [str(rdata) for rdata in answers]  # store
                except:
                    results['AAAA'] = ['No records found']  # fallback
            
            if record_type == 'all' or record_type == 'MX':
                try:
                    answers = dns.resolver.resolve(domain, 'MX')  # MX records
                    results['MX'] = [str(rdata) for rdata in answers]  # store
                except:
                    results['MX'] = ['No records found']  # fallback
            
            if record_type == 'all' or record_type == 'TXT':
                try:
                    answers = dns.resolver.resolve(domain, 'TXT')  # TXT records
                    results['TXT'] = [str(rdata) for rdata in answers]  # store
                except:
                    results['TXT'] = ['No records found']  # fallback
            
            if record_type == 'all' or record_type == 'NS':
                try:
                    answers = dns.resolver.resolve(domain, 'NS')  # NS records
                    results['NS'] = [str(rdata) for rdata in answers]  # store
                except:
                    results['NS'] = ['No records found']  # fallback
            
            # Get WHOIS information
            try:
                whois_info = whois.whois(domain)  # perform WHOIS
                results['WHOIS'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date),
                    'name_servers': whois_info.name_servers
                }  # store WHOIS data
            except:
                results['WHOIS'] = {'error': 'WHOIS information not available'}  # fallback
            
            # Log the scan
            db = get_db()  # get DB
            cursor = db.cursor()  # cursor
            cursor.execute(
                'INSERT INTO scan_results (user_id, tool_type, target_url, scan_data, results, risk_level, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (session.get('user_id'), 'dns_lookup', domain, json.dumps({'record_type': record_type}), 
                 f"DNS lookup for {record_type} records", 
                 'info', datetime.now())
            )  # store lookup action
            db.commit()  # commit
            
            return render_template('dns_lookup_tool.html', 
                                 domain=domain, 
                                 record_type=record_type,
                                 results=results)  # render results
            
        except Exception as e:
            flash(f'Error performing DNS lookup: {str(e)}', 'danger')  # flash
            print(f"DNS lookup error: {e}")  # print
    
    return render_template('dns_lookup_tool.html')  # render page

@app.route('/tools/password-checker')
def password_checker_tool():  # password checker page
    return render_template('password_checker_tool.html')  # render

@app.route('/tools/hash-generator')
def hash_generator_tool():  # hash generator page
    return render_template('hash_generator_tool.html')  # render

@app.route('/scan_history')
@login_required
def scan_history():  # show user's previous scans
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT * FROM scan_results WHERE user_id = %s ORDER BY created_at DESC', (session['user_id'],)
    )  # fetch scans for user
    scans = cursor.fetchall()  # fetch
    return render_template('scan_history.html', scans=scans)  # render

@app.route('/admin/scan_results')
@admin_required
def admin_scan_results():  # admin view recent scan results
    db = get_db()  # get DB
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)  # dict cursor
    cursor.execute(
        'SELECT sr.*, u.name, u.email FROM scan_results sr LEFT JOIN users u ON sr.user_id = u.id ORDER BY sr.created_at DESC LIMIT 100'
    )  # fetch recent scans
    scans = cursor.fetchall()  # fetch
    return render_template('admin_scan_results.html', scans=scans)  # render

@app.route('/debug-login', methods=['POST'])
def debug_login():
    """Debug login to see what's happening during authentication"""
    email = request.form['email']
    password = request.form['password']
    ip_address = request.remote_addr
    
    db = get_db()
    cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = cursor.fetchone()
    
    if user:
        from werkzeug.security import check_password_hash
        password_correct = check_password_hash(user['password_hash'], password)
        
        response = f"""
        User found: {user['email']}<br>
        User ID: {user['id']}<br>
        Role: {user['role']}<br>
        Password correct: {password_correct}<br>
        Session before login: {dict(session)}<br>
        """
        
        if password_correct:
            # Simulate the login process
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            
            response += f"<br>Session after login: {dict(session)}<br>"
            response += f"<br>Login successful! You should be redirected."
        
        return response
    else:
        return "User not found"

@app.route('/check-session')
def check_session():
    """Check current session status"""
    return f"""
    Current session: {dict(session)}<br>
    User ID in session: {'user_id' in session}<br>
    User role: {session.get('user_role', 'None')}<br>
    Session permanent: {session.permanent}<br>
    """

@app.route('/test-admin-access')
@admin_required
def test_admin_access():
    """Test if admin access works"""
    return "Admin access successful! You are logged in as admin."

@app.route('/test-client-access')
@login_required
def test_client_access():
    """Test if regular login works"""
    return "Client access successful! You are logged in."

@app.route('/debug-db')
def debug_db():
    """Debug database connection"""
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT version()')
        version = cursor.fetchone()
        cursor.execute('SELECT current_database()')
        db_name = cursor.fetchone()
        cursor.execute('SELECT current_user')
        user = cursor.fetchone()
        
        return f"""
        Database connection successful!<br>
        PostgreSQL Version: {version['version']}<br>
        Database: {db_name['current_database']}<br>
        User: {user['current_user']}<br>
        Connection details: {db.dsn}<br>
        """
    except Exception as e:
        return f"Database connection failed: {str(e)}"

@app.route('/debug-users')
def debug_users():
    """Debug users table"""
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        
        result = "Users in database:<br>"
        for user in users:
            result += f"ID: {user['id']}, Email: {user['email']}, Role: {user['role']}<br>"
        return result
    except Exception as e:
        return f"Error reading users: {str(e)}"
    
@app.route('/debug-login-process', methods=['POST'])
def debug_login_process():
    """Debug the entire login process step by step"""
    email = request.form['email']
    password = request.form['password']
    ip_address = request.remote_addr
    
    debug_output = []
    
    try:
        # Step 1: Check brute force
        debug_output.append("Step 1: Checking brute force...")
        brute_force = is_brute_force(email, ip_address)
        debug_output.append(f"Brute force result: {brute_force}")
        
        if brute_force:
            return "Blocked by brute force protection"
        
        # Step 2: Get user from database
        debug_output.append("Step 2: Querying database for user...")
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if not user:
            return "User not found"
        
        debug_output.append(f"User found: ID={user['id']}, Email={user['email']}, Role={user['role']}")
        
        # Step 3: Check password
        debug_output.append("Step 3: Checking password...")
        password_correct = check_password_hash(user['password_hash'], password)
        debug_output.append(f"Password correct: {password_correct}")
        
        if not password_correct:
            return "Password incorrect"
        
        # Step 4: Set session
        debug_output.append("Step 4: Setting session data...")
        session.clear()
        session['user_id'] = user['id']
        session['user_email'] = user['email'] 
        session['user_name'] = user['name']
        session['user_role'] = user.get('role', 'user')
        
        debug_output.append(f"Session after setting: {dict(session)}")
        
        # Step 5: Update last login
        debug_output.append("Step 5: Updating last login...")
        cursor.execute(
            'UPDATE users SET last_login = %s WHERE id = %s',
            (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id'])
        )
        db.commit()
        
        # Step 6: Log activities
        debug_output.append("Step 6: Logging activities...")
        log_activity(user['id'], 'login', 'User logged in successfully', ip_address)
        log_login_attempt(email, True, ip_address)
        
        # Step 7: Final session check
        debug_output.append("Step 7: Final session check...")
        session.modified = True
        debug_output.append(f"Final session: {dict(session)}")
        
        return "<br>".join(debug_output)
        
    except Exception as e:
        debug_output.append(f"ERROR: {str(e)}")
        return "<br>".join(debug_output)
    
@app.route('/debug-brute-force')
def debug_brute_force():
    """Debug the brute force detection"""
    email = 'admin@21centurysolutions.com'
    ip_address = '127.0.0.1'  # Mock IP for testing
    
    try:
        db = get_db()
        cursor = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Check login_attempts table exists and has data
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name = 'login_attempts'
        """)
        table_exists = cursor.fetchone()
        
        if not table_exists:
            return "login_attempts table does not exist"
        
        # Count recent failures
        cursor.execute(
            'SELECT COUNT(*) as count FROM login_attempts WHERE email = %s AND ip_address = %s AND success = 0 AND attempted_at > %s',
            (email, ip_address, (datetime.now() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S'))
        )
        recent_failures = cursor.fetchone()
        
        return f"Brute force check: Table exists: {table_exists is not None}, Recent failures: {recent_failures['count']}"
        
    except Exception as e:
        return f"Brute force debug error: {str(e)}"
    
    
