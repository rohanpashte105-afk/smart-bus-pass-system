from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_bcrypt import Bcrypt
import mysql.connector
from mysql.connector import Error
import os
from datetime import datetime,timedelta
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_change_this_in_production'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'applications'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'stamps'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'signatures'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Convert a stored upload path (e.g., 'applications/filename.png') into a URL under /static/uploads
def get_file_url(file_path):
    if not file_path:
        return None
    try:
        safe_path = file_path.replace('\\', '/').replace('\\', '/')
        return url_for('static', filename='uploads/' + safe_path)
    except Exception:
        return None
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True

bcrypt = Bcrypt(app)


# Add cache control headers
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456',
    'database': 'bus_pass_system'
}

# Database connection helper
def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        print("✅ Database connection successful!")
        return conn
    except Error as e:
        print(f"❌ Error connecting to MySQL: {e}")
        return None

# Database initialization
def init_db():
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='123456'
    )
    
    if conn is None:
        print("❌ Failed to connect to database for initialization")
        return
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("CREATE DATABASE IF NOT EXISTS bus_pass_system")
        cursor.execute("USE bus_pass_system")
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            phone VARCHAR(20),
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            college_id VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Ensure profile_photo_path exists for older databases
        try:
            cursor.execute("ALTER TABLE applications ADD COLUMN IF NOT EXISTS profile_photo_path VARCHAR(500) NULL")
        except Exception as _:
            try:
                cursor.execute("ALTER TABLE applications ADD COLUMN profile_photo_path VARCHAR(500) NULL")
            except Exception:
                pass
        

        # Admins table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(100) DEFAULT 'MSRTC Administrator',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # College Admins table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS college_admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            username VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            college_name VARCHAR(255),
            college_code VARCHAR(50),
            default_stamp_path VARCHAR(500),
            default_signature_path VARCHAR(500),
            role VARCHAR(100) DEFAULT 'College Administrator',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        # Ensure new columns exist for older databases
        try:
            cursor.execute("ALTER TABLE college_admins ADD COLUMN IF NOT EXISTS default_stamp_path VARCHAR(500) NULL")
        except Exception:
            try:
                cursor.execute("ALTER TABLE college_admins ADD COLUMN default_stamp_path VARCHAR(500) NULL")
            except Exception:
                pass
        try:
            cursor.execute("ALTER TABLE college_admins ADD COLUMN IF NOT EXISTS default_signature_path VARCHAR(500) NULL")
        except Exception:
            try:
                cursor.execute("ALTER TABLE college_admins ADD COLUMN default_signature_path VARCHAR(500) NULL")
            except Exception:
                pass
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            application_type VARCHAR(50) NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            college_verification_date TIMESTAMP NULL,
            admin_approval_date TIMESTAMP NULL,
            
            -- Personal Information
            full_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            phone VARCHAR(20),
            date_of_birth DATE,
            gender VARCHAR(10),
            address TEXT,
            
            -- Application Details
            route_details TEXT,
            pass_type VARCHAR(100),
            duration VARCHAR(50),
            from_location VARCHAR(255),
            to_location VARCHAR(255),
            
            -- Institution Information
            institution_name VARCHAR(255),
            institution_address TEXT,
            student_id VARCHAR(100),
            course VARCHAR(100),
            year_of_study VARCHAR(50),
            
            -- File Uploads
            id_proof_path VARCHAR(500),
            signature_path VARCHAR(500),
            profile_photo_path VARCHAR(500),
            
            -- College Admin Actions
            college_admin_id INT NULL,
            college_stamp_path VARCHAR(500),
            college_signature_path VARCHAR(500),
            college_verification_notes TEXT,
            
            -- Admin Actions
            admin_id INT NULL,
            admin_stamp_path VARCHAR(500),
            admin_signature_path VARCHAR(500),
            admin_approval_notes TEXT,
            
            -- Pass Generation
            pass_number VARCHAR(100) NULL,
            pass_valid_from DATE NULL,
            pass_valid_until DATE NULL,
            pass_status VARCHAR(50) DEFAULT 'pending',
            
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (college_admin_id) REFERENCES college_admins(id) ON DELETE SET NULL,
            FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
        )
        ''')
                
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            application_id INT NOT NULL,
            pass_number VARCHAR(100) UNIQUE NOT NULL,
            pass_type VARCHAR(100) NOT NULL,
            duration VARCHAR(50) NOT NULL,
            from_location VARCHAR(255) NOT NULL,
            to_location VARCHAR(255) NOT NULL,
            institution_name VARCHAR(255),
            student_id VARCHAR(100),
            course VARCHAR(100),
            year_of_study VARCHAR(50),
            issue_date DATE NOT NULL,
            expiry_date DATE NOT NULL,
            status VARCHAR(50) DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            application_id INT NULL,
            message TEXT NOT NULL,
            type VARCHAR(50) NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL
     )
     ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            application_id INT NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            pass_type VARCHAR(100) NOT NULL,
            duration VARCHAR(50) NOT NULL,
            payment_method VARCHAR(50) NOT NULL,
            payment_status VARCHAR(50) DEFAULT 'pending',
            transaction_id VARCHAR(255) NULL,
            payment_date DATETIME DEFAULT NULL,
            gateway_response TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
        )
        ''')
        
        
        conn.commit()
        print("✅ Database initialized successfully!")
        
    except Error as e:
        print(f"❌ Error initializing database: {e}")
    finally:
        cursor.close()
        conn.close()

def ensure_payments_table(cursor):
    """Ensure the payments table exists. Safe to call multiple times."""
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            application_id INT NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            pass_type VARCHAR(100) NOT NULL,
            duration VARCHAR(50) NOT NULL,
            payment_method VARCHAR(50) NOT NULL,
            payment_status VARCHAR(50) DEFAULT 'pending',
            transaction_id VARCHAR(255) NULL,
            payment_date DATETIME DEFAULT NULL,
            gateway_response TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
        )
    ''')

# Payment calculation function
def calculate_payment_amount(pass_type, duration):
    """Calculate payment amount based on pass type and duration"""
    # Base prices for different pass types (in INR)
    base_prices = {
        'monthly': 500,
        'quarterly': 1400,
        'semester': 2500,
        'annual': 4500
    }
    
    # Duration multipliers
    duration_multipliers = {
        '1-month': 1.0,
        '3-months': 2.8,  # Slight discount for longer duration
        '6-months': 5.4,  # Better discount for 6 months
        '1-year': 10.0    # Best discount for annual
    }
    
    # Get base price for pass type
    base_price = base_prices.get(pass_type, 500)  # Default to monthly if not found
    
    # Get duration multiplier
    multiplier = duration_multipliers.get(duration, 1.0)
    
    # Calculate final amount
    amount = base_price * multiplier
    
    return round(amount, 2)

# Initialize the database when app starts
with app.app_context():
    init_db()



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
        
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        
        cursor.execute('SELECT * FROM applications WHERE user_id = %s ORDER BY submission_date DESC', (session['user_id'],))
        applications = cursor.fetchall()
        
        # Get active pass from passes table
        cursor.execute('''
            SELECT p.*, a.admin_approval_date 
            FROM passes p 
            LEFT JOIN applications a ON p.application_id = a.id 
            WHERE p.user_id = %s AND p.status = "active" AND p.expiry_date >= CURDATE() 
            ORDER BY p.issue_date DESC LIMIT 1
        ''', (session['user_id'],))
        active_pass = cursor.fetchone()
        
        # Calculate dashboard statistics using passes table
        # 1. Active Passes Count
        cursor.execute('''
            SELECT COUNT(*) as count FROM passes 
            WHERE user_id = %s AND status = "active" AND expiry_date >= CURDATE()
        ''', (session['user_id'],))
        active_passes = cursor.fetchone()['count']
        
        # 2. Days Remaining for active pass
        days_remaining = 0
        if active_pass and active_pass.get('expiry_date'):
            expiry_date = active_pass['expiry_date']
            if isinstance(expiry_date, str):
                expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d').date()
            days_remaining = (expiry_date - datetime.now().date()).days
            days_remaining = max(0, days_remaining)  # Ensure it's not negative
        
        # Active pass profile photo URL (for My Pass section)
        active_profile_photo_url = None
        if active_pass and active_pass.get('application_id'):
            cursor.execute('SELECT profile_photo_path FROM applications WHERE id = %s', (active_pass['application_id'],))
            app_row = cursor.fetchone()
            if app_row and app_row.get('profile_photo_path'):
                active_profile_photo_url = get_file_url(app_row.get('profile_photo_path'))
        
        # 3. Pending Applications Count
        cursor.execute('SELECT COUNT(*) as count FROM applications WHERE user_id = %s AND status = "pending"', (session['user_id'],))
        pending_applications = cursor.fetchone()['count']
        
        # 4. Total Applications Count
        cursor.execute('SELECT COUNT(*) as count FROM applications WHERE user_id = %s AND status != "payment_required"', (session['user_id'],))
        total_applications = cursor.fetchone()['count']
        
        # 5. Previous passes (not active)
        cursor.execute('''
            SELECT * FROM passes 
            WHERE user_id = %s AND status != 'active'
            ORDER BY issue_date DESC
        ''', (session['user_id'],))
        pass_history = cursor.fetchall()

       
        # Fetch notifications for user
        cursor.execute('''
            SELECT * FROM notifications 
            WHERE user_id = %s 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''', (session['user_id'],))
        notifications = cursor.fetchall()
        
        # Count unread notifications
        notification_count = len([n for n in notifications if not n.get('is_read', False)])


        return render_template(
            'user.html',
            user=user,
            applications=applications,
            active_pass=active_pass,
            active_profile_photo_url=active_profile_photo_url,
            active_passes=active_passes,
            days_remaining=days_remaining,
            pending_applications=pending_applications,
            total_applications=total_applications,
            pass_history=pass_history,
            current_date=datetime.now().date(),
            notifications=notifications,
            notification_count=notification_count
        )
    except Error as e:
        flash(f'Database error: {e}', 'danger')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in'}), 401
    
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    college_id = request.form.get('college_id')
    username = request.form.get('username')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Check if username already exists (if it's being changed)
        if username != session['username']:
            cursor.execute('SELECT id FROM users WHERE username = %s AND id != %s', (username, session['user_id']))
            existing_user = cursor.fetchone()
            if existing_user:
                return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        # Update user profile
        cursor.execute(
            'UPDATE users SET full_name = %s, phone = %s, college_id = %s, username = %s WHERE id = %s',
            (full_name, phone, college_id, username, session['user_id'])
        )
        conn.commit()
        
        # Update session data
        session['full_name'] = full_name
        session['username'] = username
        
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Error as e:
        return jsonify({'success': False, 'message': f'Error updating profile: {str(e)}'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in'}), 401
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'}), 400
    
    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Get current password hash
        cursor.execute('SELECT password FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not bcrypt.check_password_hash(user['password'], current_password):
            return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
        
        # Hash new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # Update password
        cursor.execute(
            'UPDATE users SET password = %s, last_password_change = NOW() WHERE id = %s',
            (hashed_password, session['user_id'])
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Error as e:
        return jsonify({'success': False, 'message': f'Error changing password: {str(e)}'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/update_notifications', methods=['POST'])
def update_notifications():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in'}), 401
    
    email_notifications = 'email_notifications' in request.form
    sms_notifications = 'sms_notifications' in request.form
    pass_expiry_notifications = 'pass_expiry_notifications' in request.form
    application_updates = 'application_updates' in request.form
    promotional_notifications = 'promotional_notifications' in request.form
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            '''UPDATE users SET 
                email_notifications = %s, 
                sms_notifications = %s,
                pass_expiry_notifications = %s,
                application_updates = %s,
                promotional_notifications = %s
            WHERE id = %s''',
            (email_notifications, sms_notifications, pass_expiry_notifications, 
             application_updates, promotional_notifications, session['user_id'])
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Notification preferences updated successfully'})
    except Error as e:
        return jsonify({'success': False, 'message': f'Error updating preferences: {str(e)}'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/register', methods=['POST'])
def register():
    print("📨 Registration request received")
    
    if request.method == 'POST':
        full_name = request.form.get('signupName')
        email = request.form.get('signupEmail')
        phone = request.form.get('signupPhone')
        username = request.form.get('signupUsername')
        password = request.form.get('signupPassword')
        
        print(f"📝 Form data: {full_name}, {email}, {username}")
        
        if not all([full_name, email, phone, username, password]):
            flash('Please fill all required fields', 'danger')
            print("❌ Validation failed: Missing fields")
            return redirect(url_for('index'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db_connection()
        if conn is None:
            flash('Database connection error', 'danger')
            print("❌ Database connection failed")
            return redirect(url_for('index'))
            
        cursor = conn.cursor(dictionary=True)
        # Ensure payments table exists (handles case where server wasn't restarted)
        ensure_payments_table(cursor)
        try:
            cursor.execute(
                'INSERT INTO users (full_name, email, phone, username, password) VALUES (%s, %s, %s, %s, %s)',
                (full_name, email, phone, username, hashed_password)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            print("✅ User registered successfully!")
            
        except mysql.connector.IntegrityError as e:
            error_msg = str(e)
            if 'Duplicate entry' in error_msg and 'username' in error_msg:
                flash('Username already exists', 'danger')
                print("❌ Username already exists")
            elif 'Duplicate entry' in error_msg and 'email' in error_msg:
                flash('Email already exists', 'danger')
                print("❌ Email already exists")
            else:
                flash('Registration error. Please try again.', 'danger')
                print(f"❌ Integrity error: {error_msg}")
                
        except Error as e:
            flash('Registration error. Please try again.', 'danger')
            print(f"❌ Database error: {e}")
            
        finally:
            cursor.close()
            conn.close()
        
        return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    print("📨 Login request received")
    
    if request.method == 'POST':
        username = request.form.get('loginUsername')
        password = request.form.get('loginPassword')
        remember_me = request.form.get('rememberMe')
        
        print(f"📝 Login attempt: {username}")
        
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return redirect(url_for('index'))
        
        conn = get_db_connection()
        if conn is None:
            flash('Database connection error', 'danger')
            return redirect(url_for('index'))
            
        cursor = conn.cursor(dictionary=True)
        try:
            # CASE-SENSITIVE username check
            cursor.execute('SELECT * FROM users WHERE BINARY username = %s', (username,))
            user = cursor.fetchone()
            
            if user:
                print(f"✅ User found: {user['username']}")
                if bcrypt.check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['full_name'] = user['full_name']
                    session['email'] = user['email']
                    
                    session.permanent = bool(remember_me)
                    
                    flash('Login successful!', 'success')
                    print("✅ Login successful!")
                    return redirect(url_for('user_dashboard'))
                else:
                    flash('Invalid password', 'danger')
                    print("❌ Invalid password")
            else:
                flash('Username not found', 'danger')
                print("❌ Username not found")
                
            return redirect(url_for('index'))
                
        except Error as e:
            flash('Login error. Please try again.', 'danger')
            print(f"❌ Login error: {e}")
            return redirect(url_for('index'))
        finally:
            cursor.close()
            conn.close()

@app.route('/logout')
def logout():
    print("🚪 Logout attempt detected")
    print(f"📋 Session before clear: {dict(session)}")
    
    session.clear()
    
    print("✅ Session cleared")
    print(f"📋 Session after clear: {dict(session)}")
    
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('index'))

# -------------------- Application Routes --------------------
@app.route('/submit_application', methods=['POST'])
def submit_application():
    if 'user_id' not in session:
        flash('Please log in to submit an application', 'danger')
        return redirect(url_for('index'))
    
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return redirect(url_for('user_dashboard'))
        
        cursor = conn.cursor(dictionary=True)
        # Ensure payments table exists before using it
        ensure_payments_table(cursor)
        
        # Get form data
        application_type = request.form.get('applicationType')
        full_name = request.form.get('fullName')
        email = request.form.get('email')
        phone = request.form.get('phone')
        date_of_birth = request.form.get('dateOfBirth')
        gender = request.form.get('gender')
        address = request.form.get('address')
        route_details = request.form.get('routeDetails')
        # Optional computed fare fields from the New Application route step
        calc_distance_km = request.form.get('calc_distance_km')
        calc_normal_per_trip = request.form.get('calc_normal_per_trip')
        calc_student_per_trip = request.form.get('calc_student_per_trip')
        calc_student_monthly = request.form.get('calc_student_monthly')
        pass_type = request.form.get('passType')
        duration = request.form.get('duration')
        from_location = request.form.get('fromLocation')
        to_location = request.form.get('toLocation')
        institution_name = request.form.get('institutionName')
        institution_address = request.form.get('institutionAddress')
        student_id = request.form.get('studentId')
        course = request.form.get('course')
        year_of_study = request.form.get('yearOfStudy')
        
        # Handle file uploads
        id_proof_path = None
        signature_path = None
        profile_photo_path = None
        
        if 'idProof' in request.files:
            id_proof_file = request.files['idProof']
            if id_proof_file and id_proof_file.filename and allowed_file(id_proof_file.filename):
                filename = secure_filename(f"{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_idproof_{id_proof_file.filename}")
                id_proof_path = os.path.join('applications', filename)
                id_proof_file.save(os.path.join(app.config['UPLOAD_FOLDER'], id_proof_path))
        
        if 'signature' in request.files:
            signature_file = request.files['signature']
            if signature_file and signature_file.filename and allowed_file(signature_file.filename):
                filename = secure_filename(f"{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_signature_{signature_file.filename}")
                signature_path = os.path.join('applications', filename)
                signature_file.save(os.path.join(app.config['UPLOAD_FOLDER'], signature_path))
        
        if 'profilePhoto' in request.files:
            photo_file = request.files['profilePhoto']
            if photo_file and photo_file.filename and allowed_file(photo_file.filename):
                filename = secure_filename(f"{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_photo_{photo_file.filename}")
                profile_photo_path = os.path.join('applications', filename)
                photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], profile_photo_path))
        
        # Calculate payment amount
        payment_amount = calculate_payment_amount(pass_type, duration)
        # If user provided computed fare details (single-route calculator), prefer student monthly for payment
        try:
            if calc_student_monthly:
                sm = float(calc_student_monthly)
                if sm > 0:
                    # Determine number of months based on selected duration
                    months_map = {
                        '1-month': 1,
                        '3-months': 3,
                        '6-months': 6,
                        '1-year': 12
                    }
                    months = months_map.get(duration, 1)
                    payment_amount = round(sm * months, 2)
        except Exception:
            pass
        
        # Insert application into database with payment_required status
        insert_query = '''
        INSERT INTO applications (
            user_id, application_type, full_name, email, phone, date_of_birth, gender, address,
            route_details, pass_type, duration, from_location, to_location,
            institution_name, institution_address, student_id, course, year_of_study,
            id_proof_path, signature_path, profile_photo_path, status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'payment_required')
        '''
        
        cursor.execute(insert_query, (
            session['user_id'], application_type, full_name, email, phone, date_of_birth, gender, address,
            route_details, pass_type, duration, from_location, to_location,
            institution_name, institution_address, student_id, course, year_of_study,
            id_proof_path, signature_path, profile_photo_path
        ))
        
        application_id = cursor.lastrowid
        
        # Create payment record
        payment_query = '''
        INSERT INTO payments (
            user_id, application_id, amount, pass_type, duration, payment_method, payment_status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        '''
        
        cursor.execute(payment_query, (
            session['user_id'], application_id, payment_amount, pass_type, duration, 'pending', 'pending'
        ))
        
        conn.commit()
        
        # Store application and payment details in session for payment page
        session['pending_application_id'] = application_id
        session['payment_amount'] = payment_amount
        session['pass_details'] = {
            'pass_type': pass_type,
            'duration': duration,
            'from_location': from_location,
            'to_location': to_location,
            'distance_km': calc_distance_km,
            'normal_per_trip': calc_normal_per_trip,
            'student_per_trip': calc_student_per_trip,
            'student_monthly': calc_student_monthly,
            'computed_total_amount': payment_amount
        }
        
        return redirect(url_for('payment_page'))
        
    except Error as e:
        print(f"❌ Error submitting application: {e}")
        flash('Error submitting application. Please try again.', 'danger')
        if conn:
            conn.rollback()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
    
    return redirect(url_for('user_dashboard'))

# -------------------- Payment Routes --------------------
@app.route('/payment')
def payment_page():
    if 'user_id' not in session or 'pending_application_id' not in session:
        flash('No pending payment found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('payment.html', 
                         amount=session.get('payment_amount'),
                         pass_details=session.get('pass_details'),
                         application_id=session.get('pending_application_id'))

@app.route('/process_payment', methods=['POST'])
def process_payment():
    if 'user_id' not in session or 'pending_application_id' not in session:
        return jsonify({'success': False, 'message': 'No pending payment found'}), 400
    
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'message': 'Database connection error'}), 500
        
        cursor = conn.cursor(dictionary=True)
        # Ensure payments table exists before using it
        ensure_payments_table(cursor)
        
        # Get form data
        payment_method = request.form.get('payment_method')
        card_number = request.form.get('card_number', '')
        upi_id = request.form.get('upi_id', '')
        
        application_id = session['pending_application_id']
        
        # Simulate payment processing (in real implementation, integrate with payment gateway)
        import random
        import string
        
        # Generate transaction ID
        transaction_id = 'TXN' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        
        # Simulate payment success (90% success rate for demo)
        payment_success = random.random() > 0.1
        
        if payment_success:
            # Update payment record
            cursor.execute('''
                UPDATE payments SET 
                    payment_method = %s, 
                    payment_status = 'completed',
                    transaction_id = %s,
                    gateway_response = %s,
                    updated_at = NOW()
                WHERE application_id = %s AND user_id = %s
            ''', (payment_method, transaction_id, 'Payment successful', application_id, session['user_id']))
            
            # Update application status to pending (ready for college verification)
            cursor.execute('''
                UPDATE applications SET status = 'pending' 
                WHERE id = %s AND user_id = %s
            ''', (application_id, session['user_id']))
            
            conn.commit()
            
            # Clear session data
            session.pop('pending_application_id', None)
            session.pop('payment_amount', None)
            session.pop('pass_details', None)
            
            return jsonify({
                'success': True, 
                'message': 'Payment successful! Your application has been submitted for review.',
                'transaction_id': transaction_id
            })
        else:
            # Update payment record with failure
            cursor.execute('''
                UPDATE payments SET 
                    payment_method = %s,
                    payment_status = 'failed',
                    transaction_id = %s,
                    gateway_response = %s,
                    updated_at = NOW()
                WHERE application_id = %s AND user_id = %s
            ''', (payment_method, transaction_id, 'Payment failed', application_id, session['user_id']))
            
            conn.commit()
            
            return jsonify({
                'success': False, 
                'message': 'Payment failed. Please try again.',
                'transaction_id': transaction_id
            })
            
    except Error as e:
        print(f"❌ Error processing payment: {e}")
        return jsonify({'success': False, 'message': 'Error processing payment'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/payment_success')
def payment_success():
    return render_template('payment_success.html')

@app.route('/admin/get_application_details/<int:application_id>')
def get_application_details(application_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT a.*, 
                   u.full_name as user_name, 
                   u.email as user_email, 
                   u.phone as user_phone,
                   ca.full_name as college_admin_name,
                   ca.college_name
            FROM applications a
            JOIN users u ON a.user_id = u.id
            LEFT JOIN college_admins ca ON a.college_admin_id = ca.id
            WHERE a.id = %s
        ''', (application_id,))
        
        application = cursor.fetchone()
        
        if not application:
            return jsonify({'success': False, 'message': 'Application not found'}), 404
        
        # Convert file paths to URLs using global helper
        
        application_data = {
            'id': application['id'],
            'user_name': application['user_name'],
            'user_email': application['user_email'],
            'user_phone': application['user_phone'],
            'application_type': application['application_type'],
            'status': application['status'],
            'submission_date': application['submission_date'].isoformat() if application['submission_date'] else None,
            'route_details': application['route_details'],
            'pass_type': application['pass_type'],
            'duration': application['duration'],
            'from_location': application['from_location'],
            'to_location': application['to_location'],
            'institution_name': application['institution_name'],
            'student_id': application['student_id'],
            'course': application['course'],
            'id_proof_path': get_file_url(application['id_proof_path']),
            'signature_path': get_file_url(application['signature_path']),
            'profile_photo_path': get_file_url(application.get('profile_photo_path')),
            'college_stamp_path': get_file_url(application['college_stamp_path']),
            'college_signature_path': get_file_url(application['college_signature_path']),
            'college_admin_name': application['college_admin_name'],
            'college_name': application['college_name']
        }
        
        return jsonify({'success': True, 'application': application_data})
        
    except Error as e:
        print(f"❌ Error fetching application details: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/college/verify_application/<int:application_id>', methods=['POST'])
def college_verify_application(application_id):
    if 'college_admin_id' not in session:
        flash('Please log in as college administrator', 'danger')
        return redirect(url_for('index'))
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return redirect(url_for('college_admin_dashboard'))

        cursor = conn.cursor(dictionary=True)

        action = request.form.get('action')  # 'verify' or 'reject'
        notes = request.form.get('notes', '')

        # Get application details first to get user_id
        cursor.execute('SELECT user_id FROM applications WHERE id = %s', (application_id,))
        application = cursor.fetchone()

        if not application:
            flash('Application not found', 'danger')
            return redirect(url_for('college_admin_dashboard'))

        # Handle file uploads
        college_stamp_path = None
        college_signature_path = None

        if 'collegeStamp' in request.files:
            stamp_file = request.files['collegeStamp']
            if stamp_file and stamp_file.filename and allowed_file(stamp_file.filename):
                filename = secure_filename(f"stamp_{application_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{stamp_file.filename}")
                college_stamp_path = os.path.join('stamps', filename)
                stamp_file.save(os.path.join(app.config['UPLOAD_FOLDER'], college_stamp_path))

        if 'collegeSignature' in request.files:
            signature_file = request.files['collegeSignature']
            if signature_file and signature_file.filename and allowed_file(signature_file.filename):
                filename = secure_filename(f"signature_{application_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{signature_file.filename}")
                college_signature_path = os.path.join('signatures', filename)
                signature_file.save(os.path.join(app.config['UPLOAD_FOLDER'], college_signature_path))

        # If verify and no files uploaded, fall back to defaults from college_admins
        if action == 'verify' and (college_stamp_path is None or college_signature_path is None):
            cursor.execute('SELECT default_stamp_path, default_signature_path FROM college_admins WHERE id = %s', (session['college_admin_id'],))
            defaults = cursor.fetchone()
            if defaults:
                if college_stamp_path is None:
                    college_stamp_path = defaults.get('default_stamp_path')
                if college_signature_path is None:
                    college_signature_path = defaults.get('default_signature_path')

        # Update application status
        if action == 'verify':
            status = 'verified'
            message = 'Application verified successfully!'
            notification_type = 'verified'
            notification_msg = f'Your application #{application_id} has been verified by college administrator'
        else:
            status = 'rejected'
            message = 'Application rejected.'
            notification_type = 'rejected'
            notification_msg = f'Your application #{application_id} has been rejected by college administrator'

        update_query = '''
        UPDATE applications SET 
            status = %s, college_admin_id = %s, college_verification_date = NOW(),
            college_stamp_path = %s, college_signature_path = %s, college_verification_notes = %s
        WHERE id = %s
        '''

        cursor.execute(update_query, (
            status, session['college_admin_id'], college_stamp_path, college_signature_path, notes, application_id
        ))

        # Create notification for the user
        create_notification(application['user_id'], application_id, notification_msg, notification_type)

        conn.commit()
        flash(message, 'success')

    except Error as e:
        print(f"❌ Error verifying application: {e}")
        flash('Error processing application. Please try again.', 'danger')
        if conn:
            conn.rollback()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

    return redirect(url_for('college_admin_dashboard'))

# -------------------- College Admin Settings --------------------
@app.route('/college/update_settings', methods=['POST'])
def college_update_settings():
    if 'college_admin_id' not in session:
        flash('Please log in as college administrator', 'danger')
        return redirect(url_for('index'))

    college_name = request.form.get('college_name', '').strip()
    college_code = request.form.get('college_code', '').strip()

    default_stamp_path = None
    default_signature_path = None

    # Handle default stamp upload
    if 'defaultStamp' in request.files:
        stamp_file = request.files['defaultStamp']
        if stamp_file and stamp_file.filename and allowed_file(stamp_file.filename):
            filename = secure_filename(f"default_stamp_{session['college_admin_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{stamp_file.filename}")
            default_stamp_path = os.path.join('stamps', filename)
            stamp_file.save(os.path.join(app.config['UPLOAD_FOLDER'], default_stamp_path))

    # Handle default signature upload
    if 'defaultSign' in request.files:
        sign_file = request.files['defaultSign']
        if sign_file and sign_file.filename and allowed_file(sign_file.filename):
            filename = secure_filename(f"default_sign_{session['college_admin_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{sign_file.filename}")
            default_signature_path = os.path.join('signatures', filename)
            sign_file.save(os.path.join(app.config['UPLOAD_FOLDER'], default_signature_path))

    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('college_admin_dashboard'))
    cursor = conn.cursor(dictionary=True)
    try:
        # Build dynamic update
        update_fields = []
        params = []
        if college_name:
            update_fields.append('college_name = %s')
            params.append(college_name)
        if college_code:
            update_fields.append('college_code = %s')
            params.append(college_code)
        if default_stamp_path:
            update_fields.append('default_stamp_path = %s')
            params.append(default_stamp_path)
        if default_signature_path:
            update_fields.append('default_signature_path = %s')
            params.append(default_signature_path)

        if update_fields:
            query = 'UPDATE college_admins SET ' + ', '.join(update_fields) + ' WHERE id = %s'
            params.append(session['college_admin_id'])
            cursor.execute(query, tuple(params))
            conn.commit()

        # Update session for display on page
        if college_name:
            session['college_name'] = college_name
        if college_code:
            session['college_code'] = college_code

        flash('Settings updated successfully', 'success')
    except Error as e:
        if conn:
            conn.rollback()
        print(f"❌ Error updating college settings: {e}")
        flash('Failed to update settings', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('college_admin_dashboard'))

@app.route('/mark_notifications_read', methods=['POST'])
def mark_notifications_read():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in'}), 401
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Mark all user's notifications as read
        cursor.execute(
            'UPDATE notifications SET is_read = TRUE WHERE user_id = %s',
            (session['user_id'],)
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Notifications marked as read'})
    except Error as e:
        print(f"❌ Error marking notifications as read: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# Helper function to create notifications
def create_notification(user_id, application_id, message, notification_type):
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            'INSERT INTO notifications (user_id, application_id, message, type) VALUES (%s, %s, %s, %s)',
            (user_id, application_id, message, notification_type)
        )
        conn.commit()
        return True
    except Error as e:
        print(f"❌ Error creating notification: {e}")
        return False
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/admin/approve_application/<int:application_id>', methods=['POST'])
def admin_approve_application(application_id):
    if 'admin_id' not in session:
        flash('Please log in as administrator', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        action = request.form.get('action')  # 'approve' or 'reject'
        notes = request.form.get('notes', '')
        
        # Get application details first to get user_id and other info
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email 
            FROM applications a 
            JOIN users u ON a.user_id = u.id 
            WHERE a.id = %s
        ''', (application_id,))
        application = cursor.fetchone()
        
        if not application:
            flash('Application not found', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Handle file uploads
        admin_stamp_path = None
        admin_signature_path = None
        
        if 'adminStamp' in request.files:
            stamp_file = request.files['adminStamp']
            if stamp_file and stamp_file.filename and allowed_file(stamp_file.filename):
                filename = secure_filename(f"admin_stamp_{application_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{stamp_file.filename}")
                admin_stamp_path = os.path.join('stamps', filename)
                stamp_file.save(os.path.join(app.config['UPLOAD_FOLDER'], admin_stamp_path))
        
        if 'adminSignature' in request.files:
            signature_file = request.files['adminSignature']
            if signature_file and signature_file.filename and allowed_file(signature_file.filename):
                filename = secure_filename(f"admin_signature_{application_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{signature_file.filename}")
                admin_signature_path = os.path.join('signatures', filename)
                signature_file.save(os.path.join(app.config['UPLOAD_FOLDER'], admin_signature_path))
        
        # Update application status
        if action == 'approve':
            status = 'approved'
            pass_status = 'active'
            pass_number = f"BP{application_id:06d}"
            pass_valid_from = datetime.now().date()
            
            # Determine duration days from application['duration']
            duration_map = {
                '1-month': 30,
                '3-months': 90,
                '6-months': 180,
                '1-year': 365
            }
            duration_days = duration_map.get(str(application['duration']).lower(), 30)
            pass_valid_until = pass_valid_from + timedelta(days=duration_days)
            message = 'Application approved and pass generated successfully!'
            
            # Insert into passes table
            cursor.execute('''
                INSERT INTO passes (
                    user_id, application_id, pass_number, pass_type, duration, 
                    from_location, to_location, institution_name, student_id, 
                    course, year_of_study, issue_date, expiry_date, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                application['user_id'], application_id, pass_number, 
                application['pass_type'], application['duration'],
                application['from_location'], application['to_location'],
                application['institution_name'], application['student_id'],
                application['course'], application['year_of_study'],
                pass_valid_from, pass_valid_until, 'active'
            ))
            
            # Create notification for the user
            notification_msg = f'Your application #{application_id} has been approved. Your pass number is {pass_number}'
            create_notification(application['user_id'], application_id, notification_msg, 'approved')
            
        else:
            status = 'rejected'
            pass_status = 'rejected'
            pass_number = None
            pass_valid_from = None
            pass_valid_until = None
            message = 'Application rejected.'
            
            # Create notification for the user
            notification_msg = f'Your application #{application_id} has been rejected by MSRTC administrator'
            if notes:
                notification_msg += f'. Reason: {notes}'
            create_notification(application['user_id'], application_id, notification_msg, 'rejected')
        
        # Update the application record
        update_query = '''
        UPDATE applications SET 
            status = %s, admin_id = %s, admin_approval_date = NOW(),
            admin_stamp_path = %s, admin_signature_path = %s, admin_approval_notes = %s,
            pass_number = %s, pass_valid_from = %s, pass_valid_until = %s, pass_status = %s
        WHERE id = %s
        '''
        
        cursor.execute(update_query, (
            status, session['admin_id'], admin_stamp_path, admin_signature_path, notes,
            pass_number, pass_valid_from, pass_valid_until, pass_status, application_id
        ))
        
        conn.commit()
        flash(message, 'success')
        
    except Error as e:
        print(f"❌ Error approving application: {e}")
        flash('Error processing application. Please try again.', 'danger')
        if conn:
            conn.rollback()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/send_pass/<int:application_id>', methods=['POST'])
def admin_send_pass(application_id: int):
    if 'admin_id' not in session:
        flash('Please log in as administrator', 'danger')
        return redirect(url_for('index'))
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('admin_dashboard'))
    cursor = conn.cursor(dictionary=True)
    try:
        # Mark pass as sent (you could also queue email/sms here)
        cursor.execute("UPDATE applications SET pass_status = %s WHERE id = %s", ('sent', application_id))
        conn.commit()
        flash('Pass sent to user successfully', 'success')
    except Error as e:
        if conn:
            conn.rollback()
        print(f"❌ Error sending pass: {e}")
        flash('Failed to send pass. Please try again.', 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/renew_pass', methods=['POST'])
def renew_pass():
    if 'user_id' not in session:
        flash('Please log in to renew your pass', 'danger')
        return redirect(url_for('index'))
    
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return redirect(url_for('user_dashboard'))
        
        cursor = conn.cursor(dictionary=True)
        
        # Get the current active pass to renew
        cursor.execute('''
            SELECT * FROM passes 
            WHERE user_id = %s AND status = "active" AND expiry_date >= CURDATE() 
            ORDER BY issue_date DESC LIMIT 1
        ''', (session['user_id'],))
        current_pass = cursor.fetchone()
        
        if not current_pass:
            flash('No active pass found to renew', 'danger')
            return redirect(url_for('user_dashboard'))
        
        # Get form data
        duration = request.form.get('duration')
        
        # Handle signature upload
        signature_path = None
        if 'signature' in request.files:
            signature_file = request.files['signature']
            if signature_file and signature_file.filename and allowed_file(signature_file.filename):
                filename = secure_filename(f"{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_signature_{signature_file.filename}")
                signature_path = os.path.join('applications', filename)
                signature_file.save(os.path.join(app.config['UPLOAD_FOLDER'], signature_path))
        
        # Calculate new expiry date based on duration
        current_expiry = current_pass['expiry_date']
        if isinstance(current_expiry, str):
            current_expiry = datetime.strptime(current_expiry, '%Y-%m-%d').date()
        
        duration_days = 0
        if duration == '1-month':
            duration_days = 30
        elif duration == '3-months':
            duration_days = 90
        elif duration == '6-months':
            duration_days = 180
        elif duration == '1-year':
            duration_days = 365
        
        new_expiry_date = current_expiry + timedelta(days=duration_days)
        
        # Create a renewal application
        insert_query = '''
        INSERT INTO applications (
            user_id, application_type, full_name, email, phone, 
            route_details, pass_type, duration, from_location, to_location,
            institution_name, student_id, course, year_of_study,
            signature_path, status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
        '''
        
        cursor.execute(insert_query, (
            session['user_id'], 'renewal', current_pass['full_name'], 
            session['email'], session.get('phone'), 
            f"{current_pass['from_location']} to {current_pass['to_location']}", 
            current_pass['pass_type'], duration, current_pass['from_location'], 
            current_pass['to_location'], current_pass['institution_name'], 
            current_pass['student_id'], current_pass['course'], 
            current_pass['year_of_study'], signature_path
        ))
        
        application_id = cursor.lastrowid
        
        # Mark current pass as renewed
        cursor.execute('''
            UPDATE passes SET status = 'renewed' 
            WHERE id = %s
        ''', (current_pass['id'],))
        
        conn.commit()
        flash('Renewal application submitted successfully! It will be reviewed by your college administrator.', 'success')
        
    except Error as e:
        print(f"❌ Error submitting renewal application: {e}")
        flash('Error submitting renewal application. Please try again.', 'danger')
        if conn:
            conn.rollback()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
    
    return redirect(url_for('user_dashboard'))

@app.route('/admin/notify_user/<int:application_id>', methods=['POST'])
def admin_notify_user(application_id: int):
    if 'admin_id' not in session:
        flash('Please log in as administrator', 'danger')
        return redirect(url_for('index'))
    # Placeholder for notification (email/SMS). For now, just flash.
    flash('User has been notified.', 'info')
    return redirect(url_for('admin_dashboard'))


@app.route('/user/view_pass/<int:application_id>')
def user_view_pass(application_id: int):
    if 'user_id' not in session:
        flash('Please log in to view your pass', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('user_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM applications 
            WHERE id = %s AND user_id = %s AND status = 'approved' AND pass_number IS NOT NULL
        """, (application_id, session['user_id']))
        application = cursor.fetchone()
        
        if not application:
            flash('Pass not found or not approved yet', 'danger')
            return redirect(url_for('user_dashboard'))
        
        # Normalize file paths to URLs for template image rendering
        application['profile_photo_url'] = get_file_url(application.get('profile_photo_path'))
        application['signature_url'] = get_file_url(application.get('signature_path'))
        application['college_stamp_url'] = get_file_url(application.get('college_stamp_path'))
        application['college_signature_url'] = get_file_url(application.get('college_signature_path'))
        application['admin_stamp_url'] = get_file_url(application.get('admin_stamp_path'))
        application['admin_signature_url'] = get_file_url(application.get('admin_signature_path'))
        
        return render_template('pass_view.html', application=application)
        
    except Error as e:
        print(f"❌ Error viewing pass: {e}")
        flash('Error loading pass', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()


@app.route('/user/download_pass/<int:application_id>')
def user_download_pass(application_id: int):
    if 'user_id' not in session:
        flash('Please log in to download your pass', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('user_dashboard'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM applications 
            WHERE id = %s AND user_id = %s AND status = 'approved' AND pass_number IS NOT NULL
        """, (application_id, session['user_id']))
        application = cursor.fetchone()
        
        if not application:
            flash('Pass not found or not approved yet', 'danger')
            return redirect(url_for('user_dashboard'))
        
        # Generate PDF pass
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.utils import ImageReader
        import io, os
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Header bar
        p.setFillColorRGB(0.1, 0.3, 0.6)
        p.rect(50, height-150, width-100, 100, fill=1)
        p.setFillColorRGB(1, 1, 1)
        p.setFont("Helvetica-Bold", 24)
        p.drawString(60, height-80, "MSRTC BUS PASS")
        p.setFont("Helvetica", 12)
        p.drawString(60, height-100, f"Pass No: {application['pass_number']}")
        p.drawString(60, height-115, f"Valid: {application['pass_valid_from']} to {application['pass_valid_until']}")
        
        # Identification block: Photo and Signature with overlays
        y_top = height - 200
        # Draw photo frame
        p.setFillColorRGB(0.95, 0.95, 0.95)
        p.roundRect(60, y_top-180, 110, 140, 6, stroke=1, fill=1)
        # Load and draw profile photo if available
        if application.get('profile_photo_path'):
            try:
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], application['profile_photo_path'])
                if os.path.exists(photo_path):
                    img = ImageReader(photo_path)
                    p.drawImage(img, 62, y_top-178, width=106, height=136, preserveAspectRatio=True, mask='auto')
            except Exception as _:
                pass
        # Overlay college stamp on photo
        if application.get('college_stamp_path'):
            try:
                stamp_path = os.path.join(app.config['UPLOAD_FOLDER'], application['college_stamp_path'])
                if os.path.exists(stamp_path):
                    img = ImageReader(stamp_path)
                    p.drawImage(img, 60+110-45, y_top-180+5, width=40, height=40, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass
        
        # Signature box
        p.setFillColorRGB(1, 1, 1)
        p.roundRect(200, y_top-120, 220, 80, 6, stroke=1, fill=1)
        p.setFont("Helvetica", 9)
        p.setFillColorRGB(0.3, 0.3, 0.3)
        p.drawString(205, y_top-35, "Signature")
        if application.get('signature_path'):
            try:
                sig_path = os.path.join(app.config['UPLOAD_FOLDER'], application['signature_path'])
                if os.path.exists(sig_path):
                    img = ImageReader(sig_path)
                    p.drawImage(img, 202, y_top-118, width=216, height=76, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass
        # Overlay admin stamp and signatures
        if application.get('admin_stamp_path'):
            try:
                a_stamp = os.path.join(app.config['UPLOAD_FOLDER'], application['admin_stamp_path'])
                if os.path.exists(a_stamp):
                    p.drawImage(ImageReader(a_stamp), 200+220-48, y_top-120+4, width=44, height=44, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass
        if application.get('admin_signature_path'):
            try:
                a_sig = os.path.join(app.config['UPLOAD_FOLDER'], application['admin_signature_path'])
                if os.path.exists(a_sig):
                    p.drawImage(ImageReader(a_sig), 205, y_top-120+4, width=90, height=30, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass
        if application.get('college_signature_path'):
            try:
                c_sig = os.path.join(app.config['UPLOAD_FOLDER'], application['college_signature_path'])
                if os.path.exists(c_sig):
                    p.drawImage(ImageReader(c_sig), 205, y_top-120+40, width=90, height=30, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass
        
        # User details
        p.setFillColorRGB(0, 0, 0)
        p.setFont("Helvetica-Bold", 16)
        p.drawString(60, y_top-210, "PASS HOLDER DETAILS")
        p.setFont("Helvetica", 12)
        p.drawString(60, y_top-230, f"Name: {application['full_name']}")
        p.drawString(60, y_top-245, f"Route: {application['route_details']}")
        p.drawString(60, y_top-260, f"Pass Type: {application['pass_type']}")
        p.drawString(60, y_top-275, f"Duration: {application['duration']}")
        if application.get('institution_name'):
            p.drawString(60, y_top-290, f"Institution: {application['institution_name']}")
            if application.get('student_id'):
                p.drawString(60, y_top-305, f"Student ID: {application['student_id']}")
        
        p.showPage()
        p.save()
        
        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"MSRTC_Pass_{application['pass_number']}.pdf",
            mimetype='application/pdf'
        )
        
    except Error as e:
        print(f"❌ Error downloading pass: {e}")
        flash('Error generating pass', 'danger')
        return redirect(url_for('user_dashboard'))
    finally:
        cursor.close()
        conn.close()


# -------------------- Admin Authentication --------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        # Show the standard login modal via home; user can submit a dedicated admin form to this endpoint
        flash('Enter admin credentials to continue', 'info')
        return redirect(url_for('index'))

    username = request.form.get('loginUsername')
    password = request.form.get('loginPassword')
    print(f"📨 Admin login attempt: username={username}")
    if not username or not password:
        flash('Please enter both username and password', 'danger')
        return redirect(url_for('index'))

    conn = get_db_connection()
    if conn is None:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT * FROM admins WHERE BINARY username = %s', (username,))
        admin = cursor.fetchone()
        print(f"🔎 Admin found: {bool(admin)}")
        if admin:
            pw_ok = False
            try:
                pw_ok = bcrypt.check_password_hash(admin['password'], password)
            except Exception as e:
                print(f"❌ Bcrypt check error: {e}")
            print(f"🔐 Password match: {pw_ok}")
        if admin and pw_ok:
            session.clear()
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            session['admin_full_name'] = admin['full_name']
            session['admin_role'] = admin.get('role') if isinstance(admin, dict) else 'MSRTC Administrator'
            flash('Admin login successful', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'danger')
        return redirect(url_for('index'))
    except Error as e:
        flash('Login error. Please try again.', 'danger')
        print(f"❌ Admin login error: {e}")
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash('Please log in as admin to access dashboard', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Count pending applications for the sidebar badge
        cursor.execute('SELECT COUNT(*) as count FROM applications WHERE status = "verified"')
        pending_applications_count = cursor.fetchone()['count']
        
        # Fetch real notifications
        cursor.execute('''
            (SELECT 
                a.id,
                CONCAT('New application from ', u.full_name) as message,
                a.submission_date as timestamp,
                'new_application' as type
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.status = 'verified'
            ORDER BY a.submission_date DESC
            LIMIT 3)
            
            UNION ALL
            
            (SELECT 
                p.id,
                CONCAT('Pass renewal request from ', u.full_name) as message,
                p.created_at as timestamp,
                'renewal_request' as type
            FROM passes p
            JOIN users u ON p.user_id = u.id
            JOIN applications a ON p.application_id = a.id
            WHERE a.application_type = 'renewal'
            ORDER BY p.created_at DESC
            LIMIT 2)
            
            ORDER BY timestamp DESC
            LIMIT 5
        ''')
        notifications = cursor.fetchall()
        
        notification_count = len(notifications)

        # Fetch verified applications waiting for admin approval
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email, u.phone as user_phone,
                   ca.full_name as college_admin_name, ca.college_name
            FROM applications a
            JOIN users u ON a.user_id = u.id
            LEFT JOIN college_admins ca ON a.college_admin_id = ca.id
            WHERE a.status = 'verified'
            ORDER BY a.college_verification_date DESC
        ''')
        verified_applications = cursor.fetchall()
        
        # Fetch approved applications
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email, u.phone as user_phone,
                   ca.full_name as college_admin_name, ca.college_name
            FROM applications a
            JOIN users u ON a.user_id = u.id
            LEFT JOIN college_admins ca ON a.college_admin_id = ca.id
            WHERE a.status = 'approved'
            ORDER BY a.admin_approval_date DESC
        ''')
        approved_applications = cursor.fetchall()
        
        # Fetch rejected applications
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email, u.phone as user_phone,
                   ca.full_name as college_admin_name, ca.college_name
            FROM applications a
            JOIN users u ON a.user_id = u.id
            LEFT JOIN college_admins ca ON a.college_admin_id = ca.id
            WHERE a.status = 'rejected'
            ORDER BY a.admin_approval_date DESC
        ''')
        rejected_applications = cursor.fetchall()
        
        # Fetch pending applications for dashboard
        cursor.execute('''
            SELECT a.*, u.full_name as user_name
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.status = 'verified'
            ORDER BY a.college_verification_date DESC
        ''')
        pending_applications = cursor.fetchall()
        
        # Fetch all applications for pass management
        cursor.execute('SELECT * FROM applications')
        all_applications = cursor.fetchall()
        
        # Fetch passes with pagination
        page = request.args.get('page', 1, type=int)
        per_page = 10
        offset = (page - 1) * per_page
        
        cursor.execute('SELECT COUNT(*) as count FROM passes')
        total_pass_count = cursor.fetchone()['count']
        total_pages = (total_pass_count + per_page - 1) // per_page
        
        cursor.execute('SELECT * FROM passes ORDER BY issue_date DESC LIMIT %s OFFSET %s', (per_page, offset))
        passes = cursor.fetchall()

        # Fetch successful payments
        try:
            cursor.execute('''
                SELECT 
                    p.*, 
                    u.full_name AS user_name,
                    a.pass_type AS application_pass_type,
                    a.duration AS application_duration
                FROM payments p
                JOIN users u ON p.user_id = u.id
                JOIN applications a ON p.application_id = a.id
                WHERE p.payment_status = 'success'
                ORDER BY COALESCE(p.payment_date, p.created_at) DESC
            ''')
            payments = cursor.fetchall()
        except Error as e:
            print(f"❌ Error fetching payments: {e}")
            payments = []
        
        # Count statistics for dashboard
        cursor.execute('SELECT COUNT(*) as count FROM applications WHERE status = "verified"')
        pending_count = cursor.fetchone()['count']
        
        # placeholder removed
        cursor.execute('SELECT COUNT(*) as count FROM applications WHERE status = "approved" AND MONTH(admin_approval_date) = MONTH(CURDATE())')
        approved_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM applications WHERE status = "rejected"')
        rejected_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM passes WHERE status = "active" AND expiry_date >= CURDATE()')
        active_passes_count = cursor.fetchone()['count']
        
        # Get recent activities (last 5)
        cursor.execute('''
            (SELECT 
                a.admin_approval_date AS timestamp,
                CASE WHEN a.status = 'approved' THEN 'Application Approved' ELSE 'Application Rejected' END AS activity_type,
                u.full_name AS user_name,
                CASE WHEN a.status = 'approved' 
                     THEN CONCAT('Application ', a.id, ' approved') 
                     ELSE CONCAT('Application ', a.id, ' rejected by admin') 
                END AS details
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.admin_approval_date IS NOT NULL
            ORDER BY a.admin_approval_date DESC
            LIMIT 5)
            
            UNION ALL
            
            (SELECT 
                a.college_verification_date AS timestamp,
                CASE WHEN a.status = 'rejected' THEN 'Application Rejected' ELSE 'Application Verified' END AS activity_type,
                u.full_name AS user_name,
                CASE WHEN a.status = 'rejected' 
                     THEN CONCAT('Application ', a.id, ' rejected by college') 
                     ELSE CONCAT('Application ', a.id, ' verified by college') 
                END AS details
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.college_verification_date IS NOT NULL
            ORDER BY a.college_verification_date DESC
            LIMIT 5)
            
            UNION ALL
            
            (SELECT 
                p.created_at AS timestamp,
                'Pass Generated' AS activity_type,
                u.full_name AS user_name,
                CONCAT('Pass ', p.pass_number, ' generated') AS details
            FROM passes p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT 5)
            
            ORDER BY timestamp DESC
            LIMIT 5
        ''')
        recent_activities = cursor.fetchall()
        # Get data for reports
        # Monthly statistics for the last 6 months
        cursor.execute('''
            SELECT 
                DATE_FORMAT(submission_date, '%Y-%m') as month,
                COUNT(*) as total_applications,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
            FROM applications 
            WHERE submission_date >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(submission_date, '%Y-%m')
            ORDER BY month DESC
        ''')
        monthly_stats = cursor.fetchall()
        
        # Pass type statistics
        cursor.execute('''
            SELECT 
                pass_type,
                SUM(CASE WHEN status = 'active' AND expiry_date >= CURDATE() THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'active' AND expiry_date < CURDATE() THEN 1 ELSE 0 END) as expired,
                COUNT(*) as total
            FROM passes 
            GROUP BY pass_type
        ''')
        pass_type_stats = cursor.fetchall()
        
        # Applications by month for chart (last 6 months)
        cursor.execute('''
            SELECT 
                DATE_FORMAT(submission_date, '%b %Y') as month_name,
                COUNT(*) as applications_received,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as applications_approved
            FROM applications 
            WHERE submission_date >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(submission_date, '%Y-%m'), month_name
            ORDER BY MIN(submission_date)
        ''')
        chart_data = cursor.fetchall()
        
        # Pass distribution for chart
        cursor.execute('''
            SELECT 
                pass_type,
                COUNT(*) as count
            FROM passes 
            GROUP BY pass_type
        ''')
        pass_distribution = cursor.fetchall()
        
        # Default dates for report form
        default_date_from = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        default_date_to = datetime.now().strftime('%Y-%m-%d')
        
    except Error as e:
        print(f"❌ Error fetching report data: {e}")
        monthly_stats = []
        pass_type_stats = []
        chart_data = []
        pass_distribution = []
        default_date_from = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        default_date_to = datetime.now().strftime('%Y-%m-%d')
        notifications = []
        notification_count = 0
        verified_applications = []
        approved_applications = []
        rejected_applications = []
        pending_applications = []
        all_applications = []
        passes = []
        payments = []
        total_pass_count = 0
        total_pages = 1
        page = 1
        pending_count = 0
        approved_count = 0
        rejected_count = 0
        active_passes_count = 0
        recent_activities = []
    finally:
        cursor.close()
        conn.close()
    
    # Build a lightweight current_user object for template convenience
    current_user = {
        'full_name': session.get('admin_full_name', 'Admin User'),
        'role': session.get('admin_role', 'MSRTC Administrator'),
        'username': session.get('admin_username', 'admin')
    }
    
    current_date = datetime.now().date()
    
    return render_template('admin.html', 
                         current_user=current_user,
                         verified_applications=verified_applications,
                         approved_applications=approved_applications,
                         rejected_applications=rejected_applications,
                         pending_applications=pending_applications,
                         all_applications=all_applications,
                         passes=passes,
                         payments=payments,
                         total_pass_count=total_pass_count,
                         total_pages=total_pages,
                         current_page=page,
                         current_date=current_date,
                         pending_count=pending_count,
                         approved_count=approved_count,
                         rejected_count=rejected_count,
                         active_passes_count=active_passes_count,
                         recent_activities=recent_activities,
                         pending_applications_count=pending_applications_count,
                         notifications=notifications,
                         notification_count=notification_count,
                         monthly_stats=monthly_stats,
                         pass_type_stats=pass_type_stats,
                         chart_data=chart_data,
                         pass_distribution=pass_distribution,
                         default_date_from=default_date_from,
                         default_date_to=default_date_to)
@app.route('/admin/generate_report', methods=['POST'])
def admin_generate_report():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.get_json()
    report_type = data.get('reportType')
    date_from = data.get('dateFrom')
    date_to = data.get('dateTo')
    pass_type = data.get('passType')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        if report_type == 'applications':
            query = '''
                SELECT a.id, a.full_name, a.application_type, a.status, 
                       a.submission_date, a.institution_name
                FROM applications a
                WHERE a.submission_date BETWEEN %s AND %s
            '''
            params = [date_from, date_to + ' 23:59:59']
            
            if pass_type != 'all':
                query += ' AND a.pass_type = %s'
                params.append(pass_type)
                
            query += ' ORDER BY a.submission_date DESC'
            
        elif report_type == 'pass_issuance':
            query = '''
                SELECT p.pass_number, a.full_name, p.pass_type, p.issue_date, 
                       p.expiry_date, p.status
                FROM passes p
                JOIN applications a ON p.application_id = a.id
                WHERE p.issue_date BETWEEN %s AND %s
            '''
            params = [date_from, date_to]
            
            if pass_type != 'all':
                query += ' AND p.pass_type = %s'
                params.append(pass_type)
                
            query += ' ORDER BY p.issue_date DESC'
            
        elif report_type == 'revenue':
            # This is a simplified revenue calculation
            query = '''
                SELECT 
                    DATE_FORMAT(p.issue_date, '%Y-%m') as month,
                    p.pass_type,
                    COUNT(*) as issued_passes,
                    COUNT(*) * 
                    CASE 
                        WHEN p.pass_type = 'student' THEN 500
                        WHEN p.pass_type = 'worker' THEN 800
                        WHEN p.pass_type = 'senior' THEN 300
                        ELSE 600
                    END as revenue
                FROM passes p
                WHERE p.issue_date BETWEEN %s AND %s
            '''
            params = [date_from, date_to]
            
            if pass_type != 'all':
                query += ' AND p.pass_type = %s'
                params.append(pass_type)
                
            query += " GROUP BY DATE_FORMAT(p.issue_date, '%Y-%m'), p.pass_type"
            
        elif report_type == 'demographics':
            query = '''
                SELECT 
                    CASE 
                        WHEN TIMESTAMPDIFF(YEAR, a.date_of_birth, CURDATE()) BETWEEN 18 AND 25 THEN '18-25'
                        WHEN TIMESTAMPDIFF(YEAR, a.date_of_birth, CURDATE()) BETWEEN 26 AND 40 THEN '26-40'
                        WHEN TIMESTAMPDIFF(YEAR, a.date_of_birth, CURDATE()) > 40 THEN '40+'
                        ELSE 'Unknown'
                    END as age_group,
                    a.gender,
                    p.pass_type,
                    COUNT(*) as count
                FROM passes p
                JOIN applications a ON p.application_id = a.id
                WHERE p.issue_date BETWEEN %s AND %s
            '''
            params = [date_from, date_to]
            
            if pass_type != 'all':
                query += ' AND p.pass_type = %s'
                params.append(pass_type)
                
            query += ' GROUP BY age_group, a.gender, p.pass_type'
            
        else:
            return jsonify({'success': False, 'message': 'Invalid report type'})
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        return jsonify({'success': True, 'results': results})
        
    except Error as e:
        print(f"❌ Error generating report: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
            
@app.route('/admin/revoke_pass/<int:pass_id>', methods=['POST'])
def admin_revoke_pass(pass_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Update pass status to revoked
        cursor.execute('UPDATE passes SET status = "revoked", updated_at = NOW() WHERE id = %s', (pass_id,))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Pass revoked successfully'})
        
    except Error as e:
        print(f"❌ Error revoking pass: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# -------------------- College Admin Authentication --------------------
@app.route('/college/login', methods=['GET', 'POST'])
def college_admin_login():
    if request.method == 'GET':
        flash('Enter college admin credentials to continue', 'info')
        return redirect(url_for('index'))

    username = request.form.get('loginUsername')
    password = request.form.get('loginPassword')
    print(f"📨 College admin login attempt: username={username}")
    if not username or not password:
        flash('Please enter both username and password', 'danger')
        return redirect(url_for('index'))

    conn = get_db_connection()
    if conn is None:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT * FROM college_admins WHERE BINARY username = %s', (username,))
        cadmin = cursor.fetchone()
        print(f"🔎 College admin found: {bool(cadmin)}")
        if cadmin:
            pw_ok = False
            try:
                pw_ok = bcrypt.check_password_hash(cadmin['password'], password)
            except Exception as e:
                print(f"❌ Bcrypt check error: {e}")
            print(f"🔐 Password match: {pw_ok}")
        if cadmin and pw_ok:
            session.clear()
            session['college_admin_id'] = cadmin['id']
            session['college_admin_username'] = cadmin['username']
            session['college_admin_full_name'] = cadmin['full_name']
            session['college_name'] = cadmin.get('college_name') if isinstance(cadmin, dict) else ''
            session['college_code'] = cadmin.get('college_code') if isinstance(cadmin, dict) else ''
            flash('College admin login successful', 'success')
            return redirect(url_for('college_admin_dashboard'))
        flash('Invalid college admin credentials', 'danger')
        return redirect(url_for('index'))
    except Error as e:
        flash('Login error. Please try again.', 'danger')
        print(f"❌ College admin login error: {e}")
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

@app.route('/college/dashboard')
def college_admin_dashboard():
    if 'college_admin_id' not in session:
        flash('Please log in as college admin to access dashboard', 'danger')
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('index'))
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch pending applications
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email, u.phone as user_phone
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.status = 'pending'
            ORDER BY a.submission_date DESC
        ''')
        pending_applications = cursor.fetchall()
        
        # Fetch verified applications
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email, u.phone as user_phone
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.status = 'verified'
            ORDER BY a.college_verification_date DESC
        ''')
        verified_applications = cursor.fetchall()
        
        # Fetch rejected applications
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email, u.phone as user_phone
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.status = 'rejected'
            ORDER BY a.college_verification_date DESC
        ''')
        rejected_applications = cursor.fetchall()
        
    except Error as e:
        print(f"❌ Error fetching applications: {e}")
        pending_applications = []
        verified_applications = []
        rejected_applications = []
    finally:
        cursor.close()
        conn.close()
    
    college = {
        'name': session.get('college_name', ''),
        'code': session.get('college_code', '')
    }
    
    return render_template('collegeAdmin.html', 
                         college=college,
                         pending_applications=pending_applications,
                         verified_applications=verified_applications,
                         rejected_applications=rejected_applications)

@app.route('/college/application/<int:application_id>/details')
def college_application_details(application_id: int):
    if 'college_admin_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db'}), 500

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT a.*, u.full_name as user_name, u.email as user_email, u.phone as user_phone
            FROM applications a
            JOIN users u ON a.user_id = u.id
            WHERE a.id = %s
        ''', (application_id,))
        app_row = cursor.fetchone()
        if not app_row:
            return jsonify({'error': 'not_found'}), 404

        # Build response
        def fmt_date(dt):
            try:
                return dt.strftime('%d %b %Y') if dt else None
            except Exception:
                return None

        from flask import url_for as _url_for

        stamp_url = None
        if app_row.get('college_stamp_path'):
            stamp_url = _url_for('static', filename=os.path.join('uploads', app_row['college_stamp_path']))
        sign_url = None
        if app_row.get('college_signature_path'):
            sign_url = _url_for('static', filename=os.path.join('uploads', app_row['college_signature_path']))

        resp = {
            'id': app_row['id'],
            'name': app_row.get('user_name') or app_row.get('full_name'),
            'submitted': fmt_date(app_row.get('submission_date')),
            'verifiedOn': fmt_date(app_row.get('college_verification_date')),
            'course': app_row.get('course'),
            'route': f"{app_row.get('from_location') or ''} 2 {app_row.get('to_location') or ''}",
            'institute': app_row.get('institution_name'),
            'studentId': app_row.get('student_id'),
            'status': app_row.get('status'),
            'notes': app_row.get('college_verification_notes'),
            'stampUrl': stamp_url,
            'signUrl': sign_url,
        }
        return jsonify(resp)
    except Error as e:
        print(f"❌ Error fetching application details: {e}")
        return jsonify({'error': 'server'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/debug/users')
def debug_users():
    conn = get_db_connection()
    if conn is None:
        return "Database connection failed"
        
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return jsonify(users)

@app.route('/test-db')
def test_db():
    conn = get_db_connection()
    if conn and conn.is_connected():
        return "✅ Database connected successfully!"
    else:
        return "❌ Database connection failed!"

if __name__ == '__main__':
    app.run(debug=True, port=5000)