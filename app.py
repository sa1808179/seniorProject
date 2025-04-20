import random
import re
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from config import SECRET_KEY, DATABASE
import jwt
import datetime
from db.database import init_db, connect_db
from langchain_groq import ChatGroq
from prompts import SYSTEM
import hashlib
from functools import wraps

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = SECRET_KEY

# Initialize the database
init_db()

# Define role constants
ROLE_STUDENT = 0
ROLE_ADMIN = 1
ROLE_ADVISOR = 2
ROLE_ITSTAFF = 3

# -- Helper to decode JWT and fetch user info --
def get_current_user():
    token = session.get('token')
    if not token:
        return None
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return decoded
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_user_role_name(role_id):
    roles = {
        ROLE_STUDENT: "Student",
        ROLE_ADMIN: "Admin",
        ROLE_ADVISOR: "Advisor",
        ROLE_ITSTAFF: "IT Staff"
    }
    return roles.get(role_id, "Unknown")

# Role-based access control decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute('SELECT isadmin FROM Users WHERE user_id = ?', (user['user_id'],))
            result = cursor.fetchone()
            conn.close()
            
            if not result or result[0] not in roles:
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# -- Routes --
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    otp_required = False
    
    if request.method == 'POST':
        # Retrieve submitted form values
        username = request.form.get('user', '').strip()
        password = request.form.get('password', '')
        otp_input = request.form.get('otp')
        # Determine if we are in OTP stage
        otp_stage = 'otp' in request.form
        
        # First stage: credentials only
        if not otp_stage:
            if not (username and password):
                return render_template('login.html', error='Username and password required', otp_required=False)
                
            # Hash and verify credentials
            hashed_pw = hash_password(password)
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT user_id, username, isadmin FROM Users WHERE username = ? AND password = ?',
                (username, hashed_pw)
            )
            user = cursor.fetchone()
            conn.close()
            
            if not user:
                return render_template('login.html', error='Invalid username or password', otp_required=False)
                
            user_id, user_name, isadmin = user
            # Generate OTP, store in session, print to console
            otp_code = f"{random.randint(100000,999999)}"
            session['otp_value'] = otp_code
            session['pending_user'] = {
                'user_id': user_id,
                'username': user_name,
                'isadmin': isadmin
            }
            role_name = get_user_role_name(isadmin)
            print(f"OTP for {user_name} (role: {role_name}): {otp_code}")
            # Prompt for OTP input
            return render_template('login.html', otp_required=True)
            
        # Second stage: OTP verification
        else:
            saved = session.get('pending_user')
            saved_otp = session.get('otp_value')
            
            if not saved or not saved_otp:
                # Missing session data, restart login
                return render_template('login.html', error='Session expired. Please login again.', otp_required=False)
                
            if not otp_input or otp_input != saved_otp:
                # Invalid OTP
                return render_template('login.html', error='Invalid OTP! Try again.', otp_required=True)
                
            # OTP valid: set up the session and issue JWT
            session.pop('otp_value', None)
            session.pop('pending_user', None)
            
            # Create JWT token
            token = jwt.encode({
                'user_id': saved['user_id'],
                'username': saved['username'],
                'isadmin': saved['isadmin'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            session['token'] = token
            
            # Also store user info in session
            session['user'] = {
                'user_id': saved['user_id'],
                'username': saved['username'],
                'isadmin': saved['isadmin']
            }
            
            # Redirect based on role
            if saved['isadmin'] in [ROLE_ADMIN, ROLE_ADVISOR, ROLE_ITSTAFF]:
                return redirect(url_for('admin_dashboard'))
            else:  # isadmin == ROLE_STUDENT (0)
                return redirect(url_for('dashboard'))
    
    # GET request: show credentials form
    return render_template('login.html', error=error, otp_required=otp_required)

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    # 1. All fields required
    if not (username and email and password):
        return render_template('login.html', error='All fields are required!')

    # 2. Email must be qu.edu.qa
    if not email.endswith('@qu.edu.qa'):
        return render_template('login.html', error='Email must end with @qu.edu.qa')

    # 3. Password policy: 8+ chars, one special
    if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return render_template(
            'login.html',
            error='Password must be at least 8 characters long and include a special character'
        )

    # 4. Hash the password
    hashed = hash_password(password)

    conn = connect_db()
    cursor = conn.cursor()

    # 5. Unique username/email
    cursor.execute(
        'SELECT 1 FROM Users WHERE email = ? OR username = ?',
        (email, username)
    )
    if cursor.fetchone():
        conn.close()
        return render_template('login.html', error='Email or Username already exists!')

    # 6. Insert as student (isadmin = ROLE_STUDENT)
    cursor.execute(
        'INSERT INTO Users (username, email, password, isadmin) VALUES (?, ?, ?, ?)',
        (username, email, hashed, ROLE_STUDENT)
    )
    conn.commit()
    conn.close()

    return render_template('login.html', success='User registered successfully!')

@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=user['username'], isadmin=user['isadmin'])

@app.route('/faqs')
def faqs():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('faqs.html', username=user['username'], isadmin=user['isadmin'])

@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    # Fetch advisors and admin status
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT advisor_id, name FROM Advisors')
    advisors = cursor.fetchall()
    
    if request.method == 'POST':
        advisor_id = request.form.get('advisor_id')
        appointment_date = request.form.get('appointment_date')
        time_slot = request.form.get('time_slot')
        if not (advisor_id and appointment_date and time_slot):
            conn.close()
            return render_template('book_appointment.html', error='All fields are required!',
                                   username=user['username'], isadmin=user['isadmin'], advisors=advisors)
        cursor.execute(
            'SELECT slot_id FROM Time_Slots WHERE advisor_id = ? AND available_date = ? '
            'AND time_slot = ? AND is_booked = 0',
            (advisor_id, appointment_date, time_slot)
        )
        slot = cursor.fetchone()
        if not slot:
            conn.close()
            return render_template('book_appointment.html', error='Time slot not available!',
                                   username=user['username'], isadmin=user['isadmin'], advisors=advisors)
        slot_id = slot[0]
        cursor.execute('UPDATE Time_Slots SET is_booked = 1 WHERE slot_id = ?', (slot_id,))
        cursor.execute(
            'INSERT INTO Appointments (student_id, slot_id, advisor_id) VALUES (?, ?, ?)',
            (user['user_id'], slot_id, advisor_id)
        )
        conn.commit()
        conn.close()
        return render_template('book_appointment.html', success='Appointment booked!',
                               username=user['username'], isadmin=user['isadmin'], advisors=advisors)

    # GET
    cursor.execute('SELECT slot_id, available_date, time_slot FROM Time_Slots WHERE is_booked = 0')
    slots = cursor.fetchall()
    conn.close()
    return render_template('book_appointment.html', username=user['username'], isadmin=user['isadmin'],
                           advisors=advisors, slots=slots)

@app.route('/api/advisors', methods=['GET'])
def get_advisors():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT advisor_id, name FROM Advisors')
    advisors = cursor.fetchall()
    conn.close()
    return jsonify([{'id': a[0], 'name': a[1]} for a in advisors])

@app.route('/api/available_slots', methods=['GET'])
def get_available_slots():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT slot_id, available_date, time_slot, advisor_id FROM Time_Slots WHERE is_booked = 0')
    slots = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': s[0], 'available_date': s[1], 'time_slot': s[2], 'advisor_id': s[3]}
        for s in slots
    ])

@app.route('/api/book_appointment', methods=['POST'])
def book_appointment_api():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json
    student_id = user['user_id']  # Force using the logged-in user's ID for security
    advisor_id = data.get('advisor_id')
    appointment_date = data.get('appointment_date')
    time_slot = data.get('time_slot')
    
    if not (advisor_id and appointment_date and time_slot):
        return jsonify({'error': 'All fields are required'}), 400
        
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT slot_id FROM Time_Slots WHERE advisor_id = ? AND available_date = ? '
        'AND time_slot = ? AND is_booked = 0',
        (advisor_id, appointment_date, time_slot)
    )
    slot = cursor.fetchone()
    if not slot:
        conn.close()
        return jsonify({'error': 'Time slot not available'}), 400
    slot_id = slot[0]
    cursor.execute('UPDATE Time_Slots SET is_booked = 1 WHERE slot_id = ?', (slot_id,))
    cursor.execute(
        'INSERT INTO Appointments (student_id, slot_id, advisor_id) VALUES (?, ?, ?)',
        (student_id, slot_id, advisor_id)
    )
    conn.commit()
    conn.close()
    return jsonify({'message': 'Booked successfully!'}), 201

@app.route('/api/slots', methods=['GET'])
def get_slots():
    advisor_id = request.args.get('advisor_id')
    date = request.args.get('date')
    if not (advisor_id and date):
        return jsonify({'error': 'Missing advisor_id or date'}), 400
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT time_slot FROM Time_Slots WHERE advisor_id = ? AND available_date = ? AND is_booked = 0',
        (advisor_id, date)
    )
    times = cursor.fetchall()
    conn.close()
    return jsonify([{'time_slot': t[0]} for t in times])

# -- Admin Panel --
@app.route('/admin')
@role_required(ROLE_ADMIN, ROLE_ADVISOR, ROLE_ITSTAFF)
def admin_dashboard():
    user = get_current_user()
    return render_template('admin.html', username=user['username'], isadmin=user['isadmin'])

# -- Users Management --
@app.route('/users')
@role_required(ROLE_ADMIN)
def users():
    user = get_current_user()
    return render_template('partials/users.html', isadmin=user['isadmin'])

@app.route('/api/users_data')
@role_required(ROLE_ADMIN)
def get_users_data():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id, username, email, isadmin FROM Users')
    users = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': u[0], 'username': u[1], 'email': u[2], 'role': get_user_role_name(u[3]), 'isadmin': u[3]}
        for u in users
    ])

@app.route('/api/toggle_admin', methods=['POST'])
@role_required(ROLE_ADMIN)
def toggle_admin():
    user_id = request.form.get('user_id')
    new_role = int(request.form.get('new_role', ROLE_STUDENT))
    
    if not user_id:
        return 'User ID required', 400
    
    # Validate role value
    if new_role not in [ROLE_STUDENT, ROLE_ADMIN, ROLE_ADVISOR, ROLE_ITSTAFF]:
        return 'Invalid role specified', 400
    
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE Users SET isadmin = ? WHERE user_id = ?', (new_role, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('users'))

@app.route('/api/delete_user', methods=['POST'])
@role_required(ROLE_ADMIN)
def delete_user():
    user_id = request.form.get('user_id')
    if not user_id:
        return 'User ID required', 400
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('users'))

# -- Appointments Management --
@app.route('/appointments')
@role_required(ROLE_ADMIN, ROLE_ADVISOR)
def appointments():
    user = get_current_user()
    return render_template('partials/appointments.html', isadmin=user['isadmin'])

@app.route('/api/appointments_data')
@role_required(ROLE_ADMIN, ROLE_ADVISOR)
def get_appointments_data():
    user = get_current_user()
    conn = connect_db()
    cursor = conn.cursor()
    
    # If advisor, only show their appointments
    if user['isadmin'] == ROLE_ADVISOR:
        # Get advisor_id for this user
        cursor.execute('SELECT advisor_id FROM Advisors WHERE name = ?', (user['username'],))
        advisor = cursor.fetchone()
        if advisor:
            advisor_id = advisor[0]
            cursor.execute('''
                SELECT a.appointment_id,
                       u.username AS student,
                       adv.name AS advisor,
                       ts.available_date AS appointment_date,
                       ts.time_slot
                FROM Appointments a
                LEFT JOIN Users u ON a.student_id = u.user_id
                LEFT JOIN Advisors adv ON a.advisor_id = adv.advisor_id
                LEFT JOIN Time_Slots ts ON a.slot_id = ts.slot_id
                WHERE a.advisor_id = ?
            ''', (advisor_id,))
        else:
            # If no advisor record found, return empty list
            return jsonify([])
    else:
        # Admin sees all appointments
        cursor.execute('''
            SELECT a.appointment_id,
                   u.username AS student,
                   adv.name AS advisor,
                   ts.available_date AS appointment_date,
                   ts.time_slot
            FROM Appointments a
            LEFT JOIN Users u ON a.student_id = u.user_id
            LEFT JOIN Advisors adv ON a.advisor_id = adv.advisor_id
            LEFT JOIN Time_Slots ts ON a.slot_id = ts.slot_id
        ''')
    
    appts = cursor.fetchall()
    conn.close()
    return jsonify([
        {
            'id': row[0],
            'student': row[1] or 'Unknown',
            'advisor': row[2] or 'Unknown',
            'date': row[3],
            'time_slot': row[4]
        }
        for row in appts
    ])

@app.route('/api/delete_appointment', methods=['POST'])
@role_required(ROLE_ADMIN, ROLE_ADVISOR)
def delete_appointment():
    appt_id = request.form.get('appointment_id')
    user = get_current_user()
    
    conn = connect_db()
    cursor = conn.cursor()
    
    # If advisor, verify they own this appointment
    if user['isadmin'] == ROLE_ADVISOR:
        # Get advisor_id for this user
        cursor.execute('SELECT advisor_id FROM Advisors WHERE name = ?', (user['username'],))
        advisor = cursor.fetchone()
        if advisor:
            advisor_id = advisor[0]
            # Check if appointment belongs to this advisor
            cursor.execute('SELECT 1 FROM Appointments WHERE appointment_id = ? AND advisor_id = ?', 
                          (appt_id, advisor_id))
            if not cursor.fetchone():
                conn.close()
                return jsonify({'error': 'Unauthorized'}), 403
    
    # Get the slot_id to free up the slot
    cursor.execute('SELECT slot_id FROM Appointments WHERE appointment_id = ?', (appt_id,))
    slot = cursor.fetchone()
    if slot:
        # Set the slot as available again
        cursor.execute('UPDATE Time_Slots SET is_booked = 0 WHERE slot_id = ?', (slot[0],))
    
    # Delete the appointment
    cursor.execute('DELETE FROM Appointments WHERE appointment_id = ?', (appt_id,))
    conn.commit()
    conn.close()
    return render_template('partials/appointments.html', success='Deleted successfully', isadmin=user['isadmin'])


@app.route('/addappointmentslots')
@role_required(ROLE_ADMIN, ROLE_ADVISOR)
def addappointmentslots():
    user = get_current_user()
    
    conn = connect_db()
    cursor = conn.cursor()
    
    # If advisor, only show their own record
    if user['isadmin'] == ROLE_ADVISOR:
        # Check if user exists as an advisor
        cursor.execute('SELECT advisor_id, name FROM Advisors WHERE name = ?', (user['username'],))
        advisor = cursor.fetchone()
        if not advisor:
            # Create advisor record if not exists
            cursor.execute('INSERT INTO Advisors (name, specialization) VALUES (?, ?)',
                           (user['username'], 'General Advising'))
            conn.commit()
            cursor.execute('SELECT advisor_id, name FROM Advisors WHERE name = ?', (user['username'],))
            advisor = cursor.fetchone()
        advisors = [advisor]  # Only include the advisor's own record
    else:
        # For admin, show all advisors
        cursor.execute('SELECT advisor_id, name FROM Advisors')
        advisors = cursor.fetchall()
    
    conn.close()
    return render_template('partials/addappointmentslot.html', advisors=advisors, isadmin=user['isadmin'])

@app.route('/api/add_slots', methods=['POST'])
@role_required(ROLE_ADMIN, ROLE_ADVISOR)
def add_slots():
    advisor_id = request.form.get('advisor_id')
    available_date = request.form.get('available_date')
    time_slot = request.form.get('time_slot')
    
    user = get_current_user()
    
    # Debug: Print form data
    print(f"Form data: advisor_id={advisor_id}, available_date={available_date}, time_slot={time_slot}")
    
    conn = connect_db()
    cursor = conn.cursor()
    
    # If advisor, force using their own ID
    if user['isadmin'] == ROLE_ADVISOR:
        cursor.execute('SELECT advisor_id FROM Advisors WHERE name = ?', (user['username'],))
        advisor = cursor.fetchone()
        if advisor:
            advisor_id = advisor[0]
        else:
            conn.close()
            return render_template('partials/addappointmentslot.html', error='Advisor not found', 
                                  advisors=[(None, user['username'])], isadmin=user['isadmin'])
    
    # For admin, use the advisor_id from the form
    if not (advisor_id and available_date and time_slot):
        print("Validation failed: Missing fields")
        cursor.execute('SELECT advisor_id, name FROM Advisors')
        advisors = cursor.fetchall() if user['isadmin'] == ROLE_ADMIN else [(advisor_id, user['username'])]
        conn.close()
        return render_template('partials/addappointmentslot.html', error='All fields required', 
                              advisors=advisors, isadmin=user['isadmin'])
    
    try:
        cursor.execute('INSERT INTO Time_Slots (advisor_id, available_date, time_slot, is_booked) VALUES (?, ?, ?, 0)',
                       (advisor_id, available_date, time_slot))
        conn.commit()
        # Fetch advisors based on role
        if user['isadmin'] == ROLE_ADVISOR:
            cursor.execute('SELECT advisor_id, name FROM Advisors WHERE name = ?', (user['username'],))
            advisors = cursor.fetchall()
        else:
            cursor.execute('SELECT advisor_id, name FROM Advisors')
            advisors = cursor.fetchall()
        conn.close()
        return render_template('partials/addappointmentslot.html', success='Slot added!', 
                              advisors=advisors, isadmin=user['isadmin'])
    except Exception as e:
        # Fetch advisors based on role for error case
        if user['isadmin'] == ROLE_ADVISOR:
            cursor.execute('SELECT advisor_id, name FROM Advisors WHERE name = ?', (user['username'],))
            advisors = cursor.fetchall()
        else:
            cursor.execute('SELECT advisor_id, name FROM Advisors')
            advisors = cursor.fetchall()
        conn.close()
        print(f"Error: {str(e)}")
        return render_template('partials/addappointmentslot.html', error=str(e),
                              advisors=advisors, isadmin=user['isadmin'])

@app.route('/adddoctor')
@role_required(ROLE_ADMIN)
def adddoctor():
    user = get_current_user()
    return render_template('partials/adddoctor.html', isadmin=user['isadmin'])

@app.route('/api/add_doctor', methods=['POST'])
@role_required(ROLE_ADMIN)
def add_doctor():
    name = request.form.get('name')
    specialization = request.form.get('specialization')
    
    if not (name and specialization):
        return render_template('partials/adddoctor.html', error='All fields required')
    
    conn = connect_db()
    cursor = conn.cursor()
    user = get_current_user()
    
    try:
        cursor.execute('INSERT INTO Advisors (name, specialization) VALUES (?, ?)', 
                      (name, specialization))
        conn.commit()
        conn.close()
        return render_template('partials/adddoctor.html', success='Advisor added!',
                              isadmin=user['isadmin'])
    except Exception as e:
        conn.close()
        return render_template('partials/adddoctor.html', error=str(e),
                              isadmin=user['isadmin'])

@app.route('/courses')
@role_required(ROLE_ADMIN, ROLE_ADVISOR, ROLE_ITSTAFF, ROLE_STUDENT)
def courses():
    user = get_current_user()
    return render_template('partials/viewallcourses.html', isadmin=user['isadmin'])

@app.route('/api/courses_data', methods=['GET'])
@role_required(ROLE_ADMIN, ROLE_ADVISOR, ROLE_ITSTAFF, ROLE_STUDENT)
def courses_data():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT course_id, course_name, description FROM Courses')
    courses = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': c[0], 'course_name': c[1], 'description': c[2]} for c in courses
    ])

@app.route('/addcourse')
@role_required(ROLE_ADMIN, ROLE_ITSTAFF)
def addcourse():
    user = get_current_user()
    return render_template('partials/addcourse.html', isadmin=user['isadmin'])

@app.route('/api/add_course', methods=['POST'])
@role_required(ROLE_ADMIN, ROLE_ITSTAFF)
def add_course():
    course_name = request.form.get('course_name')
    description = request.form.get('description')
    
    if not (course_name and description):
        return render_template('partials/addcourse.html', error='All fields required')
    
    conn = connect_db()
    cursor = conn.cursor()
    user = get_current_user()
    
    try:
        cursor.execute('INSERT INTO Courses (course_name, description) VALUES (?, ?)', 
                      (course_name, description))
        conn.commit()
        conn.close()
        return render_template('partials/addcourse.html', success='Course added!',
                              isadmin=user['isadmin'])
    except Exception as e:
        conn.close()
        return render_template('partials/addcourse.html', error=str(e),
                              isadmin=user['isadmin'])

@app.route('/updatecourse/<int:course_id>', methods=['GET'])
@role_required(ROLE_ADMIN, ROLE_ITSTAFF)
def updatecourse(course_id):
    user = get_current_user()
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT course_name, description FROM Courses WHERE course_id = ?', (course_id,))
    course = cursor.fetchone()
    conn.close()
    if not course:
        return render_template('partials/updatecourse.html', error='Course not found',
                              isadmin=user['isadmin'])
    return render_template('partials/updatecourse.html', course_id=course_id,
                          course_name=course[0], description=course[1], isadmin=user['isadmin'])

@app.route('/api/update_course/<int:course_id>', methods=['POST'])
@role_required(ROLE_ADMIN, ROLE_ITSTAFF , ROLE_ADVISOR)
def update_course_api(course_id):
    course_name = request.form.get('course_name')
    description = request.form.get('description')
    user = get_current_user()
    
    if not (course_name and description):
        return render_template('partials/updatecourse.html', error='All fields required',
                             course_id=course_id, isadmin=user['isadmin'])
    
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE Courses SET course_name = ?, description = ? WHERE course_id = ?',
                       (course_name, description, course_id))
        conn.commit()
        conn.close()
        return redirect(url_for('courses'))
    except Exception as e:
        conn.close()
        return render_template('partials/updatecourse.html', error=str(e),
                              course_id=course_id, isadmin=user['isadmin'])

# -- Chat Management --
@app.route('/api/ask', methods=['POST'])
def ask_question():
    data = request.json
    session_id = data.get('chat_id', 0)
    question = data.get('question', '').strip()
    if not question:
        return jsonify({'error': 'Question is required'}), 400
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    # Generate response via ChatGroq
    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0,
                   api_key="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")
    messages = [("system", SYSTEM), ("human", question)]
    ai_msg = llm.invoke(messages)
    # Save session and chat
    conn = connect_db()
    cursor = conn.cursor()
    if session_id == 0:
        cursor.execute('INSERT INTO Chat_Sessions (user_id) VALUES (?)', (user['user_id'],))
        session_id = cursor.lastrowid
    cursor.execute(
        'INSERT INTO Chats (user_id, session_id, user_message, bot_response) VALUES (?, ?, ?, ?)',
        (user['user_id'], session_id, question, ai_msg.content)
    )
    conn.commit()
    conn.close()
    return jsonify({'chat_id': session_id, 'question': question, 'answer': ai_msg.content})

@app.route('/api/chat_sessions', methods=['GET'])
def get_chat_sessions():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT session_id, name, created_at FROM Chat_Sessions WHERE user_id = ? ORDER BY created_at DESC',
        (user['user_id'],)
    )
    sessions = cursor.fetchall()
    conn.close()
    return jsonify([
        {'id': s[0], 'name': s[1] or 'New Chat', 'created_at': s[2]}
        for s in sessions
    ])

@app.route('/api/chat/<int:session_id>', methods=['GET'])
def get_chat(session_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT user_message, bot_response, timestamp FROM Chats WHERE session_id = ? AND user_id = ? ORDER BY timestamp ASC',
        (session_id, user['user_id'])
    )
    chats = cursor.fetchall()
    conn.close()
    return jsonify([
        {'user_message': c[0], 'bot_response': c[1], 'timestamp': c[2]}
        for c in chats
    ])

# -- Logout Route --
@app.route('/logout')
def logout():
    session.pop('token', None)
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/advisor/chat_sessions')
@role_required(ROLE_ADVISOR)
def advisor_chat_sessions_view():
    # Advisor and Admin can view all user chat sessions
    user = get_current_user()
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT cs.session_id,
               u.username,
               cs.created_at
        FROM Chat_Sessions cs
        JOIN Users u ON cs.user_id = u.user_id
        ORDER BY cs.created_at DESC
    ''')
    sessions = cursor.fetchall()
    conn.close()
    return render_template('advisor_chat_sessions.html', sessions=sessions , isadmin=user['isadmin'])

@app.route('/advisor/chat/<int:session_id>')
@role_required(ROLE_ADVISOR)
def advisor_view_chat(session_id):
    # Advisor and Admin can view chats for a specific session
    user = get_current_user()
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.username AS user,
               c.user_message,
               c.bot_response,
               c.timestamp
        FROM Chats c
        JOIN Users u ON c.user_id = u.user_id
        WHERE c.session_id = ?
        ORDER BY c.timestamp ASC
    ''', (session_id,))
    chats = cursor.fetchall()
    conn.close()
    return render_template('advisor_view_chat.html', session_id=session_id, chats=chats, isadmin=user['isadmin'])


# -- Run the Application --
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)