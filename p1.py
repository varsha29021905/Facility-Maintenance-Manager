from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'


def get_db_connection():
    conn = sqlite3.connect('facility_manager.db')
    conn.row_factory = sqlite3.Row
    return conn


# Database Initialization
with get_db_connection() as conn:
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS facilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL
                    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS maintenance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        facility_id INTEGER,
                        issue_id INTEGER NULL,
                        date TEXT,
                        status TEXT DEFAULT 'Pending',
                        appliance TEXT,  -- Ensure the appliance column exists during creation
                        FOREIGN KEY(facility_id) REFERENCES facilities(id) ON DELETE CASCADE,
                        FOREIGN KEY(issue_id) REFERENCES issues(id) ON DELETE SET NULL
                    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS issues (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        facility_id INTEGER,
                        issue TEXT NOT NULL,
                        status TEXT DEFAULT 'Reported',
                        FOREIGN KEY(facility_id) REFERENCES facilities(id) ON DELETE CASCADE
                    )''')
    conn.commit()

# Function to add appliance column if it doesn't exist
def add_appliance_column():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the appliance column already exists
    cursor.execute('PRAGMA table_info(maintenance);')
    columns = [column['name'] for column in cursor.fetchall()]
    if 'appliance' not in columns:
        cursor.execute('ALTER TABLE maintenance ADD COLUMN appliance TEXT')
        conn.commit()
    conn.close()

# Call this function once when the app starts
add_appliance_column()

# User Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):  # Secure password check
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)  # Hashing password

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# Protect routes to require login
def login_required(f):
    @wraps(f)  # Fix decorator issue
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/facilities')
@login_required
def facilities():
    conn = get_db_connection()
    facilities = conn.execute('SELECT * FROM facilities').fetchall()
    conn.close()
    return render_template('facilities.html', facilities=facilities)

@app.route('/add_facility', methods=['POST'])
@login_required
def add_facility():
    name = request.form.get('name')

    if not name:
        flash('Please enter a facility name!', 'error')
        return redirect(url_for('facilities'))

    conn = get_db_connection()
    conn.execute('INSERT INTO facilities (name) VALUES (?)', (name,))
    conn.commit()
    conn.close()

    flash('Facility added successfully!', 'success')
    return redirect(url_for('facilities'))

@app.route('/delete_facility/<int:facility_id>')
@login_required
def delete_facility(facility_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM facilities WHERE id = ?', (facility_id,))
    conn.commit()
    conn.close()

    flash('Facility deleted successfully!', 'success')
    return redirect(url_for('facilities'))

@app.route('/maintenance')
@login_required
def maintenance():
    today = date.today().isoformat()  # Fix `today` variable issue
    conn = get_db_connection()
    facilities = conn.execute('SELECT * FROM facilities').fetchall()
    issues = conn.execute('SELECT * FROM issues').fetchall()  # Fetch existing issues
    maintenance = conn.execute(''' 
        SELECT maintenance.id, maintenance.date, maintenance.status, facilities.name, 
               IFNULL(issues.issue, 'No Issue') AS issue, maintenance.appliance
        FROM maintenance
        JOIN facilities ON maintenance.facility_id = facilities.id
        LEFT JOIN issues ON maintenance.issue_id = issues.id
    ''').fetchall()
    conn.close()
    return render_template('maintenance.html', facilities=facilities, maintenance=maintenance, today=today, issues=issues)

@app.route('/schedule_maintenance', methods=['POST'])
@login_required
def schedule_maintenance():
    facility_id = request.form.get('facility_id')
    appliance = request.form.get('appliance')
    issue_description = request.form.get('issue')  # Issue field added here
    date_scheduled = request.form.get('date')

    if not facility_id or not appliance or not date_scheduled:
        flash('All fields are required!', 'error')
        return redirect(url_for('maintenance'))

    # Check if a maintenance for the same appliance is already scheduled on the same date
    conn = get_db_connection()
    existing_maintenance = conn.execute('''
        SELECT * FROM maintenance 
        WHERE facility_id = ? 
        AND appliance = ? 
        AND date = ?
    ''', (facility_id, appliance, date_scheduled)).fetchone()
    
    if existing_maintenance:
        flash('Maintenance already scheduled for this appliance on this date!', 'error')
        conn.close()
        return redirect(url_for('maintenance'))

    # Create an issue if not provided
    cursor = conn.cursor()

    # Insert issue only if the description is provided
    cursor.execute('INSERT INTO issues (facility_id, issue) VALUES (?, ?)', (facility_id, issue_description))
    issue_id = cursor.lastrowid  # Get the ID of the newly created issue
    conn.commit()

    # Now schedule the maintenance with the new issue_id and appliance name
    cursor.execute(
        'INSERT INTO maintenance (facility_id, issue_id, appliance, date, status) VALUES (?, ?, ?, ?, "Pending")',
        (facility_id, issue_id, appliance, date_scheduled)
    )
    conn.commit()
    conn.close()

    flash('Maintenance scheduled successfully!', 'success')
    return redirect(url_for('maintenance'))


@app.route('/issues')
@login_required
def issues():
    conn = get_db_connection()
    facilities = conn.execute('SELECT * FROM facilities').fetchall()
    issues = conn.execute('SELECT issues.*, facilities.name FROM issues JOIN facilities ON issues.facility_id = facilities.id').fetchall()
    conn.close()
    return render_template('issues.html', facilities=facilities, issues=issues)

@app.route('/report_issue', methods=['POST'])
@login_required
def report_issue():
    facility_id = request.form.get('facility_id')
    issue_description = request.form.get('issue')

    if not facility_id or not issue_description:
        flash('Please provide both facility and issue details.', 'error')
        return redirect(url_for('issues'))

    conn = get_db_connection()
    conn.execute('INSERT INTO issues (facility_id, issue) VALUES (?, ?)', (facility_id, issue_description))
    conn.commit()
    conn.close()

    flash('Issue reported successfully!', 'success')
    return redirect(url_for('issues'))

@app.route('/update_issue/<int:issue_id>', methods=['POST'])
@login_required
def update_issue(issue_id):
    status = request.form.get('status')

    if not status:
        flash('Please select a status!', 'error')
        return redirect(url_for('issues'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if status == "Resolved":
        # Delete the issue if it's resolved
        cursor.execute('DELETE FROM issues WHERE id = ?', (issue_id,))
        flash('Resolved issue deleted successfully!', 'success')
    else:
        # Update the issue status
        cursor.execute('UPDATE issues SET status = ? WHERE id = ?', (status, issue_id))
        flash('Issue updated successfully!', 'success')

    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for('issues'))

if __name__ == '__main__':
    app.run(debug=True)
