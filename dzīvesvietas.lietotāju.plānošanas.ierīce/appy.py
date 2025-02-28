from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import json
import bcrypt
from datetime import datetime

with open('text.json', 'r', encoding='utf-8') as f:
    TEXTS = json.load(f)

app = Flask(__name__)
app.secret_key = 'secret_key'

def init_db():
    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT UNIQUE NOT NULL,
                          password TEXT NOT NULL)
        ''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS reminders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    task TEXT NOT NULL,
                    due_date TEXT,
                    due_time TEXT,
                    progress TEXT DEFAULT 'neiesākts',
                    important INTEGER DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id))
        ''')

        conn.commit()

def update_missed_reminders():
    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()
        current_date = datetime.now().strftime('%Y-%m-%d')
        current_time = datetime.now().strftime('%H:%M:%S')
        cursor.execute('''
            UPDATE reminders
            SET progress = 'nokavēts'
            WHERE due_date < ? OR (due_date = ? AND due_time < ?)
        ''', (current_date, current_date, current_time))
        conn.commit()

@app.route('/')
def index():
    return render_template('index.html', texts=TEXTS)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8') 

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        with sqlite3.connect('data.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return render_template('register.html', texts=TEXTS, error=TEXTS['error_user_exists'])

    return render_template('register.html', texts=TEXTS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  

        with sqlite3.connect('data.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
                session['user_id'] = user[0]
                session['username'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', texts=TEXTS, error=TEXTS['error_invalid_credentials'])

    return render_template('login.html', texts=TEXTS)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    update_missed_reminders()

    edit_mode = session.get('edit_mode', False)
    par_info = session.get('par_info', False)
    show_important = session.get('show_important', False)

    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()
        if show_important:
            cursor.execute('SELECT id, task, due_date, due_time, progress, important FROM reminders WHERE user_id = ? AND important = 1', (session['user_id'],))
        else:
            cursor.execute('SELECT id, task, due_date, due_time, progress, important FROM reminders WHERE user_id = ?', (session['user_id'],))
        reminders = cursor.fetchall()

    return render_template('dashboard.html', texts=TEXTS, reminders=reminders, edit_mode=edit_mode, par_info=par_info, show_important=show_important)

@app.route('/update_progress/<int:reminder_id>')
def update_progress(reminder_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    progress = request.args.get('progress')
    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()

        if progress == "Pabeigts":
            cursor.execute('DELETE FROM reminders WHERE id = ?', (reminder_id,))
        else:
            cursor.execute('UPDATE reminders SET progress = ? WHERE id = ?', (progress, reminder_id))

        conn.commit()

    return redirect(url_for('dashboard'))

@app.route('/add_reminder', methods=['POST'])
def add_reminder():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = request.form['task']
    due_date = request.form['due_date']
    due_time = request.form.get('due_time', None)

    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO reminders (user_id, task, due_date, due_time) VALUES (?, ?, ?, ?)',
                       (session['user_id'], task, due_date, due_time))
        conn.commit()

    return redirect(url_for('dashboard'))

@app.route('/delete_reminder/<int:reminder_id>')
def delete_reminder(reminder_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM reminders WHERE id = ? AND user_id = ?', (reminder_id, session['user_id']))
        conn.commit()

    return redirect(url_for('dashboard'))

@app.route('/toggle_edit_mode')
def toggle_edit_mode():
    session['edit_mode'] = not session.get('edit_mode', False)
    return redirect(url_for('dashboard'))

@app.route('/toggle_par_info')
def toggle_par_info():
    session['par_info'] = not session.get('par_info', False)
    return redirect(url_for('dashboard'))

@app.route('/toggle_important/<int:reminder_id>')
def toggle_important(reminder_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT important FROM reminders WHERE id = ?', (reminder_id,))
        important = cursor.fetchone()[0]
        new_important = 0 if important else 1
        cursor.execute('UPDATE reminders SET important = ? WHERE id = ?', (new_important, reminder_id))
        conn.commit()

    return redirect(url_for('dashboard'))

@app.route('/toggle_show_important')
def toggle_show_important():
    session['show_important'] = not session.get('show_important', False)
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
