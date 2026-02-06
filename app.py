from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# Azure PostgreSQL Connection String - GET FROM AZURE PORTAL
# DATABASE_URL = """
#     "host=jawa.postgres.database.azure.com"
#     "port=5432"
#     "dbname=jawarava"
#     "user=jawa01@jawa"
#     "password=Jaawa5667&"
#     "sslmode=require"
# """
#DATABASE_URL = "host=jawa.postgres.database.azure.com port=5432 dbname=postgres user=jawa01@jawa password=Jaawa5667%26 sslmode=require"
DATABASE_URL = "host=jawa.postgres.database.azure.com port=5432 dbname=postgres user=jawa01 password=welcome5005! sslmode=require"
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('home.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password, user['password_hash'].encode('utf-8')):
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s)", 
                (email, password_hash)
            )
            conn.commit()
            conn.close()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except psycopg2.errors.UniqueViolation:
            flash('Email already exists!', 'error')
            conn.close()
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
