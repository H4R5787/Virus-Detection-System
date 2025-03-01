
from flask import Flask, request, render_template, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
from file_handler import save_file
from virus_scanner import scan_file, get_scan_results
from alert_system import send_alert
from dotenv import load_dotenv
from groq import Groq


# Load environment variables from .env file
load_dotenv()


app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/virus_users'
db = SQLAlchemy(app)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Groq client for Llama 3

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

def explain_virus_info(virus_info):
    """Uses Llama 3 to generate detailed explanations about the virus information."""
    
    messages = [
        {"role": "user", "content": f"Provide a detailed explanation of the virus: {virus_info}"},
        {"role": "user", "content": f"Describe the history of the virus: {virus_info}"},
        {"role": "user", "content": f"Explain how the virus operates: {virus_info}"},
        {"role": "user", "content": f"Suggest methods to prevent infection by the virus: {virus_info}"}
    ]
    
    explanations = []
    
    for msg in messages:
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[msg],
            temperature=1,
            max_tokens=1024,
            top_p=1,
            stream=False,
            stop=None,
        )

        if isinstance(response, tuple):
            response = response[0]

        explanation = response.choices[0].message.content
        explanations.append(explanation)
    
    return explanations

@app.route('/')
def home():
    return render_template('TEST.html')  # First page: TEST.html


@app.route('/Home')
def Home():
    return render_template('Home.html')


@app.route('/Missions')
def Missions():
    return render_template('Missions.html')



@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/ContactUs')
def ContactUs():
    return render_template('ContactUs.html')


@app.route('/Post')
def Post():
    return render_template('Post.html')


@app.route('/Help')
def Help():
    return render_template('Help.html')



@app.route('/Register', methods=['GET', 'POST'])
def Register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        existing_user_email = User.query.filter_by(email=email).first()
        if existing_user_email:
            flash('Email already exists. Please use a different email.', 'error')
            return redirect('/Register')

        existing_user_name = User.query.filter_by(name=name).first()
        if existing_user_name:
            flash('Name already exists. Please use a different name.', 'error')
            return redirect('/Register')

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('Register.html')


@app.route('/login', methods=['GET', 'POST'])
def Login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email == 'Admin@gmail.com' and password == 'admin':
            session['admin'] = True
            return redirect('/admin')
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['name'] = user.name
            session['email'] = user.email
            return redirect('/index')
        else:
            flash('Invalid email or password', 'error')
            return redirect('/login')

    return render_template('Login.html')


@app.route('/index')
def index():
    if session.get('name'):
        return render_template('index.html')
    else:
        return redirect('/login')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)
    if file:
        file_path = save_file(file, app.config['UPLOAD_FOLDER'])
        scan_id = scan_file(file_path)
        if scan_id:
            result = get_scan_results(scan_id)
            if result:
                positives = result['data']['attributes']['stats']['malicious']
                if positives > 0:
                    virus_info = result['data']['attributes']['results']
                    explanations = explain_virus_info(virus_info)
                    send_alert(file_path, virus_info)
                    flash(f"Virus found in {file.filename}:", 'danger')
                    
                    categories = [
                        "Explain Virus",
                        "Explain the History of the Virus",
                        "Explain how the Virus works",
                        "Explain how to prevent the Virus"
                    ]
                    
                    for explanation, category in zip(explanations, categories):
                        flash(explanation, category)
                    return render_template('index.html', scan_result='virus')
                else:
                    flash(f"{file.filename} is clean.", 'success')
                    return render_template('index.html', scan_result='clean')
            else:
                flash(f"Could not retrieve scan results for {file.filename}.", 'danger')
        else:
            flash(f"Could not scan file {file.filename}.", 'danger')
    return redirect(url_for('index'))


@app.route('/Attacks')
def attacks():
    return render_template('attacks.html')


@app.route('/SQL_Injection')
def SQL_Injection():
    return render_template('SQL_Injection.html')

@app.route('/Cross_Site_Scripting')
def Cross_Site_Scripting():
    return render_template('Cross_Site_Scripting.html')

@app.route('/Command_Execution')
def Command_Execution():
    return render_template('Command_Execution.html')

@app.route('/Trojan_horse')
def Trojan_horse():
    return render_template('Trojan_horse.html')

@app.route('/Spyware')
def Spyware():
    return render_template('Spyware.html')

@app.route('/Worm')
def Worm():
    return render_template('Worm.html')

@app.route('/Adware')
def Adware():
    return render_template('Adware.html')

@app.route('/Keyloggers')
def Keyloggers():
    return render_template('Keyloggers.html')

@app.route('/Phishing')
def Phishing():
    return render_template('Phishing.html')

@app.route('/Rootkits')
def Rootkits():
    return render_template('Rootkits.html')

@app.route('/Ransomware')
def Ransomware():
    return render_template('Ransomware.html')

@app.route('/Cryptojacking')
def Cryptojacking():
    return render_template('Cryptojacking.html')


@app.route('/admin')
def admin():
    if session.get('admin'):
        users = User.query.all()
        return render_template('admin.html', users=users)
    else:
        return redirect('/login')


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('admin'):
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
        return redirect('/admin')
    else:
        return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
