from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

QUESTION_BANK = [
    {'question': 'What is data processing?', 'options': ['Sorting', 'Calculating', 'Transforming raw data into information', 'Printing'], 'answer': 'Transforming raw data into information', 'topic': 'SS1 - Introduction to Data Processing'},
    {'question': 'What is the output of 2 ** 3 in Python?', 'options': ['5', '6', '8', '9'], 'answer': '8', 'topic': 'SS2 - Programming Basics'}
]

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'])
        new_user = User(username=request.form['username'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    import random
    questions = random.sample(QUESTION_BANK, min(5, len(QUESTION_BANK)))
    return render_template('dashboard.html', questions=questions)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    return render_template('admin_dashboard.html', questions=QUESTION_BANK)

@app.route('/admin/upload', methods=['POST'])
@login_required
def upload_questions():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    from io import TextIOWrapper
    import csv
    file = request.files['csv_file']
    if file and file.filename.endswith('.csv'):
        stream = TextIOWrapper(file.stream)
        csv_input = csv.DictReader(stream)
        for row in csv_input:
            QUESTION_BANK.append({
                'question': row['question'],
                'options': [row['option1'], row['option2'], row['option3'], row['option4']],
                'answer': row['answer'],
                'topic': row['topic']
            })
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit/<int:index>', methods=['POST'])
@login_required
def edit_question(index):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    if 0 <= index < len(QUESTION_BANK):
        QUESTION_BANK[index]['question'] = request.form['question']
        QUESTION_BANK[index]['topic'] = request.form['topic']
        QUESTION_BANK[index]['answer'] = request.form['answer']
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:index>', methods=['POST'])
@login_required
def delete_question(index):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    if 0 <= index < len(QUESTION_BANK):
        del QUESTION_BANK[index]
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin-create')
def create_admin():
    if User.query.filter_by(username='admin').first():
        return 'Admin already exists.'
    admin = User(username='admin', password=generate_password_hash('admin123'), is_admin=True)
    db.session.add(admin)
    db.session.commit()
    return 'Admin created.'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)