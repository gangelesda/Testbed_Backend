from flask import render_template, jsonify
from app import app, db
from flask_login import current_user, login_user, logout_user
from app.models import User
from app.forms import LoginForm, RegisterForm

def makeResponse(stat, msg, uname=None):
    if uname is not None:
        return jsonify(status = stat,
                        message = msg)
    return jsonify(status = stat,
                    message = msg,
                    full_name = uname)

@app.route('/')
@app.route('/index') 

def home():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])

def login():
    if current_user.is_authenticated:
        return "Already Logged In"
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            response = makeResponse(1, "Invalid username and password combination")
            return response
        login_user(user)
        response = makeResponse(0, "Login successful", form.username.data)
        return response
    else:
        response = makeResponse(2, "Missing Fields")
        return response

@app.route('/logout')

def logout():
    logout_user()
    return 'Logged out'

@app.route('/register', methods=['GET','POST'])

def register():
    if(current_user.is_authenticated):
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        response = makeResponse(0, "User Created")
        return response
    else:
        response = makeResponse(1, "User or Email already in use")
        return response

@app.route('/home/thermostat', methods=['GET','POST'])
@login_required

def thermostat():
    return 'Current Temp'

@app.route('/home/lightbulb', methods=['GET','POST'])
@login_required

def lightbulb():
    return 'On'

@app.route('/home/trashcan', methods=['GET'])
@login_required

def trashcan():
    return 'Fullness'

@app.route('/home/doorlock', methods=['GET','POST'])
@login_required

def doorlock():
    return 'Locked'

@app.route('/home/camera', methods=['GET'])
@login_required

def camera():
    return 'video'