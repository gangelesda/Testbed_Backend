from flask import render_template, jsonify, request
from app import app, db, dynamodb, IoTMEF, lambda_aws
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User
from app.forms import LoginForm, RegisterForm

#Imports for DynamoDB
from boto3.dynamodb.conditions import Key, Attr 
import json
import decimal
import ast

#Imports for lambda
from config import Enums

#Should make new file for this

#Helper
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)

#Formating for json response
def makeResponse(stat, msg, uname=None):
    if uname is None:
        return jsonify(status = stat,
                        message = msg)
    return jsonify(status = stat,
                    message = msg,
                    full_name = uname)

#To invoke Lambda
def sendToLambda(topic, action):
    payload = {"topic": topic, 
                "payload": {
                    "action": action
                }
            }
    #Invoke Lambda to publish
    result = lambda_aws.invoke(
        FunctionName = Enums.LAMBDA_FUNC,
        InvocationType = 'RequestResponse',
        Payload = json.dumps(payload)
    )
    range = result['Payload'].read()
    api_response = json.loads(range)
    return api_response['ResponseMetadata']['HTTPStatusCode'] 

@app.route('/')
@app.route('/index')   

#Render Main Page
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST'])

def login():
    #Check session
    if current_user.is_authenticated:
        #Response is same as successful to be easibly handled by android
        response = makeResponse(0, "Login successful", current_user.username)
        return response
    #CSRF disabled as it was causing trouble with android (fix in later iterations) (Prob not need a form)
    form = LoginForm(csrf_enabled=False)
    if form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            response = makeResponse(1, "Invalid username and password combination")
            return response
        #Create the session
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

@app.route('/register', methods=['POST'])

def register():
    if(current_user.is_authenticated):
        return redirect(url_for('index'))
    #CSRF disabled as it was causing trouble with android (fix in later iterations)
    form = RegisterForm(csrf_enabled=False)
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        #Add user to database
        db.session.add(user)
        db.session.commit()
        response = makeResponse(0, "User Created")
        return response
    #This will be the response even on missing fields as I have not seen part of the API been able to handle individual validators
    else:
        response = makeResponse(1, "User or Email already in use")
        return response

@app.route('/home/thermostat/status', methods=['GET'])
@login_required

def thermostart_status():
    query_last = IoTMEF.query(
        KeyConditionExpression = Key('Topic').eq(Enums.THERMO_TOPIC_STATUS),
        ScanIndexForward = False,
        Limit = 1
    )
    message = json.dumps(query_last[u'Items'][0], cls=DecimalEncoder)
    message_dict = ast.literal_eval(message)
    return makeResponse(0, message_dict['message'])

@app.route('/home/thermostat/set', methods=['POST'])
@login_required

def set_temp():
    action = request.form.get('temp')
    if (action is None):
        return makeResponse(1, "Missing correct field")

    invokeLambda = sendToLambda(Enums.THERMO_TOPIC_ACTION, action)

    if (invokeLambda == 200):
        return makeResponse(0, "Thermostat set to " + action)
    else:
        return makeResponse(1, "Something Failed in the process")

@app.route('/home/lightbulb/status', methods=['GET'])
@login_required

def lightbulb_status():
    query_last = IoTMEF.query(
        KeyConditionExpression = Key('Topic').eq(Enums.LIGHTBULB_TOPIC_STATUS),
        ScanIndexForward = False,
        Limit = 1
    )
    message = json.dumps(query_last[u'Items'][0], cls=DecimalEncoder)
    message_dict = ast.literal_eval(message)
    return makeResponse(0, message_dict['message'])

@app.route('/home/lightbulb/turn', methods=['POST'])
@login_required

def turn():
    action = request.form.get('turn')
    if (action is None):
        return makeResponse(1, "Missing correct field")

    invokeLambda = sendToLambda(Enums.LIGHTBULB_TOPIC_ACTION, action)

    if (invokeLambda == 200):
        return makeResponse(0, "Lightbulb turned " + action)
    else:
        return makeResponse(1, "Something Failed in the process")
    

@app.route('/home/trashcan/status', methods=['GET'])
@login_required

def trashcan():
    query_last = IoTMEF.query(
        KeyConditionExpression = Key('Topic').eq(Enums.TRASH_TOPIC_STATUS),
        ScanIndexForward = False,
        Limit = 1
    )
    message = json.dumps(query_last[u'Items'][0], cls=DecimalEncoder)
    message_dict = ast.literal_eval(message)
    return makeResponse(0, message_dict['message'])


@app.route('/home/doorlock/status', methods=['GET'])
@login_required

def doorlock_status():
    query_last = IoTMEF.query(
        KeyConditionExpression = Key('Topic').eq(Enums.DOORLOCK_TOPIC_STATUS),
        ScanIndexForward = False,
        Limit = 1
    )
    message = json.dumps(query_last[u'Items'][0], cls=DecimalEncoder)
    message_dict = ast.literal_eval(message)
    return makeResponse(0, message_dict['message'])

@app.route('/home/doorlock/action', methods=['POST'])
@login_required

#TBD For Lambda
def lock_unlock():
    #Encrypted???
    action = request.form.get('pin')
    if (action is None):
        return makeResponse(1, "Missing correct field")

    invokeLambda = sendToLambda(Enums.DOORLOCK_TOPIC_ACTION, action)

    if (invokeLambda != 200):
        return makeResponse(1, "Something Failed in the process")
    
    return makeResponse(0, "Success")

@app.route('/home/camera', methods=['GET'])
@login_required

def camera():
    return 'video'