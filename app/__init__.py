from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import boto3

#Initial config
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
dynamodb = boto3.resource('dynamodb')
lambda_aws = boto3.client('lambda')
IoTMEF = dynamodb.Table('IoTMEF')
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

from app import routes, models