import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'
app.config['SECRET_KEY'] = 'your_flask_secret_key_here'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kuruvavinodkumar6529@gmail.com'
app.config['MAIL_PASSWORD'] = 'irai mcri pbti xgoe'
app.config['MAIL_DEFAULT_SENDER'] = 'kuruvavinodkumar6529@gmail.com'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir+'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIICATIONS'] = False


db = SQLAlchemy(app)
Migrate(app,db)
jwt = JWTManager(app)
mail = Mail(app)


from Fusion import views