import os
from flask import Flask, render_template, redirect, url_for, flash, request, abort, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_gravatar import Gravatar
from typing import Callable
from discord_oauth2 import DiscordAuth
from zenora import APIClient

todays_date = date.today()
app = Flask(__name__)
app.config['SECRET_KEY'] = "secret"
app.config['CKEDITOR_PKG_TYPE'] = 'basic'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

# login manager from flask-login
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB and create the file
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Keys for Discord Api - I will refresh the tokens and the secret keys
API_ENDPOINT = "https:///discord.com/api/v10"
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = 'https://time-app-scheduler.herokuapp.com/auth/callback'

TOKEN = os.environ.get("TOKEN")
client = APIClient(TOKEN, client_secret=CLIENT_SECRET)
new_url = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_SECRET}&redirect_uri=https%3A%2F%2Ftime-app-scheduler.herokuapp.com%2Fauth%2Fcallback&response_type=code&scope=guilds"


class MySQLAlchemy(SQLAlchemy):
    Column: Callable
    String: Callable
    Text: Callable
    Integer: Callable
    ForeignKey: Callable


db = MySQLAlchemy(app)


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)


class Priority(db.Model):
    __tablename__ = "priorities"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer)
    topic = db.Column(db.String(250), nullable=False)
    item1 = db.Column(db.String(250), nullable=False)
    item2 = db.Column(db.String(250), nullable=True)
    item3 = db.Column(db.String(250), nullable=True)


class GamePlan(db.Model):
    __tablename__ = "gameplans"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, unique=True)
    text = db.Column(db.Text, nullable=True)


class Scheduler(db.Model):
    __tablename__ = "scheduler"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer)
    author_email = db.Column(db.String())
    six = db.Column(db.String(), nullable=True)
    seven = db.Column(db.String(), nullable=True)
    eight = db.Column(db.String(), nullable=True)
    nine = db.Column(db.String(), nullable=True)
    ten = db.Column(db.String(), nullable=True)
    eleven = db.Column(db.String(), nullable=True)
    twelve = db.Column(db.String(), nullable=True)
    thirteen = db.Column(db.String(), nullable=True)
    fourteen = db.Column(db.String(), nullable=True)
    fifteen = db.Column(db.String(), nullable=True)
    sixteen = db.Column(db.String(), nullable=True)
    seventeen = db.Column(db.String(), nullable=True)
    eighteen = db.Column(db.String(), nullable=True)


db.create_all()


### forms
class Register(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class Login(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class GamePlanForm(FlaskForm):
    text = CKEditorField("", render_kw={"placeholder": "Game Plan"})
    submit_gp = SubmitField("Save")


class SchedulerForm(FlaskForm):
    six_am = StringField("6 AM")
    seven_am = StringField("7 AM")
    eight_am = StringField("8 AM")
    nine_am = StringField("9 AM")
    ten_am = StringField("10 AM")
    eleven_am = StringField("11 AM")
    twelve_pm = StringField("12 PM")
    one_pm = StringField("1 PM")
    two_pm = StringField("2 PM")
    three_pm = StringField("3 PM")
    four_pm = StringField("4 PM")
    five_pm = StringField("5 PM")
    six_pm = StringField("6 PM")

    submit_sf = SubmitField("Save")


# use priotities as general header for this section in html end
class CreatePriorityForm(FlaskForm):
    topic = StringField('', render_kw={"placeholder": "Enter your Project Topic"},
                        validators=[DataRequired('Enter a project topic.')])
    item1 = StringField('', render_kw={"placeholder": "Priority Item"},
                        validators=[DataRequired('Enter at least one priority.')])
    item2 = StringField('', render_kw={"placeholder": "Priority Item"})
    item3 = StringField('', render_kw={"placeholder": "Priority Item"})
    # gameplan = CKEditorField('', render_kw={"placeholder": "Game Plan"})
    submit = SubmitField("Create TaskSet")


### forms


def user_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Sorry. Please login or Sign up first.')
            return redirect(url_for('register'))
        return f(*args, **kwargs)

    return wrapper


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Register()
    if form.validate_on_submit() and request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not User.query.filter_by(email=email).first():
            new_user = User(username=username, email=email,
                            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            user_id = new_user.id
            session['user_id'] = user_id
            flash("You've created your account. Log in!")
            return redirect(url_for('login'))
        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit() and request.method == 'POST':
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            user_id = user.id
            session['user_id'] = user_id
            return redirect(url_for('get_user_info'))
        if not user or not check_password_hash(user.password, password):
            flash('Your email or password is wrong. Sign up if you do not have an account.')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('register'))


@app.route('/', methods=['GET', 'POST'])
@user_only
def get_user_info():
    user_id = session['user_id']  # counterpart for session
    priorities = Priority.query.filter_by(author_id=user_id).first()

    # check if priority list is empty
    if not priorities:
        return redirect(url_for('set_task'))
    else:
        topic = priorities.topic.title()
        priorities = [priorities.item1, priorities.item2, priorities.item3]

        # for the brain dump logic
        user_gameplan = GamePlan.query.filter_by(author_id=user_id).first()
        idea_form = GamePlanForm(text=user_gameplan.text)
        # for the scheduler logic
        user_schedule = Scheduler.query.filter_by(author_id=user_id).first()
        schedule_form = SchedulerForm(six_am=user_schedule.six,
                                      seven_am=user_schedule.seven,
                                      eight_am=user_schedule.eight,
                                      nine_am=user_schedule.nine,
                                      ten_am=user_schedule.ten,
                                      eleven_am=user_schedule.eleven,
                                      twelve_pm=user_schedule.twelve,
                                      one_pm=user_schedule.thirteen,
                                      two_pm=user_schedule.fourteen,
                                      three_pm=user_schedule.fifteen,
                                      four_pm=user_schedule.sixteen,
                                      five_pm=user_schedule.seventeen,
                                      six_pm=user_schedule.eighteen)

        if idea_form.validate_on_submit() and idea_form.submit_gp.data:
            print('idea form validation')
            user_gameplan.text = idea_form.text.data
            db.session.commit()
            return redirect(url_for("get_user_info"))
        elif schedule_form.validate_on_submit() and schedule_form.submit_sf.data:
            print('sched form validation')
            user_schedule.six = schedule_form.six_am.data
            user_schedule.seven = schedule_form.seven_am.data
            user_schedule.eight = schedule_form.eight_am.data
            user_schedule.nine = schedule_form.nine_am.data
            user_schedule.ten = schedule_form.ten_am.data
            user_schedule.eleven = schedule_form.eleven_am.data
            user_schedule.twelve = schedule_form.twelve_pm.data
            user_schedule.thirteen = schedule_form.one_pm.data
            user_schedule.fourteen = schedule_form.two_pm.data
            user_schedule.fifteen = schedule_form.three_pm.data
            user_schedule.sixteen = schedule_form.four_pm.data
            user_schedule.seventeen = schedule_form.five_pm.data
            user_schedule.eighteen = schedule_form.six_pm.data

            db.session.commit()
            return redirect(url_for("get_user_info"))

        return render_template("index.html", all_priorities=priorities, idea_box=idea_form, scheduler_tab=schedule_form,
                               topic=topic, date=todays_date, oauth_uri=new_url)


@app.route("/settask", methods=['GET', 'POST'])
@user_only
def set_task():
    form = CreatePriorityForm()
    user_id = session['user_id']
    if form.validate_on_submit():
        new_priority = Priority(
            item1=form.item1.data,
            item2=form.item2.data,
            item3=form.item3.data,
            topic=form.topic.data,
            author_id=user_id
        )
        new_schedule = Scheduler(
            six='',
            seven='',
            eight='',
            nine='',
            ten='',
            eleven='',
            twelve='',
            thirteen='',
            fourteen='',
            fifteen='',
            sixteen='',
            seventeen='',
            eighteen='',
            author_id=user_id,
            author_email=User.query.filter_by(id=user_id).first().email
        )
        new_gameplan = GamePlan(
            text='-',
            author_id=user_id,
        )
        db.session.add(new_priority)
        db.session.add(new_schedule)
        db.session.add(new_gameplan)
        db.session.commit()
        return redirect(url_for("get_user_info"))
    return render_template("create_task.html", form=form)


# Discord
@app.route("/auth/callback", methods=["GET", "POST"])
def callback():
    code = request.args["code"]

    access_token = client.oauth.get_access_token(code, REDIRECT_URI).access_token

    bearer_client = APIClient(access_token, bearer=True)

    current_user_guilds = bearer_client.users.get_my_guilds()

    guild_names = [guild.name for guild in list(current_user_guilds)]

    return str(guild_names)


if __name__ == "__main__":
    app.run(debug=True)
