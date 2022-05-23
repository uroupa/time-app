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


app = Flask(__name__)
app.config['SECRET_KEY'] = "secret"
app.config['CKEDITOR_PKG_TYPE'] = 'basic'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

# login manager from flask-login
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB and create the file
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


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
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
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
    submit = SubmitField("Save")


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

    submit = SubmitField("Save Schedule")


# use priotities as general header for this section in html end
class CreatePriorityForm(FlaskForm):
    topic = StringField('', render_kw={"placeholder": "Enter your Project Topic"}, validators=[DataRequired('Enter a project topic.')])
    item1 = StringField('', render_kw={"placeholder": "Priority Item"}, validators=[DataRequired('Enter at least one priority.')])
    item2 = StringField('', render_kw={"placeholder": "Priority Item"})
    item3 = StringField('', render_kw={"placeholder": "Priority Item"})
    # gameplan = CKEditorField('', render_kw={"placeholder": "Game Plan"})
    submit = SubmitField("Submit Post")

### forms


def admin_only(f):
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
            new_user = User(username=username, email=email, password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            user_id = new_user.id
            session['user_id'] = user_id
            return redirect(url_for('get_user_info'))
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
@admin_only
def get_user_info():
    # user_id = request.args['user_id']   # counterpart for url_for()
    user_id = session['user_id']        # counterpart for session
    priorities = Priority.query.filter_by(author_id=user_id).first()

    schedule_form = SchedulerForm()
    if schedule_form.validate_on_submit():
        print(f"rare {schedule_form.six_am.data}")
        new_schedule = Scheduler(
            six=schedule_form.six_am.data,
            seven=schedule_form.seven_am.data,
            eight=schedule_form.eight_am.data,
            nine=schedule_form.nine_am.data,
            ten=schedule_form.ten_am.data,
            eleven=schedule_form.eleven_am.data,
            twelve=schedule_form.twelve_pm.data,
            thirteen=schedule_form.one_pm.data,
            fourteen=schedule_form.two_pm.data,
            fifteen=schedule_form.three_pm.data,
            sixteen=schedule_form.four_pm.data,
            seventeen=schedule_form.five_pm.data,
            eighteen=schedule_form.six_pm.data)
        db.session.add(new_schedule)
        db.session.commit()
        print("not empty now")
        return redirect(url_for("get_user_info"))

    # check if priority list is empty
    if not priorities:
        return redirect(url_for('set_task'))
    else:
        topic = priorities.topic.title()
        priorities = [priorities.item1, priorities.item2, priorities.item3]

        #for the brain dump logic
        user_gameplan = GamePlan.query.filter_by(author_id=user_id).first()
        # print(user_gameplan)
        if user_gameplan is None:
            idea_form = GamePlanForm()
            if idea_form.validate_on_submit():
                idea_text = idea_form.text.data
                new_gameplan = GamePlan(author_id=user_id, text=idea_text)
                db.session.add(new_gameplan)
                db.session.commit()
                return redirect(url_for("get_user_info"))

        else:
            idea_form = GamePlanForm(text=user_gameplan.text)
            # print(user_gameplan)
            if idea_form.validate_on_submit():
                user_gameplan.text = idea_form.text.data
                db.session.commit()
                return redirect(url_for("get_user_info"))

        # for the scheduler logic
        # add the form variables to the database and catch them here. if the user has data, bring back
        # user_schedule = Scheduler.query.filter_by(author_id=user_id).first()
        # print(user_schedule)

    user_schedule = Scheduler.query.filter_by(author_id=user_id).first()
    print(user_schedule)

        # if user_schedule is None:
        #     print("empty user schedule")


    return render_template("index.html", all_priorities=priorities, idea_box=idea_form, scheduler_tab=schedule_form, topic=topic)


@app.route("/settask", methods=['GET', 'POST'])
@admin_only
def set_task():
    form = CreatePriorityForm()
    if form.validate_on_submit():
        new_priority = Priority(
            item1=form.item1.data,
            item2=form.item2.data,
            item3=form.item3.data,
            topic=form.topic.data,
            author_id=session['user_id']
        )
        db.session.add(new_priority)
        db.session.commit()
        return redirect(url_for("get_user_info"))
    return render_template("create_task.html", form=form)


@app.route("/edit_gameplan", methods=['GET', 'POST'])
@admin_only
def edit_gameplan():
    user_id = session['user_id']
    user_gameplan = GamePlan.query.filter_by(author_id=user_id).first()
    if user_gameplan:
        form = GamePlanForm(
            text=user_gameplan.text
        )
    else:
        form = GamePlanForm()
    if form.validate_on_submit():
        user_gameplan.text = form.text.data
        db.session.commit()
        return redirect(url_for("get_user_info"))
    return render_template("create_task.html", form=form)


# @app.route("/post/<int:priority_id>", methods=['GET', 'POST'])
# def show_post(priority_id):
#     requested_priority = Priority.query.get(priority_id)
#     form = GamePlanForm()
#     if request.method == 'POST' and form.validate_on_submit():
#         if not current_user.is_authenticated:
#             flash('Failed to post. Please login first.')
#         else:
#             new_comment = GamePlan(text=form.text.data, comment_author=current_user, parent_priority=requested_priority)
#             db.session.add(new_comment)
#             db.session.commit()
#     return render_template("post.html", post=requested_priority, form=form, current_user=current_user)
#
#
#
#
#
#
# @app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
# @admin_only
# def edit_post(post_id):
#     post = BlogPost.query.get(post_id)
#     edit_form = CreatePostForm(
#         title=post.title,
#         subtitle=post.subtitle,
#         img_url=post.img_url,
#         author=post.author,
#         body=post.body
#     )
#     if edit_form.validate_on_submit():
#         post.title = edit_form.title.data
#         post.subtitle = edit_form.subtitle.data
#         post.img_url = edit_form.img_url.data
#         post.author = edit_form.author.data
#         post.body = edit_form.body.data
#         db.session.commit()
#         return redirect(url_for("show_post", post_id=post.id))
#
#     return render_template("create_task.html", form=edit_form)
#
#
# @app.route("/delete/<int:post_id>")
# @admin_only
# def delete_post(post_id):
#     post_to_delete = BlogPost.query.get(post_id)
#     db.session.delete(post_to_delete)
#     db.session.commit()
#     return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
