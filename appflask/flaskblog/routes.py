from flask import render_template, url_for, flash, redirect, request
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required

posts = [
    {
        'author': 'John Faria',
        'title': 'Aprendendo NODE.js',
        'content': 'First post content',
        'date_posted': 'May 14, 2018'
    },
    {
        'author': 'Beltrano',
        'title': 'Crindo um CRUD com C++',
        'content': 'Second post content',
        'date_posted': 'May 14, 2018'
    },
    {
        'author': 'Fulano',
        'title': 'Aprendendo Python',
        'content': 'Third post content',
        'date_posted': 'May 14, 2018'
    },
    {
        'author': 'Maria',
        'title': 'Utilizando o Arduino',
        'content': 'Post content',
        'date_posted': 'May 17, 2018'
    },
    {
        'author': 'Claudio ',
        'title': 'Utilizando o MSP430',
        'content': 'Post content',
        'date_posted': 'May 18, 2018'
    }
]


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', posts=posts)


@app.route('/about')
def about():
    return render_template('about.html', title='About')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(
            f'Account created for { form.username.data }, You are now able to log in!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('You Have Been Logged In!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Uncessfull. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('You Have Been Logged Out!', 'success')
    return redirect(url_for('home'))


@app.route('/account')
@login_required
def account():
    return render_template('account.html', title='Account')
