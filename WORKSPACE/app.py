from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "DEVELOPED_BY_KEERTHIVASAN"

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login" 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(80), nullable=False, unique=True)
    Password = db.Column(db.String(255), nullable=False)  # Corrected field name


class RegisterForm(FlaskForm):
    Username = StringField(validators=[InputRequired(), length(min=4, max=25)], render_kw={"placeholder": "Username"})
    Password = PasswordField(validators=[InputRequired(), length(min=4, max=25)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, Username):
        existing_user = User.query.filter_by(Username=Username.data).first()
        if existing_user:
            raise ValidationError("That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    Username = StringField(validators=[InputRequired(), length(min=4, max=25)], render_kw={"placeholder": "Username"})
    Password = PasswordField(validators=[InputRequired(), length(min=4, max=25)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(Username=form.Username.data).first()
        if user and bcrypt.check_password_hash(user.Password, form.Password.data):
            login_user(user)  
            return redirect(url_for('dashboard'))
        return "Invalid username or password"
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.Password.data).decode('utf-8')
        new_user = User(Username=form.Username.data, Password=hashed_password) 
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
