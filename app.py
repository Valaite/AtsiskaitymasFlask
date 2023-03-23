import os
from flask import Flask, render_template,  redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user, login_required
from flask_bcrypt import Bcrypt

import forms

basedir = os.path.abspath(os.path.dirname(__file__))
print(basedir)

app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'registration'
login_manager.login_message_category = 'info'

SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:///'+ os.path.join(basedir, 'bills.sqlite')) + '?check_same_thread=False'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

bcrypt = Bcrypt(app)

association_table = db.Table(
    'association', db.metadata,
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column("Vardas", db.String(50), nullable=False)
    l_name = db.Column("Pavarde", db.String(50), nullable=False)
    email = db.Column("El_pastas", db.String(120), unique=True, nullable=False)
    password = db.Column("Slaptazodis", db.String(60), unique=True, nullable=False)
    groups = db.relationship("Group", secondary=association_table, back_populates="users")
    
class Group(db.Model):
    __tablename__ = "group"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column('Pavadinimas', db.String(50), nullable=False)
    users = db.relationship('User', secondary=association_table, back_populates="groups")
    bills = db.relationship('Bill', back_populates="group")

class Bill(db.Model):
    __tablename__ = "bill"
    id = db.Column(db.Integer, primary_key=True)
    sum = db.Column("Suma", db.Float, nullable=False)
    description = db.Column("Komentaras", db.String(120), unique=True, nullable=False)
    group = db.relationship("Group")
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    

@login_manager.user_loader
def load_user(user_id):
    db.create_all()
    return User.query.get(int(user_id))

@app.route("/registration", methods=['GET', 'POST'])
def registration():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('groups'))
    form = forms.UserForm()
    if form.validate_on_submit():
        bcrypt_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(name=form.name.data, l_name=form.l_name.data, email=form.email.data, password=bcrypt_password)
        for group in form.groups.data:
           added_group = Group.query.get(group.id)
           new_user.groups.append(added_group)
        db.session.add(new_user)
        db.session.commit()
        flash('Sėkmingai prisiregistravote! Galite prisijungti', 'success')
        return redirect(url_for('groups'))
    return render_template('registration.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('groups'))
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('groups'))
        else:
            flash('Prisijungti nepavyko. Patikrinkite el. paštą ir slaptažodį', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('base'))

@app.route("/add_group", methods=["GET", "POST"])
def add_group():
    db.create_all()
    form = forms.GroupForm()
    if form.validate_on_submit():
        add_group = Group(name=form.name.data)
        db.session.add(add_group)
        db.session.commit()
        return render_template("add_group.html", form=False)
    return render_template("add_group.html", form=form)
   
@app.route("/groups")
@login_required
def groups():
    db.create_all()
    try:
        groups = Group.query.filter_by(user_id=current_user.id).all()
    except:
        groups = []
    print(groups)
    return render_template("groups.html", groups=groups)

@app.route("/join_group", methods=["GET", "POST"])
@login_required
def join_group():
    db.create_all()
    form = forms.UserForm()
    groups = Group.query.filter(~Group.users.contains(current_user)).all()
    form.groups.choices = [(g.id, g.name) for g in groups]
    if form.validate_on_submit():
        group_id = form.groups.data
        group = Group.query.get(group_id)
        current_user.groups.append(group)
        db.session.commit()
        flash('Sėkmingai prisijungėte prie grupės', 'success')
        return redirect(url_for('groups'))
    return render_template("join_group.html", form=form)

@app.route('/group/<int:group_id>/bills')
def group_bills(group_id):
    group = Group.query.get(group_id)
    if group is None:
        return "Group not found", 404
    bills = Bill.query.filter_by(group_id=group_id).all()
    return render_template('bills.html', group=group, bills=bills)

@app.route("/group/<int:group_id>/add_bill", methods=["GET", "POST"])
def add_bill(group_id):
    db.create_all()
    group = Group.query.get(group_id)
    form = forms.BillForm()
    if form.validate_on_submit():
        add_bill = Bill(sum=form.sum.data, description=form.description.data, group_id=group_id)
        db.session.add(add_bill)
        db.session.commit()
        return render_template("add_bill.html", group=group, form=False)
    form.group.data = group_id
    return render_template("add_bill.html", group=group, form=form)

@app.route('/')
def base():
    return render_template('base.html')

if __name__ == '__main__':
    app.run(host='localhost', port=5001, debug=True)
    db.create_all()