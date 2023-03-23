from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FloatField, BooleanField, PasswordField, HiddenField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo
from wtforms_sqlalchemy.fields import QuerySelectField, QuerySelectMultipleField
from app import Group
import app

    
def group_query():
    return Group.query

def user_query():
    return app.User.query

def get_pk(obj):
    return str(obj)

class UserForm(FlaskForm):
    name = StringField('Vardas', validators=[DataRequired(message='Įveskite vardą')])
    l_name = StringField('Pavardė', validators=[DataRequired(message='Įveskite pavardę')])
    email = StringField('El. paštas', validators=[DataRequired(message='Įveskite el.paštą')])
    password = PasswordField('Slaptažodis', validators=[DataRequired(message='Įveskite slaptažodį')])
    repeat_password = PasswordField("Pakartokite slaptažodį", [EqualTo('password', "Slaptažodis turi sutapti.")])
    groups = QuerySelectMultipleField(query_factory=group_query, get_label="name", get_pk=get_pk)
    submit = SubmitField('Prisiregistruoti')
    
    def check_user(self, email):
        user = app.User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Šis el.paštas jau registruotas')
    
class LoginForm(FlaskForm):
    email = StringField('El. paštas', [DataRequired()])
    password = PasswordField('Slaptažodis', [DataRequired()])
    remember = BooleanField("Prisiminti mane")
    submit = SubmitField('Prisijungti')
    
class GroupForm(FlaskForm):
    name = StringField('Pavadinimas', validators=[DataRequired(message='Įveskite grupės pavadinimą')])
    submit = SubmitField('Pridėti grupę')

class BillForm(FlaskForm):
    sum = FloatField('Suma', validators=[DataRequired(message='Įveskite sąskaitos sumą')])
    description = TextAreaField('Komentaras', [DataRequired(message='Įveskite aprašymą'), Length(max=200)])
    group = HiddenField('group_id')
    submit = SubmitField('Pridėti sąskaitą')    
