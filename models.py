from run import db, app, mail
from passlib.hash import pbkdf2_sha256 as sha256
from time import time
import jwt
from flask_mail import Message
from flask import render_template, url_for



class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    surname = db.Column(db.String(120), nullable=False)
    current_balance = db.Column(db.Integer, nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'id': x.id,
                'email': x.email,
                'name': x.name,
                'surname': x.surname,
                'balance': x.current_balance
            }

        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def return_user_by_id(cls, id):
        def to_json(x):
            return {
                'username': x.username,
                'id': x.id,
                'email': x.email,
                'name': x.name,
                'surname': x.surname,
                'balance': x.current_balance
            }

        return {'user': to_json(cls.find_by_id(id))}



    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

    def change_password(self, new_password):
        db.session.query(UserModel).filter(UserModel.username == self.username).\
            update({UserModel.password: new_password}, synchronize_session=False)
        db.session.commit()

    def change_balance(self, new_balance):
        db.session.query(UserModel).filter(UserModel.id == self.id).\
            update({UserModel.current_balance: new_balance}, synchronize_session=False)
        db.session.commit()

    def get_reset_password_token(self, expires_in=60000):
        return jwt.encode(
            {'id': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'])['id']
        except:
            return
        return db.session.query(UserModel).filter(UserModel.id == id).first()

    @staticmethod
    def send_password_reset_email(user):
        token = user.get_reset_password_token()
        msg = Message('Reset your password', sender='Слайдовалюта', recipients=[user.email])
        link = 'https://slide-wallet.firebaseapp.com/auth/restore-password?token=' + str(token)
        msg.body = render_template('reset_password.txt',
                                         user=user, link=link)
        msg.html = render_template('reset_password.html',
                                         user=user, link=link)
        mail.send(msg)


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)


class TransactionModel(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    receiver_id = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Integer, nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
