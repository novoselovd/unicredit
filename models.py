from run import db, app, mail
from passlib.hash import pbkdf2_sha256 as sha256
from time import time
import jwt
from flask_mail import Message
from flask import render_template, url_for
from sqlalchemy import and_, or_, not_
import datetime
from sqlalchemy.types import TypeDecorator, VARCHAR
import json
from sqlalchemy.ext.mutable import Mutable


class PickleType(TypeDecorator):
    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class MutableDict(Mutable, dict):
    @classmethod
    def coerce(cls, key, value):
        # Convert plain dictionaries to MutableDict

        if not isinstance(value, MutableDict):
            if isinstance(value, dict):
                return MutableDict(value)

            # this call will raise ValueError
            return Mutable.coerce(key, value)
        else:
            return value

    def __setitem__(self, key, value):
        "Detect dictionary set events and emit change events."

        dict.__setitem__(self, key, value)
        self.changed()

    def __delitem__(self, key):
        "Detect dictionary del events and emit change events."

        dict.__delitem__(self, key)
        self.changed()
    
    def isin(self, item_id):
        return item_id in dict(self).keys()

    def __getstate__(self):
        return dict(self)

    def __setstate__(self, state):
        self.update(state)


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    surname = db.Column(db.String(120), nullable=False)
    current_balance = db.Column(db.Integer, nullable=False)
    purchases = db.Column(MutableDict.as_mutable(PickleType))

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
            update({UserModel.password: new_password},
                   synchronize_session=False)
        db.session.commit()

    def change_balance(self, new_balance):
        db.session.query(UserModel).filter(UserModel.id == self.id).\
            update({UserModel.current_balance: new_balance},
                   synchronize_session=False)
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
        msg = Message('Reset your password',
                      sender='Слайдовалюта', recipients=[user.email])
        link = 'https://slide-wallet.firebaseapp.com/auth/restore-password?token=' + \
            str(token)[2:-1]
        msg.body = render_template('reset_password.txt',
                                   user=user, link=link)
        msg.html = render_template('reset_password.html',
                                   user=user, link=link)
        mail.send(msg)

    @staticmethod
    def send_support_email(body, user):
        msg = Message('Technical Support message', sender='Слайдовалюта', recipients=[app.config['MAIL_USERNAME']])
        msg.body = render_template('technical_support.txt', user=user, body=body)
        msg.html = render_template('technical_support.html', user=user, body=body)
        mail.send(msg)

    def get_own_purchases_list(self):
        if len(self.purchases) == 0:
            return {'message': 'list is empty'}
        return self.purchases
    
    @classmethod
    def delete(cls, user_id):
        deleted = cls.query.filter_by(id=user_id).delete()
        db.session.commit()


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
    date = db.Column(db.DateTime, nullable=False)
    transaction_type = db.Column(db.String, nullable=False)


    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_transfer_by_id_sender(cls, sender_id):
        return cls.query.filter_by(sender_id=sender_id).first()

    @classmethod
    def find_transfer_by_id_receiver(cls, receiver_id):
        return cls.query.filter_by(receiver_id=receiver_id).first()

    @classmethod
    def find_transfer_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def find_transfer_by_sender_or_receiver_id(cls, user_id):
        return cls.query.filter_by(receiver_id=user_id).all()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'sender_id': x.sender_id,
                'receiver_id': x.receiver_id,
                'amount': x.amount,
                'date': x.date.isoformat(),
                'type': x.transaction_type,
            }
        return {'transactions': list(map(lambda x: to_json(x), TransactionModel.query.all()))}

    @classmethod
    def return_transfer_by_user_id(cls, id):
        def to_json(x):
            return {
                'id': x.id,
                'sender_id': x.sender_id,
                'receiver_id': x.receiver_id,
                'amount': x.amount,
                'date': x.date.isoformat(),
                'type': x.transaction_type,
            }
        return {'transactions': list(map(lambda x: to_json(x),
            TransactionModel.query.filter(or_(TransactionModel.sender_id == id, TransactionModel.receiver_id == id)).all()))}

    @classmethod
    def return_transfer_by_sender_id(cls, id):
        def to_json(x):
            return {
                'id': x.id,
                'sender_id': x.sender_id,
                'receiver_id': x.receiver_id,
                'amount': x.amount,
                'date': x.date.isoformat(),
                'type': x.transaction_type,
            }
        return {'transactions': list(map(lambda x: to_json(x), TransactionModel.query.filter_by(sender_id=id).all()))}

    @classmethod
    def return_transfer_by_receiver_id(cls, id):
        def to_json(x):
            return {
                'id': x.id,
                'sender_id': x.sender_id,
                'receiver_id': x.receiver_id,
                'amount': x.amount,
                'date': x.date.isoformat(),
                'type': x.transaction_type,
            }
        return {'transactions': list(map(lambda x: to_json(x), TransactionModel.query.filter_by(receiver_id=id).all()))}


class ShopItemModel(db.Model):
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    price = db.Column(db.Float, nullable=False)


    @staticmethod
    def to_json(x):
        return {
            'id': x.id,
            'name': x.name,
            'description': x.description,
            'price': x.price
        }

    @classmethod
    def return_all(cls):
        return {'items': list(map(lambda x: cls.to_json(x), ShopItemModel.query.all()))}

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def purchase_item(self, user):
        str_id = str(self.id)  # потому что в словаре ключи хранятся как строка (json-format)
        if user.purchases.isin(str_id):
            user.purchases[str_id] += 1
        else:
            user.purchases[str_id] = 1

        db.session.commit()

    @classmethod
    def find_item_by_id(cls, item_id):
        return cls.query.filter_by(id=int(item_id)).first()

    @classmethod
    def return_item_by_id(cls, item_id):
        return {'item': cls.to_json(cls.find_item_by_id(item_id))}

    @classmethod
    def delete(cls, item_id):
        deleted = cls.query.filter_by(id=item_id).delete()
        db.session.commit()
