from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from flask import jsonify
import datetime

errors = {
    'ExpiredSignatureError': {
        'message': 'Token has expired',
        'status': 401
    }
}

app = Flask(__name__)
CORS(app)
api = Api(app, errors=errors)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_USERNAME'] = 'slidecurrence@gmail.com'
app.config['MAIL_PASSWORD'] = 'slidevaluehse'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
mail = Mail(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=900)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)

db = SQLAlchemy(app)


@app.before_first_request
def create_tables():
    db.create_all()



app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)


app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({
        'status': 401,
        'sub_status': 43,
        'msg': f'Problem is {reason}'
    }), 401


@jwt.expired_token_loader
def expired_token_callback(expired_token):
    token_type = expired_token['type']
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'msg': 'The {} token has expired'.format(token_type)
    }), 401


@jwt.user_identity_loader
def user_identity_lookup(user):
    return {
        'username': user.username,
        'id': user.id,
        'email': user.email,
        'name': user.name,
        'surname': user.surname,
        'balance': user.current_balance
    }


#TODO: Consider moving to the top and get rid off circular dependency of db haha

import resources, views, models

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.SecretResource, '/secret')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.UserChangePassword, '/password/change')
api.add_resource(resources.UserForgotPassword, '/password/forgot')
api.add_resource(resources.UserResetPasswordViaEmail,
                 '/password/forgot/reset/<token>')
api.add_resource(resources.Transaction, '/transaction')
api.add_resource(resources.UserFindById, '/user/<id>')
api.add_resource(resources.AllTransactions, '/alltransactions')
api.add_resource(resources.FindTransferById, '/transfers')
api.add_resource(resources.UserGetSupport, '/support')
api.add_resource(resources.ItemsInShop, '/shop')
api.add_resource(resources.AddItemToShop, '/shop/additem')
api.add_resource(resources.BuyItem, '/shop/buy')
api.add_resource(resources.GetOwnPurchases, '/mypurchases')
api.add_resource(resources.GetItemById, '/items/<item_id>')
api.add_resource(resources.AddMoney, '/addmoney')
api.add_resource(resources.UserDelete, '/deleteuser')
api.add_resource(resources.ItemDelete, '/deleteitem')
api.add_resource(resources.ItemUpdate, '/updateitem')
api.add_resource(resources.AddNewAdmin, '/add_new_admin')
