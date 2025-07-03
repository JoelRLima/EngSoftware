from flask import Blueprint, request, jsonify
from app import db, bcrypt
from app.models import User
from app.utils.jwt_handler import generate_token
from flask_jwt_extended import jwt_required, get_jwt_identity
from flasgger import swag_from

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'schema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string'},
                'email': {'type': 'string'},
                'password': {'type': 'string'}
            },
            'required': ['username', 'email', 'password']
        }
    }],
    'responses': {
        200: {'description': 'User created successfully'},
        400: {'description': 'User already exists'}
    }
})
def register():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Corpo da requisição não pode ser vazio'}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'message': 'Campos username, email e password são obrigatórios'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'message': 'Usuário já existe'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'Usuário criado com sucesso'}), 200

@auth_bp.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'schema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string'},
                'password': {'type': 'string'}
            },
            'required': ['username', 'password']
        }
    }],
    'responses': {
        200: {'description': 'Login successful'},
        401: {'description': 'Invalid credentials'}
    }
})
def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Corpo da requisição não pode ser vazio'}), 400

    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'message': 'Campos username e password são obrigatórios'}), 400

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        token = generate_token(identity=user.id)
        return jsonify({'access_token': token}), 200
    return jsonify({'message': 'Usuário ou senha inválidos'}), 401

@auth_bp.route('/edit', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Auth'],
    'security': [{'BearerAuth': []}],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'schema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string'},
                'email': {'type': 'string'},
                'password': {'type': 'string'}
            }
        }
    }],
    'responses': {
        200: {'description': 'Conta atualizada com sucesso'},
        400: {'description': 'Dados inválidos'}
    }
})
def edit_account():
    user_id = get_jwt_identity()
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Corpo da requisição não pode ser vazio'}), 400

    user = User.query.get(user_id)

    new_username = data.get('username')
    if new_username:
        if User.query.filter(User.username == new_username, User.id != user_id).first():
            return jsonify({'message': 'Nome de usuário já em uso'}), 400
        user.username = new_username

    new_email = data.get('email')
    if new_email:
        if User.query.filter(User.email == new_email, User.id != user_id).first():
            return jsonify({'message': 'E-mail já em uso'}), 400
        user.email = new_email

    new_password = data.get('password')
    if new_password:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')

    db.session.commit()
    return jsonify({'message': 'Conta atualizada com sucesso'}), 200
