# app.py
from flask import Flask, jsonify, request
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import jwt
import datetime
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from pymongo.server_api import ServerApi
import os

def create_app():
    app = Flask(__name__)
    uri = "mongodb+srv://yashwantmore77:bh9RWf0EGKA13LsO@cluster0.oyjdx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

    # Enable CORS
    CORS(app, resources={r"/*": {"origins": "*"}})
    socketio = SocketIO(app, cors_allowed_origins="*")

    app.config['SECRET_KEY'] = 'your-secret-key'

    # Connect to MongoDB
    client = MongoClient(uri, server_api=ServerApi('1'))
    try:
        client.admin.command('ping')
        print("Connected to MongoDB")
    except Exception as e:
        print(e)

    db = client['xmessages']
    collection = db['users']
    login_records_collection = db['login_records']

    @app.route('/')
    def index():
        return 'Hello, World!'

    @app.route('/add', methods=['POST'])
    def add_user():
        data = request.json
        password = data.get('password')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        data['password'] = hashed_password.decode('utf-8')
        result = collection.insert_one(data)
        return jsonify({'result': str(result.inserted_id)}), 201

    @app.route('/users', methods=['GET'])
    def get_users():
        users = list(collection.find())
        for user in users:
            user['_id'] = str(user['_id'])
            user.pop('password', None)
        return jsonify(users)

    @app.route('/update_password/<id>', methods=['PUT'])
    def update_password(id):
        object_id = ObjectId(id)
        new_password = request.json.get('password')
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        result = collection.update_one({'_id': object_id}, {'$set': {'password': hashed_password.decode('utf-8')}})
        if result.matched_count > 0:
            return jsonify({'result': 'Password updated successfully'}), 200
        else:
            return jsonify({'result': 'User not found'}), 404

    @app.route('/delete/<id>', methods=['DELETE'])
    def delete_user(id):
        object_id = ObjectId(id)
        result = collection.delete_one({'_id': object_id})
        if result.deleted_count > 0:
            return jsonify({'result': 'User deleted successfully'}), 200
        else:
            return jsonify({'result': 'User not found'}), 404

    @app.route('/login', methods=['POST'])
    def login():
        data = request.json
        username = data.get('username')
        password = data.get('password')
        user = collection.find_one({'username': username})
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                token = jwt.encode({
                    'user_id': str(user['_id']),
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }, app.config['SECRET_KEY'], algorithm='HS256')
                login_record = {
                    'user_id': user['_id'],
                    'login_time': datetime.datetime.utcnow(),
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent')
                }
                login_records_collection.insert_one(login_record)
                return jsonify({'token': token}), 200
            else:
                return jsonify({'result': 'Invalid credentials'}), 401
        else:
            return jsonify({'result': 'User not found'}), 404

    @app.route('/protected', methods=['GET'])
    def protected():
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data['user_id']
            user = collection.find_one({'_id': ObjectId(user_id)})
            if user:
                return jsonify({'message': f'Welcome {user["username"]}!'}), 200
            else:
                return jsonify({'message': 'User not found!'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

    @socketio.on('connect')
    def handle_connect():
        print('Client connected')

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')

    @socketio.on('signal')
    def handle_signal(data):
        emit('signal', data, broadcast=True)

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
