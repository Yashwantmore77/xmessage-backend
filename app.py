from flask import Flask, jsonify, request , render_template
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import jwt
import datetime
from flask_cors import CORS  # Import CORS
from flask_socketio import SocketIO, emit
from pymongo.server_api import ServerApi

app = Flask(__name__)
uri = "mongodb+srv://yashwantmore77:bh9RWf0EGKA13LsO@cluster0.oyjdx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins; you can restrict this to specific origins if needed
socketio = SocketIO(app, cors_allowed_origins="*")

app.config['SECRET_KEY'] = 'xmessages'  # Replace with your own secret key


# Connect to MongoDB
# client = MongoClient('mongodb://localhost:27017/')

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))


# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)


# Select the database
db = client['xmessages']

# Select the collection
collection = db['users']  # Assume we are dealing with a users collection
login_records_collection = db['login_records'] # New collection for tracking login records

@app.route('/')
def index():
    return 'Hello, World!'

@app.route('/add', methods=['POST'])
def add_user():
    data = request.json
    
    # Hash the password before storing it
    password = data.get('password')
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Store the user data with the hashed password
    data['password'] = hashed_password.decode('utf-8')
    
    result = collection.insert_one(data)
    return jsonify({'result': str(result.inserted_id)}), 201

@app.route('/users', methods=['GET'])
def get_users():
    users = list(collection.find())
    for user in users:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string
        user.pop('password', None)  # Remove the password field from the response for security
    return jsonify(users)

@app.route('/update_password/<id>', methods=['PUT'])
def update_password(id):
    # Convert the ID from a string to an ObjectId
    object_id = ObjectId(id)
    
    # Get the new password from the request
    new_password = request.json.get('password')
    
    # Hash the new password before storing it
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    # Update the user's password
    result = collection.update_one({'_id': object_id}, {'$set': {'password': hashed_password.decode('utf-8')}})
    
    # Check if the document was updated
    if result.matched_count > 0:
        return jsonify({'result': 'Password updated successfully'}), 200
    else:
        return jsonify({'result': 'User not found'}), 404
    

@app.route('/delete/<id>', methods=['DELETE'])
def delete_user(id):
    # Convert the ID from a string to an ObjectId
    object_id = ObjectId(id)
    
    # Delete the document from the collection
    result = collection.delete_one({'_id': object_id})
    
    # Check if the document was deleted
    if result.deleted_count > 0:
        return jsonify({'result': 'User deleted successfully'}), 200
    else:
        return jsonify({'result': 'User not found'}), 404


@app.route('/login', methods=['POST'])
def login():
    # Get the username and password from the request
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Find the user in the database
    user = collection.find_one({'username': username})
    
    if user:
        # Check if the provided password matches the stored hashed password
        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            # Generate a JWT token
            token = jwt.encode({
                'user_id': str(user['_id']),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')

             # Record the login attempt
            login_record = {
                'user_id': user['_id'],
                'login_time': datetime.datetime.utcnow(),
                'ip_address': request.remote_addr,  # Store the IP address
                'user_agent': request.headers.get('User-Agent')  # Store the user agent (browser/device info)
            }
            login_records_collection.insert_one(login_record)

            return jsonify({'token': token}), 200
        else:
            return jsonify({'result': 'Invalid credentials'}), 401
    else:
        return jsonify({'result': 'User not found'}), 404

# Route for verifying the token (for protected routes)
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    try:
        # Decode the token
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']
        
        # Find the user in the database
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
    # Send the signaling data to the intended peer
    emit('signal', data, broadcast=True)


if __name__ == '__main__':
    app.run(debug=True)
