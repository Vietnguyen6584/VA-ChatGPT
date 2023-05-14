from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from flask_session import Session
import openai
import os
import re
import json
import time
import csv
from pathlib import Path
from flask_cors import CORS, cross_origin
from flask_socketio import join_room, emit, SocketIO, leave_room
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
#app.config['SESSION_COOKIE_NAME'] = 'my_session_id'
Session(app)
CORS(app)
app.secret_key = '1212'

# Define ChatGPT model parameters
model_engine = "text-davinci-002"
max_tokens = 1024
temperature = 0.5
top_p = 1

socketio = SocketIO(app, cors_allowed_origins="*")
USER_FILE = 'userAppData/user.txt'
chatfile = open('userAppData/dump.json', 'w+')
filename = 'userAppData/dump.json'
faq = {
    "What is your return policy?": "Our return policy is ...",
    "How long does shipping take?": "Shipping usually takes ...",
    "What payment methods do you accept?": "We accept ...",
    "Hello": "Hello, how will i help you ?",
}

@app.before_request
def before_request():
    if request.path == '/sendToUser': print()

@socketio.on('connect')
def connectuser(userid):
    join_room(session[userid])
@socketio.on('connect')
def disconnectuser(userid):
    leave_room(session[userid])

def sendMesssage(userid):
    emit('message', {'text': 'Hello, client!'}, room=session['user_id'])
def check_faq(user_input):
    for question, answer in faq.items():
        if re.search(question, user_input, re.IGNORECASE):
            return answer
    return None
def read_chatlog(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    data = []
    for line in lines:
        data.append(json.loads(line.strip()))
    
    return json.dumps(data)
# Function to derive a key from a user-provided key string
def derive_key(key_str, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(key_str.encode())
    return key

# Function to encrypt a message with a key
def encrypt_message(message, key):
    # Generate an initialization vector (IV)
    iv = os.urandom(16)

    # Create a cipher object with the AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Create a padder object to pad the message to a multiple of 128 bits
    padder = padding.PKCS7(128).padder()

    # Pad the message
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Return the IV and encrypted message
    return iv + encrypted_message

# Function to decrypt a message with a key
def decrypt_message(encrypted_message, key):
    # Extract the IV from the encrypted message
    iv = encrypted_message[:16]

    # Create a cipher object with the AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Create an unpadder object to remove padding from the decrypted message
    unpadder = padding.PKCS7(128).unpadder()

    # Decrypt the message
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()

    # Remove padding from the decrypted message
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    # Return the decrypted message as a string
    return unpadded_message.decode()

def generate_response(user_input):
    faq_answer = check_faq(user_input)
    if faq_answer:
        return faq_answer
    else:
        response = openai.Completion.create(
            engine=model_engine,
            prompt=user_input,
            max_tokens=max_tokens,
            n=1,
            stop=None,
            temperature=0.5,
            top_p=top_p
        )
        return response.choices[0].text.strip()

@app.route('/')
@cross_origin(supports_credentials=True)
def index():
    if 'logged_in' in session:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open(USER_FILE, 'r') as f:
            for line in f:
                stored_id, stored_username, stored_email, stored_role, stored_password = line.strip().split(',')
                if username == stored_username and password == stored_password:
                    session['logged_in'] = True
                    session['username'] = username
                    session['user_id'] = stored_id
                    session['email'] = stored_email
                    session['role'] = stored_role
                    filename = 'userAppData/' + stored_id + '.json'
                    chatfile = open(filename, 'a+')
                    chatfile.close()
                    return redirect(url_for('home'))

        error = 'Invalid username or password'
        return render_template('login.html', error=error)
        
    else:
        return render_template('login.html')

    

@app.route('/logout')

def logout():
    # Clear the session variables
    session.clear()
    return redirect(url_for('login'))


@app.route('/home')
@cross_origin(supports_credentials=True)
def home():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    #print('home')
    print(session)
    filename ='userAppData/' + session['user_id'] + '.json'
    chatlog = read_chatlog(filename)
    #print(chatlog)    
    #print(filename)
    #print(type(chatlog))
    return render_template('home.html', chatlog=chatlog, username=session['username'], user_id=session['user_id'])


@app.route("/ask", methods=["POST"])
@cross_origin(supports_credentials=True)

def ask():
    
    user_message = request.json.get('userInput')
    user_id = request.json.get('user_id')
    #print(session)
    filename ='userAppData/' + user_id + '.json'
    print("saving to")
    print(filename)
    print(user_message)
    
    msg = [
        {
        "sender": "user",
        "text": user_message,
        "timestamp": time.time()
        },
    ]
    
    
    json_string = json.dumps(msg)
    with open(filename, mode="a") as f:
        f.write(json_string)
        f.write('\n')
        f.close()
    response = generate_response(user_message)
    
    response_text = response
    
    msg = [
        {
        "sender": "va",
        "text": response_text,
        "timestamp": time.time()
        },
    ]
    json_string = json.dumps(msg)
    with open(filename, 'a') as f:
        f.write(json_string)
        f.write('\n')
        f.close()
    print(response)

    return jsonify({"response": response_text})
@app.route('/get-id', methods=['POST'])
def get_id():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
        print("redirect to login")
    print(session['username'])
    return jsonify({'id': session['user_id']})

@app.route('/admin')
def admin():
    #print(session.get('role'))
    if session.get('role') == '1':
        return render_template('admin.html')
    else:
        return "Access denied"


@app.route('/admin/users')
def users():
    if session.get('role') == '1':
        with open(USER_FILE, 'r') as file:
            lines = file.readlines()[1:]
        # Parse data into list of dictionaries
        users = []
        for line in lines:
            user_data = line.strip().split(',')
            user = {
                'id': user_data[0],
                'username': user_data[1],
                'email': user_data[2],
                'role': user_data[3],
                #'password': user_data[4]
            }
            users.append(user)
        # Convert list of dictionaries to JSON
        users_json = json.dumps(users)
        #print(users_json)
        # Render the template and pass the JSON data to it
        return render_template('users.html', users_data=users_json)
    else:
        return "Access denied"
@app.route('/input_key', methods=['GET', 'POST'])
def input_key():
    if request.method == 'POST':
        session['userkey'] = request.form['userkey']
        return redirect('/home')
    return render_template('input_key.html')


@app.route('/auth/check')
def check_auth():
    if 'logged_in' in session and session['logged_in'] and 'role' in session and session['role'] == 1:
        return {'authenticated': True, 'role': session['role'], 'username': session['username']}
    else:
        return {'authenticated': False}
@app.route('/removeuser/<int:user_id>', methods=['DELETE'])
def remove_user(user_id):
    if session.get('role') == '1':
        if user_id == session.get('user_id'): 
            return "Can't delete the logged in account"
        with open(USER_FILE, 'r') as file:
            lines = file.readlines()
        with open(USER_FILE, 'w') as file:
            for line in lines:
                if not line.startswith(str(user_id)):
                    file.write(line)
        return "User deleted successfully"
    else:
        return "Access denied"
@app.route('/user/<int:user_id>')
def user_profile(user_id):
    if session.get('role') == '1':
        with open(USER_FILE, 'r') as file:
            lines = file.readlines()
            for line in lines[1:]:
                user_data = line.strip().split(',')
                if int(user_data[0]) == user_id:
                    user = {'id': user_data[0], 'username': user_data[1], 'email': user_data[2], 'role': user_data[3], 'password': user_data[4]}
                    filename='userAppData/'+user_data[0]+'.json'
                    chatlog = read_chatlog(filename)
                    print(chatlog)
                    return render_template('userprofile.html', user=user, session=session, chatlog=chatlog)
            return "User not found"
    else:
        return "Access denied"

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
