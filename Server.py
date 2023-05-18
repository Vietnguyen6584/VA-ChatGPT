from flask import Flask, request, jsonify, session, redirect, url_for, render_template, make_response
from flask_session import Session
import requests
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
import base64
from cryptography.hazmat.primitives import padding
from io import StringIO


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
FAQfile = 'FAQ.csv'
#salt use to generate key 
salt = b'\xf8nHCf\xec\xf9V\x0c0\xf1\xc6 \xe5r '

faq = {
    "What is your return policy?": "Our return policy is ...",
    "How long does shipping take?": "Shipping usually takes ...",
    "What payment methods do you accept?": "We accept ...",
    "Hello": "Hello, how will i help you ?",
}
def process_faq_to_json(faq):
    processed_faq = []
    for question, answer in faq.items():
        processed_question = {"Q": question}
        processed_answer = {"A": answer}
        processed_faq.append({**processed_question, **processed_answer})
    return json.dumps(processed_faq)

def import_faq_data(filename):
    faq_data = {}
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            faq_data[row[0]] = row[1]
    return faq_data

def export_faq_data(filename, faq_data):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        for question, answer in faq_data.items():
            writer.writerow([question, answer])
#export_faq_data(FAQfile, faq)
faq = import_faq_data(FAQfile)
@app.before_request
def before_request():
    if 'userkey' in session:
        print("session key:"+session['userkey'])
    else: 
        print("Session key not foundaaaaaaa")

def check_faq(user_input):
    for question, answer in faq.items():
        if re.search(question, user_input, re.IGNORECASE):
            return answer
    return None
import ast

def read_chatlog(filename, userkey):
    with open(filename, 'r') as f:
        lines = f.readlines()

    data = []
    for line in lines:
        message_list = json.loads(line.strip())

        # Iterate over each message in the list
        for message in message_list:
            encrypted_text = message['text']
            decrypted_text = decrypt_message(bytes.fromhex(encrypted_text), userkey)
            message['text'] = decrypted_text
            data.append(message)

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
    try:
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
    except ValueError as e:
        # Padding error occurred
        print("Padding error:", str(e))
        return "Unknown message (Key error)"
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

@app.route('/signup', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        with open(USER_FILE, 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # Skip the header line
                stored_id, stored_username, stored_email, stored_role, stored_password = line.strip().split(',')
                if username == stored_username:
                    error = 'Username already exists'
                    return render_template('signup.html', error=error)
                if email == stored_email:
                    error = 'Email already exists'
                    return render_template('signup.html', error=error)

        # Append user data to the file
        with open(USER_FILE, 'a') as f:
            user_id = len(lines) - 1  # Number of lines excluding the header
            role = 3
            new_user = f"\n{user_id},{username},{email},{role},{password}"
            f.write(new_user)

        return redirect(url_for('login'))

    else:
        return render_template('signup.html')



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
                    session['decodekey'] = "123"
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
    if 'userkey' in session:
        print("session key:"+session['userkey'])
        keyfilename = 'userAppData/userkey/' + session['user_id'] + '.key'
        print(keyfilename)
        with open(keyfilename, 'w') as file:
            ekey = derive_key(session['userkey'], salt)
            ekey = base64.b64encode(ekey).decode('utf-8')
            print("ekey:" +ekey)
            file.write(ekey)
            ekey = base64.b64decode(ekey)
            
        file.close()
    else: 
        print("Session key not found")
        return redirect('/input_key')
    print(session)
    filename ='userAppData/' + session['user_id'] + '.json'
    chatlog = read_chatlog(filename, ekey)
    print(chatlog)    
    #print(filename)
    #print(type(chatlog))
    return render_template('home.html', chatlog=chatlog, username=session['username'], user_id=session['user_id'])


@app.route("/ask",  methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def ask():
    print(faq)
    user_message = request.json.get('userInput')
    user_id = request.json.get('user_id')
    if user_id == None:
        filename = 'userAppData/dump.json'
    else:
        filename ='userAppData/' + user_id + '.json'
    print(session)

    #keyfile part
    keyfilename = 'userAppData/userkey/' + str(user_id) + '.key'
    with open(keyfilename, 'r') as file:
        userkey = ekey = base64.b64decode(file.readline().strip())
    file.close()
    print("userkey:")
    print(userkey)

    print("saving to")
    print(filename)
    print(user_message)
    msg = [
        {
        "sender": "user",
        "text": encrypt_message(user_message, userkey).hex(),
        "timestamp": time.time()
        },
    ]
    response = generate_response(user_message)
    json_string = json.dumps(msg)
    with open(filename, mode="a") as f:
        f.write(json_string)
        f.write('\n')
        f.close()
    
    response_text = response
    msg = [
        {
        "sender": "va",
        "text": encrypt_message(response_text, userkey).hex(),
        "timestamp": time.time()
        },
    ]
    print(msg)
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
    print(session)
    if session.get('role') == '1':
        return redirect('/adminusers')
    else:
        return "Access denied"

@app.route('/datamanage')
def datamanage():
    if session.get('role') == '1':
        faq_json = process_faq_to_json(faq)
        return render_template('dataM.html', faq = faq_json)
    else:
        return "Access denied"


@app.route('/importfaq', methods=['POST'])
def import_faq():
    # Check if a file was uploaded
    if 'faqFile' not in request.files:
        return 'No file uploaded'

    file = request.files['faqFile']

    # Check if the file is CSV format
    if not file.filename.endswith('.csv'):
        return 'Invalid file format'

    # Read and process the CSV data
    faq_data = {}
    reader = csv.reader(file.stream.read().decode("UTF8").splitlines())
    for row in reader:
        if len(row) == 2:
            faq_data[row[0]] = row[1]
    faq.update(faq_data)
    export_faq_data(FAQfile, faq_data)
    # Do something with the imported FAQ data
    # For example, you can store it in a database or update an existing FAQ dictionary

    return redirect('/datamanage')

@app.route('/exportfaq')
def export_faq():
    # Create a string buffer to store the CSV data
    csv_data = StringIO()
    writer = csv.writer(csv_data)
    for key, value in faq.items():
        writer.writerow([key, value])
    
    # Create a response with the CSV data and headers for file download
    response = make_response(csv_data.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=faq_data.csv'
    response.headers['Content-Type'] = 'text/csv'
    
    return response


@app.route('/adminusers')
def adminusers():
    print(session)
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
        return render_template('users.html', users_data=users_json, username=session['username'])
    else:
        return "Access denied"

@app.route('/input_key', methods=['GET', 'POST'])
def input_key():
    if request.method == 'POST':
        session['userkey'] = request.form['userkey']
        return redirect('/home')
    return render_template('input_key.html')

@app.route('/key', methods=['GET', 'POST'])
def key():
    return None

@app.route('/decode', methods=['GET', 'POST'])
def decode():
    if request.method == 'POST':
        print(request.form)
        session['decodekey'] = request.form['key']
        if request.form['userId']!=None:
            url = "http://localhost:5000/user/" + request.form['userId']
        else:
            url = "http://localhost:5000/adminusers"
        return redirect(url)    
    return redirect('/admin')


@app.route('/savemessage', methods=['GET', 'POST'])
def savemessage():
    return None
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
                    key = session['decodekey']
                    print(key)
                    key = derive_key(key, salt)
                    chatlog = read_chatlog(filename, key)
                    print(chatlog)
                    return render_template('userprofile.html', user=user, session=session, chatlog=chatlog)
            return "User not found"
    else:
        return "Access denied"
@app.route('/edituser/<int:user_id>', methods=['GET', 'POST'])
def edituser(user_id):
    if request.method == 'POST':
        # Read the existing user data from the file
        with open(USER_FILE, 'r') as file:
            lines = file.readlines()

        # Extract the edited user information from the form data
        edited_user_data = {
            'id': str(user_id),
            'username': request.form['username'],
            'email': request.form['email'],
            'role': request.form['role'],
            'password': request.form['password']
        }

        # Check if the edited user email or username already exists
        for line in lines[1:]:
            existing_user_data = line.strip().split(',')
            if (existing_user_data[1] == edited_user_data['username'] or
                    existing_user_data[2] == edited_user_data['email']) and existing_user_data[0] != edited_user_data['id']:
                return "Error: Email or username already exists"

        # Update the user data in memory
        lines[user_id + 1] = f"{edited_user_data['id']},{edited_user_data['username']},{edited_user_data['email']},{edited_user_data['role']},{edited_user_data['password']}\n"

        # Write the updated user data back to the file
        with open(USER_FILE, 'w') as file:
            file.writelines(lines)
        url = "http://localhost:5000/user/" + str(user_id)
        return redirect(url)
if __name__ == "__main__":
    app.run(debug=True, threaded=True)
