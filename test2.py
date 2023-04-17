from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from flask_session import Session
import openai
import os
import re
import json
import time
from pathlib import Path
from flask_cors import CORS, cross_origin
from flask_socketio import join_room, emit, SocketIO, leave_room


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
                stored_username, stored_password, stored_id = line.strip().split(':')
                if username == stored_username and password == stored_password:
                    session['logged_in'] = True
                    session['username'] = username
                    session['user_id'] = stored_id
                    filename ='userAppData/' + stored_id + '.json'
                    chatfile = open(filename, 'r+')
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

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
