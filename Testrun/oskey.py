from flask import Flask, request
import openai
import os

app = Flask(__name__)
print(os.environ)