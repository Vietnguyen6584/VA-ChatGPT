from flask import Flask, request, jsonify
import openai
import os
import re

app = Flask(__name__)

# Set OpenAI API key
openai.api_key = os.environ["OPENAI_API_KEY"]

# Define ChatGPT model parameters
model_engine = "text-davinci-002"
max_tokens = 1024
temperature = 0.5
top_p = 1

# Define FAQ questions and answers
faq = {
    "What is your name?": "My name is ChatGPT.",
    "How does this work?": "This works by using OpenAI's ChatGPT model to generate responses.",
    "Can you provide an example?": "Sure! Just ask me any question and I'll do my best to answer it."
}

@app.route("/ask", methods=["POST"])
def ask():
    # Get user message from the request
    user_message = request.json["message"]
    print(user_message)

    # Check if the user message matches a FAQ question
    for question, answer in faq.items():
        if re.search(question, user_message, re.IGNORECASE):
            return jsonify({"response": answer})

    # Generate response from ChatGPT model
    response = openai.Completion.create(
        engine=model_engine,
        prompt=user_message,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p
    )

    # Extract text from the response
    response_text = response.choices[0].text.strip()
    print(response_text)
    # Return response to the user
    return jsonify({"response": response_text})

if __name__ == "__main__":
    app.run(debug=True)
