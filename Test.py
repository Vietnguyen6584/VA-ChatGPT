import re

import openai
openai.api_key = "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"

# Set up the prompt text and parameters
prompt_text = "Hello, how are you today?"
model_engine = "text-davinci-002"
temperature = 0.5
max_tokens = 50

# Define FAQ
faq = {
    "What is your return policy?": "Our return policy is ...",
    "How long does shipping take?": "Shipping usually takes ...",
    "What payment methods do you accept?": "We accept ...",
}

def check_faq(user_input):
    for question, answer in faq.items():
        if re.search(question, user_input, re.IGNORECASE):
            return answer
    return None

def generate_response(user_input):
    faq_answer = check_faq(user_input)
    if faq_answer:
        return faq_answer
    else:
        response = openai.Completion.create(
            engine=model_engine,
            prompt=user_input,
            max_tokens=1024,
            n=1,
            stop=None,
            temperature=0.7,
        )
        return response.choices[0].text.strip()

while True:
    prompt_text = input("You: ")
    if(prompt_text == "endchat"): break;
    response = generate_response(prompt_text)
    generated_text = response

    # Print the generated text
    print(generated_text)
    print("Type endchat to stop")
