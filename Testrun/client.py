import requests

url = "http://localhost:5000/tell"


#prompt_text = input("You: ")
prompt_text = ("Hello")
data = {"message": prompt_text}

try:
    response = requests.post(url, json=data)
    print(response)
    response.raise_for_status()
except requests.exceptions.HTTPError as err:
    print(err)
else:
    print(response.json()["response"])
