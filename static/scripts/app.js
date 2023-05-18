const chatBody = document.querySelector(".chat-body");
const txtInput = document.querySelector("#txtInput");

window.addEventListener('load', function() {
  var chatlogEl = document.getElementById("chatlog");
  var chatlogRaw = chatlogEl.getAttribute("data-chatlog");
  var chatlogJson = JSON.parse(chatlogRaw);
  for (var i = 0; i < chatlogJson.length; i++) {
    var message = chatlogJson[i];
    console.log("Sender: " + message.sender);
    console.log("Text: " + message.text);

    renderMessageEle(message.text, message.sender);
    
  }
  const usernameElement = document.getElementById('username');
  const userIdElement = document.getElementById('user_id');
  const username = usernameElement.dataset.username;
  const userId = userIdElement.dataset.user_id;
  console.log(`Username: ${username}, User ID: ${userId}`);
});

document.addEventListener('DOMContentLoaded', () => {
  const send = document.querySelector(".send");
  send.addEventListener("click", () => renderUserMessage());
});

txtInput.addEventListener("keyup", (event) => {
  if (event.keyCode === 13) {
    renderUserMessage();
  }
});

const renderUserMessage = () => {
  const userInput = txtInput.value;
  renderMessageEle(userInput, "user");
  txtInput.value = "";
  setTimeout(() => {
    renderChatbotResponse(userInput);
    setScrollPosition();
  }, 600);
};


async function renderChatbotResponse(userInput){
  const res = await getChatbotResponse(userInput, handleMessage);
  console.log(res);
  renderMessageEle(res.response, "bot");
};

const renderMessageEle = (txt, type) => {
  let className = "user-message";
  if (type !== "user") {
    className = "chatbot-message";
  }
  const messageEle = document.createElement("div");
  const txtNode = document.createTextNode(txt);
  messageEle.classList.add(className);
  messageEle.append(txtNode);
  chatBody.append(messageEle);
};

function getChatbotResponse(userInput) {
  const url = 'http://localhost:5000/ask'; // replace with your own URL

  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    const usernameElement = document.getElementById('username');
    const userIdElement = document.getElementById('user_id');
    const username = usernameElement.dataset.username;
    const user_id = userIdElement.dataset.user_id;
    request.open('POST', url);
    request.setRequestHeader('Content-Type', 'application/json');
    request.send(JSON.stringify({ userInput, username, user_id }));

    request.onload = function() {
      if (request.status === 200) {
        const response = JSON.parse(request.responseText);
        console.log(response);
        resolve(response);
      } else {
        console.error('Error:', request.statusText);
        reject(request.statusText);
      }
    };
  });
}

async function handleMessage(userInput) {
  const response = await getChatbotResponse(userInput);
  console.log(response);
  // Do something with the response here
}


const setScrollPosition = () => {
  if (chatBody.scrollHeight > 0) {
    chatBody.scrollTop = chatBody.scrollHeight;
  }
};
