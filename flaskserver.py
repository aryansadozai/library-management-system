from flask import Flask, request
import json
app = Flask(__name__)

@app.route("/")
def home():
    return "Chat server is working!"
@app.route("/history")
def history():
    with open("chat.json","r")as file:
        chats=json.load(file)

    return chats

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json

    with open("chat.json", "r") as file:
        chats = json.load(file)

    chats.append(data)

    with open("chat.json", "w") as file:
        json.dump(chats, file, indent=4)

    return {
        "message": "Chat saved successfully!"
    }

app.run(debug=True)
