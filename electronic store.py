from flask import Flask , jsonify, Request
import json

app= Flask(__name__)

def save_data(data):
    with open("client.json","w") as file:
        json.dump(data,file,indent=4)


def load_data():
    with open("client.json","r") as file:
       return json.load(file)


def find_item(client, product_id):
    for item in client:
        if item["id"] == product_id:
            return item

def no_data(data):
    if not data:
        return jsonify({
            "success":False,
            "error":"json data is required"
        }),400

app.route("/products",method=["GET"])
def all_products():
    products= load_data()
    return jsonify({
        "success":True,
        "products":products
    }), 200

app.route("/products/<int:product_id>",methods=["GET"])
def products_byid():
    products=load_data()
    item=find_item()
    if item is None:
        return jsonify({
             "success": False,
             "message": "Product not found"
         }), 404

    return jsonify({
         "success": True,
         "data": item
     }), 200
    
    
