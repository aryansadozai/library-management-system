from flask import Flask,jsonify,request
import json

app = Flask(__name__)

#saving the data as json
def save_data(shirts):
    with open("storage.json","w")as file:
       json.dump(shirts,file,indent=4)

#loading data from json
def load_data():
    with open("storage.json","r")as file:
        return json.load(file)


#checking if no data was sent
def no_data(data):
    if not data:
        return jsonify({
            "success":False,
            "error":"json data is required"
        }),400

#checking if the value is missing
def no_val(name,color,material_type,size):
    if name is None or color is None or material_type is None or size is None:
        return jsonify({
            "success":False,
            "error":"all entries must be filled"
        }), 400


#checking if data is in correct format
def correct_data(name,color,material_type,size):
    if not isinstance(name,str) or not isinstance(color,str) or not isinstance(material_type,str) or not isinstance(size,str):
        return jsonify({
            "success":False,
            "error":"all entries must be in string datatype"
        }), 400


#checking if the size entered is correct
def correct_name(item):
    if not item["size"].lower()=="m" and not item["size"].lower()=="s" and not item["size"].lower()=="l" and not item["size"].lower()=="xl":
        return jsonify({
            "success":False,
            "error":"size must be valid"
        }), 400


#checking if shirt already exists
def shirt_exists(name,color,material_type,size):
    shirts=load_data()
    for item in shirts:
        if item["name"].lower() == name.lower() and item["material_type"].lower() == material_type.lower() and item["size"].lower() == size.lower() and item["color"].lower() == color.lower():
            return jsonify({
            "success":False,
            "error":"shirt already exists"
        }), 400


#actual program start
@app.route("/store",methods=["GET"])
def get_allshirts():
    shirts=load_data()
    return jsonify({
        "success":True,
        "data":shirts
    }),200


@app.route("/store/add",methods=["POST"])
def add():
    data=request.get_json()

    result=no_data(data)
    if result:
        return result

    name=data.get("name")
    color=data.get("color")
    material_type=data.get("material_type")
    size=data.get("size")

    result=no_val(name,color,material_type,size)
    if result:
        return result

    result=correct_data(name,color,material_type,size)
    if result:
        return result

    result=correct_name(data)
    if result:
        return result

    result=shirt_exists(name,color,material_type,size)
    if result:
        return result

    shirts=load_data()
    shirts.append(data)
    save_data(shirts)

    return jsonify({
        "success":True,
        "data":data
    }),201


#filtering shirts by get method
@app.route("/store/filter",methods=["GET"])
def filter():
    shirts=load_data()
    name = request.args.get("name")
    size= request.args.get("size")
    material_type=request.args.get("material_type")
    color=request.args.get("color")

    filtered_shirts=[]
    for item in shirts:
        if name and item["name"].lower() != name.lower():
            continue

        if color and item["color"].lower() != color.lower():
            continue

        if material_type and item["material_type"].lower() != material_type.lower():
            continue

        if size and item["size"].lower() != size.lower():
            continue

        filtered_shirts.append(item)

    return jsonify({
        "success": True,
        "data": filtered_shirts
    }), 200


if __name__=="__main__":
    app.run(debug=True)