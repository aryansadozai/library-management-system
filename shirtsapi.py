from flask import Flask, request, jsonify
import json

app = Flask(__name__)


#save the data
def save_data(shirts):
    with open("shirts.json", "w") as file:
        json.dump(shirts, file, indent=4)


#getting the data
def get_data():
    with open("shirts.json", "r") as file:
        return json.load(file)


#checking if no json data was sent
def no_jsondata(data):
    if not data:
        return jsonify({
            "success": False,
            "error": "json data is required"
        }), 400


#checking if value is missing
def miss_value(name, material_type, size, color):
    if name is None or material_type is None or size is None or color is None:
        return jsonify({
            "success": False,
            "error": "name, material_type, size and color cannot be empty"
        }), 400


#checking if data is string
def val_shirt(name, material_type, size, color):
    if (
        not isinstance(name, str)
        or not isinstance(material_type, str)
        or not isinstance(size, str)
        or not isinstance(color, str)
    ):
        return jsonify({
            "success": False,
            "error": "all the data entries must be of string datatype"
        }), 400


#checking if shirt already exists
def shirt_exists(name, material_type, size, color):
    shirts = get_data()

    for item in shirts:
        if (
            item["name"].lower() == name.lower()
            and item["material_type"].lower() == material_type.lower()
            and item["size"].lower() == size.lower()
            and item["color"].lower() == color.lower()
        ):
            return jsonify({
                "success": False,
                "error": "shirt already exists"
            }), 400


#getting all shirts
@app.route("/shirts", methods=["GET"])
def all_shirts():
    shirts = get_data()

    return jsonify({
        "success": True,
        "data": shirts
    }), 200


#adding shirt
@app.route("/shirts/add", methods=["POST"])
def add():
    data = request.get_json()

    result = no_jsondata(data)

    if result:
        return result

    name = data.get("name")
    material_type = data.get("material_type")
    size = data.get("size")
    color = data.get("color")

    result = miss_value(name, material_type, size, color)

    if result:
        return result

    result = val_shirt(name, material_type, size, color)

    if result:
        return result

    result = shirt_exists(name, material_type, size, color)

    if result:
        return result

    shirts = get_data()

    new_shirt = {
        "name": name,
        "material_type": material_type,
        "size": size,
        "color": color
    }

    shirts.append(new_shirt)

    save_data(shirts)

    return jsonify({
        "success": True,
        "message": "shirt added successfully",
        "data": new_shirt
    }), 201


#filtering shirts
@app.route("/shirts/filter", methods=["POST"])
def filter_shirts():
    shirts = get_data()

    data = request.get_json()

    #checking if no json data was sent
    if not data:
        return jsonify({
            "success": False,
            "error": "json data is required"
        }), 400

    name = data.get("name")
    color = data.get("color")
    size = data.get("size")
    material_type = data.get("material_type")

    results = shirts

    #filtering by name
    if name:
        if not isinstance(name, str):
            return jsonify({
                "success": False,
                "error": "name must be a string"
            }), 400

        results = [
            item for item in results
            if item["name"].lower() == name.lower()
        ]

    #filtering by color
    if color:
        if not isinstance(color, str):
            return jsonify({
                "success": False,
                "error": "color must be a string"
            }), 400

        results = [
            item for item in results
            if item["color"].lower() == color.lower()
        ]

    #filtering by size
    if size:
        if not isinstance(size, str):
            return jsonify({
                "success": False,
                "error": "size must be a string"
            }), 400

        results = [
            item for item in results
            if item["size"].lower() == size.lower()
        ]

    #filtering by material_type
    if material_type:
        if not isinstance(material_type, str):
            return jsonify({
                "success": False,
                "error": "material_type must be a string"
            }), 400

        results = [
            item for item in results
            if item["material_type"].lower() == material_type.lower()
        ]

    #returning filtered data
    return jsonify({
        "success": True,
        "data": results
    }), 200


#running the server
if __name__ == "__main__":
    app.run(debug=True)