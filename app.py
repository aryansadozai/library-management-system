from flask import Flask, request, jsonify
import json


# Create the Flask application
app = Flask(__name__)


# Get the complete inventory from inventory.json
def get_data():
    with open("inventory.json", "r") as file:
        return json.load(file)


# Save the complete inventory back into inventory.json
def save_data(inventory):
    with open("inventory.json", "w") as file:
        json.dump(inventory, file, indent=4)


# Find one item using its product ID
def find_item(inventory, product_id):

    # Check every item in the inventory
    for item in inventory:

        # If the item's ID matches the requested ID
        if item["id"] == product_id:

            # Return that item
            return item

    # Return None if no item was found
    return None


# Get all products
@app.route("/products", methods=["GET"])
def get_products():

    # Get the complete inventory
    inventory = get_data()

    # Send all inventory items back to the user
    return jsonify({
        "success": True,
        "data": inventory
    }), 200


# Get one product using its ID
@app.route("/products/<int:product_id>", methods=["GET"])
def get_single_product(product_id):

    # Get the complete inventory
    inventory = get_data()

    # Find the item with the requested ID
    item = find_item(inventory, product_id)

    # If the item does not exist
    if item is None:
        return jsonify({
            "success": False,
            "message": "Product not found"
        }), 404

    # Send the found item back to the user
    return jsonify({
        "success": True,
        "data": item
    }), 200


# Add a new product
@app.route("/products", methods=["POST"])
def add_product():

    # Get the JSON data sent by the user
    data = request.get_json()

    # Check if JSON data was sent
    if not data:
        return jsonify({
            "success": False,
            "message": "JSON data is required"
        }), 400

    # Get the values from the JSON
    name = data.get("name")
    price = data.get("price")
    quantity = data.get("quantity")

    # Check if any required value is missing
    if name is None or price is None or quantity is None:
        return jsonify({
            "success": False,
            "message": "Name, price and quantity are required"
        }), 400

    # Check that the price is a number greater than 0
    if not isinstance(price, (int, float)) or isinstance(price, bool) or price <= 0:
        return jsonify({
            "success": False,
            "message": "Price must be greater than 0"
        }), 400

    # Check that quantity is an integer and is not negative
    if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity < 0:
        return jsonify({
            "success": False,
            "message": "Quantity cannot be negative"
        }), 400

    # Get the complete inventory
    inventory = get_data()

    # Check every existing item
    for item in inventory:

        # Check if an item with the same name already exists
        if item["name"].lower() == name.lower():
            return jsonify({
                "success": False,
                "message": "Product already exists"
            }), 400

    # If inventory already has items, create the next ID
    if inventory:
        new_id = max(item["id"] for item in inventory) + 1

    # If inventory is empty, start with ID 1
    else:
        new_id = 1

    # Create the new item
    new_item = {
        "id": new_id,
        "name": name,
        "price": price,
        "quantity": quantity
    }

    # Add the new item to the inventory
    inventory.append(new_item)

    # Save the updated inventory
    save_data(inventory)

    # Send a success response
    return jsonify({
        "success": True,
        "message": "Product added successfully",
        "data": new_item
    }), 201


# Purchase a product    
@app.route("/products/<int:product_id>/purchase", methods=["POST"])
def purchase_product(product_id):

    # Get the complete inventory
    inventory = get_data()

    # Find the item using its ID
    item = find_item(inventory, product_id)

    # Check if the item exists
    if item is None:
        return jsonify({
            "success": False,
            "message": "Product not found"
        }), 404

    # Get the JSON data sent by the user
    data = request.get_json()

    # Check if JSON data was sent
    if not data:
        return jsonify({
            "success": False,
            "message": "JSON data is required"
        }), 400

    # Get the quantity from the JSON
    quantity = data.get("quantity")

    # Check that quantity is a positive integer
    if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0:
        return jsonify({
            "success": False,
            "message": "Quantity must be a positive integer"
        }), 400

    # Check if enough quantity is available
    if quantity > item["quantity"]:
        return jsonify({
            "success": False,
            "message": "Insufficient stock",
            "available_quantity": item["quantity"]
        }), 400

    # Reduce the quantity after purchase
    item["quantity"] -= quantity

    # Save the updated inventory
    save_data(inventory)

    # Send a success response
    return jsonify({
        "success": True,
        "message": "Purchase successful",
        "remaining_quantity": item["quantity"]
    }), 200

#update the price of a product

@app.route("/products/<int:product_id>/price", methods=["PATCH"])
def update_price(product_id):

    # Get the complete inventory
    inventory = get_data()

    # Find the item using its ID
    item = find_item(inventory, product_id)

    # Check whether the ID exists
    if item is None:
        return jsonify({
            "success": False,
            "message": "Product not found"
        }), 404

    # Get the JSON data sent by the user
    data = request.get_json()

    # Check if JSON data was provided
    if not data:
        return jsonify({
            "success": False,
            "message": "JSON data is required"
        }), 400

    # Get the new price from the JSON
    price = data.get("price")

    # Check that price is a positive number
    if not isinstance(price, (int, float)) or isinstance(price, bool) or price <= 0:
        return jsonify({
            "success": False,
            "message": "Price must be greater than 0"
        }), 400

    # Change the old price to the new price
    item["price"] = price

    # Save the updated inventory
    save_data(inventory)

    # Send the updated item back
    return jsonify({
        "success": True,
        "message": "Price updated successfully",
        "data": item
    }), 200

# Restock a product
@app.route("/products/<int:product_id>/restock", methods=["POST"])
def restock_product(product_id):

    # Get the complete inventory
    inventory = get_data()

    # Check whether the ID exists
    item = find_item(inventory, product_id)

    # If the item was not found
    if item is None:
        return jsonify({
            "success": False,
            "message": "Product not found"
        }), 404

    # Get the JSON you typed in the request body
    data = request.get_json()

    # Check if JSON data was sent
    if not data:
        return jsonify({
            "success": False,
            "message": "JSON data is required"
        }), 400

    # Get the quantity from the JSON
    quantity = data.get("quantity")

    # Check that quantity is a positive integer
    if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0:
        return jsonify({
            "success": False,
            "message": "Quantity must be greater than 0"
        }), 400

    # Add the quantity you entered
    item["quantity"] += quantity

    # Save the updated inventory
    save_data(inventory)

    # Send the updated item back to the user
    return jsonify({
        "success": True,
        "message": "Product restocked successfully",
        "data": item
    }), 200


# Get all products with quantity 5 or less
@app.route("/products/low-stock", methods=["GET"])
def low_stock():

    # Get the complete inventory
    inventory = get_data()

    # Create an empty list for low-stock items
    low_stock_items = []

    # Check every item in the inventory
    for item in inventory:

        # If quantity is 5 or less
        if item["quantity"] <= 5:

            # Add that item to the low-stock list
            low_stock_items.append(item)

    # Send all low-stock items back to the user
    return jsonify({
        "success": True,
        "count": len(low_stock_items),
        "data": low_stock_items
    }), 200


# Checkout a product and apply a discount
@app.route("/products/<int:product_id>/checkout", methods=["POST"])
def checkout(product_id):

    # Get the complete inventory
    inventory = get_data()

    # Find the item using its ID
    item = find_item(inventory, product_id)

    # Check if the item exists
    if item is None:
        return jsonify({
            "success": False,
            "message": "Product not found"
        }), 404

    # Get the JSON data sent by the user
    data = request.get_json()

    # Check if JSON data was sent
    if not data:
        return jsonify({
            "success": False,
            "message": "JSON data is required"
        }), 400

    # Get the quantity from the JSON
    quantity = data.get("quantity")

    # Check that quantity is a positive integer
    if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0:
        return jsonify({
            "success": False,
            "message": "Quantity must be a positive integer"
        }), 400

    # Check if enough stock is available
    if quantity > item["quantity"]:
        return jsonify({
            "success": False,
            "message": "Insufficient stock",
            "available_quantity": item["quantity"]
        }), 400

    # Calculate the total before discount
    subtotal = item["price"] * quantity

    # Decide the discount percentage
    if subtotal >= 50000:
        discount_percentage = 15

    elif subtotal >= 20000:
        discount_percentage = 10

    elif subtotal >= 5000:
        discount_percentage = 5

    else:
        discount_percentage = 0

    # Calculate the discount amount
    discount_amount = subtotal * discount_percentage / 100

    # Calculate the final price after discount
    final_total = subtotal - discount_amount

    # Reduce the quantity after checkout
    item["quantity"] -= quantity

    # Save the updated inventory
    save_data(inventory)

    # Send the checkout details back to the user
    return jsonify({
        "success": True,
        "product": item["name"],
        "quantity": quantity,
        "discount_percentage": discount_percentage,
        "subtotal": subtotal,
        "final_total": final_total,
        "discount_amount": discount_amount,
        
    }), 200


# Start the Flask server
if __name__ == "__main__":
    app.run(debug=True)
