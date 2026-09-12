from flask import Flask, request, jsonify
import json

app = Flask(__name__)


def load_tasks():
    with open("tasksflask.json", "r") as file:
        return json.load(file)


def save_tasks(tasks):
    with open("tasksflask.json", "w") as file:
        json.dump(tasks, file, indent=4)


@app.route("/tasks", methods=["POST"])
def add_task():
    task = request.get_json()

    if not task:
        return jsonify({"error": "JSON data is required"}), 400

    if "name" not in task:
        return jsonify({"error": "Task name is required"}), 400

    if not isinstance(task["name"], str) or not task["name"].strip():
        return jsonify({"error": "Task name cannot be empty"}), 400

    if "status" not in task:
        return jsonify({"error": "Status is required"}), 400

    if task["status"] not in ["pending", "completed"]:
        return jsonify({
            "error": "Status must be pending or completed"
        }), 400

    tasks = load_tasks()

    if len(tasks) == 0:
        new_id = 1
    else:
        new_id = max(task["id"] for task in tasks) + 1

    task["id"] = new_id

    tasks.append(task)

    save_tasks(tasks)

    return jsonify(task), 201


@app.route("/tasks/all", methods=["GET"])
def all_tasks():
    tasks = load_tasks()

    return jsonify(tasks)


@app.route("/tasks/todo", methods=["GET"])
def task_todo():
    tasks = load_tasks()

    todo_tasks = []

    for task in tasks:
        if task["status"] == "pending":
            todo_tasks.append(task)

    return jsonify(todo_tasks)


@app.route("/tasks/done", methods=["GET"])
def tasks_done():
    tasks = load_tasks()

    done_tasks = []

    for task in tasks:
        if task["status"] == "completed":
            done_tasks.append(task)

    return jsonify(done_tasks)


@app.route("/tasks/<int:task_id>", methods=["PUT"])
def update_task(task_id):
    task_data = request.get_json()

    if not task_data:
        return jsonify({"error": "JSON data is required"}), 400

    if "status" not in task_data:
        return jsonify({"error": "Status is required"}), 400

    if task_data["status"] not in ["pending", "completed"]:
        return jsonify({
            "error": "Status must be pending or completed"
        }), 400

    tasks = load_tasks()

    for task in tasks:
        if task["id"] == task_id:
            task["status"] = task_data["status"]

            save_tasks(tasks)

            return jsonify(task)

    return jsonify({"error": "Task not found"}), 404


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    tasks = load_tasks()

    for task in tasks:
        if task["id"] == task_id:
            tasks.remove(task)

            save_tasks(tasks)

            return jsonify({
                "message": "Task deleted successfully"
            })

    return jsonify({"error": "Task not found"}), 404


app.run(debug=True)