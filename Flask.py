from flask import Flask, render_template, redirect, url_for, request, jsonify

app = Flask(__name__)

@app.route("/ManualDashboard", methods=["POST","GET"])
def manual():
    if request.method == "POST":
        command = request.form["command"]
        return render_template("ManualDashboard.html", command_input=f"command: {command}")
    else:
        return render_template("ManualDashboard.html")
    
@app.route("/AutoDashboard", methods=["POST","GET"])
def auto():
    if request.method == "POST":
        command = request.form["command"]
        return render_template("AutoDashboard.html", command_input=f"command: {command}")
    else:
        return render_template("AutoDashboard.html")

@app.route('/process-form', methods=['POST'])
def process_form():
    command = request.form["command"]
    physical = request.form.get("physical-check")
    return jsonify({"message": command, "physic": physical})

@app.route("/<cmd>")
def commandtest(cmd):
    return f"<h1>{cmd}</h1>"

if __name__ == "__main__":
    app.run(debug=True)