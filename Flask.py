from flask import Flask, render_template, redirect, url_for, request, jsonify
import vol2

app = Flask(__name__)

@app.route("/ManualDashboard", methods=["POST", "GET"])
def manual():
    if request.method == "POST":
        command = request.form["command"]
        return render_template("ManualDashboard.html", command_input=f"command: {command}")
    else:
        return render_template("ManualDashboard.html")


@app.route("/AutoDashboard", methods=["POST", "GET"])
def auto():
    if request.method == "POST":
        command = request.form["command"]
        return render_template("AutoDashboard.html", command_input=f"command: {command}")
    else:
        return render_template("AutoDashboard.html")


@app.route('/process-form', methods=['POST'])
def process_form():
    # command = request.form["command"]
    # filePath = request.form["file-path"]
    # pid = request.form["pid-fieldvalue"]
    # offset = request.form["offset-fieldvalue"]
    # key = request.form["key-fieldvalue"]
    # physical = request.form.get("physical-check")
    # includeCorrupt = request.form.get("include-corruptCheck")
    # recurse = request.form.get("recurseCheck")
    # dump = request.form.get("dumpCheck")

    # if physical is None:
    #     physical = False

    # if includeCorrupt is None:
    #     includeCorrupt = False

    # if recurse is None:
    #     recurse = False

    # if dump is None:
    #     dump = False
    form_data = request.form
    command = ""
    filePath = ""
    pid = ""
    offset = ""
    keyRegis = ""
    physical = ""
    includeCorrupt = ""
    recurse = ""
    dump = ""
    
    data_dict = {}
    data_dict.clear()
    for key, value in form_data.items():
        if key == "command":
            command = value
        elif key == "file-path":
            filePath = value
        elif key == "pid-fieldvalue":
            pid = value
        elif key == "offset-fieldvalue":
            offset = value
        elif key == "key-fieldvalue":
            keyRegis = value
        elif key == "physical-check":
            physical = value
        elif key == "include-corruptCheck":
            includeCorrupt = value
        elif key == "recurseCheck":
            recurse = value
        elif key == "dumpCheck":
            dump = value

    data_dict = vol2.run(command,"./wanncry.vmem","./outputtest",[])
    print(data_dict)
    # print(data_dict)
    return jsonify(data_dict)

    # return jsonify({"command": command, "File Path": filePath, "PID": pid, "Offset": offset, "Key": key, "Include Corrupt": includeCorrupt, "Recurse": recurse, "Dump": dump,  "physic": physical})


@app.route("/<cmd>")
def commandtest(cmd):
    return f"<h1>{cmd}</h1>"


if __name__ == "__main__":
    app.run(debug=True)
