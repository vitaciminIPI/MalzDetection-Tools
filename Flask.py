from flask import Flask, render_template, request, jsonify, render_template, send_from_directory, send_file, session, make_response
import os
import urllib.parse
from datetime import datetime
import vol2
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'


@app.route("/ManualDashboard", methods=["POST", "GET"])
def manual():
    file_path = os.path.abspath(__file__).replace('\\', '/')
    if request.method == "POST":
        file = request.files['file']
        file_name = os.path.abspath(file.filename)
        upload_directory = os.path.join(app.root_path)
        file_path = os.path.join(upload_directory, file_name)
        file.save(file_path)
        session["filePath"] = file_path
        return make_response('', 204)
    else:
        return render_template("ManualDashboard.html", file_path=file_path)


@app.route('/')
@app.route('/index')
@app.route('/index.html')
def index():
    return render_template('index.html')


@app.route("/AutoDashboard", methods=["POST", "GET"])
def auto():
    if request.method == "POST":
        command = request.form["command"]
        return render_template("AutoDashboard.html", command_input=f"command: {command}")
    else:
        return render_template("AutoDashboard.html")


@app.route('/generate_report', methods=['POST'])
def generate_report():
    with open('templates/generateReport.html', 'r') as template_file:
        template_content = template_file.read()

    # Isi template dengan konten yang diinginkan
    # Misalnya, Anda dapat menggunakan Jinja untuk mengganti placeholder dengan nilai yang diinginkan
    # Di sini, kita hanya akan mengganti placeholder {{ content }} dengan string "Ini adalah konten yang diinginkan"
    html_content = template_content.replace('{{ name }}', 'wanncry.vmem')
    html_content = html_content.replace('{{ size }}', '7 GB')
    html_content = html_content.replace('{{ hash }}', '1h43556789')
    html_content = html_content.replace('{{ optsys }}', 'Windows')
    html_content = html_content.replace('{{ lname }}', 'Windows Intel')
    html_content = html_content.replace('{{ lmemory }}', '1 File Layer')
    html_content = html_content.replace('{{ proc }}', 'x64')
    html_content = html_content.replace(
        '{{ systime }}', '2023-06-16  02:25:51')
    html_content = html_content.replace('{{ sysroot }}', 'c:\windows')

    # Tentukan direktori tujuan untuk menyimpan file HTML yang diunduh
    destination_directory = os.path.join(os.getcwd(), 'static', 'reports')
    if not os.path.exists(destination_directory):
        os.makedirs(destination_directory)

    # Simpan file HTML di direktori tujuan
    tanggal_waktu_sekarang = datetime.now()
    deretan_angka = tanggal_waktu_sekarang.strftime('%Y%m%d%H%M%S')
    report_filename = 'report ' + deretan_angka + '.html'
    report_path = os.path.join(destination_directory, report_filename)
    with open(report_path, 'w') as report_file:
        report_file.write(html_content)

    # Kembalikan file HTML yang diunduh
    return send_file(report_path, as_attachment=False)


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
    filePath = session.get('filePath')
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
        # elif key == "file-path":
        #     filePath = "./"+value
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

    data_dict = vol2.run(command, filePath, "./outputtest", [])
    # data_dict = vol2.run("windows.psscan.PsScan","./wanncry.vmem","./outputtest",[])
    print("File: "+filePath)
    # print(data_dict)
    return jsonify(data_dict)

    # "File: "+ return jsonify({"command": command, "File Path": filePath, "PID": pid, "Offset": offset, "Key": key, "Include Corrupt": includeCorrupt, "Recurse": recurse, "Dump": dump,  "physic": physical})


@app.route("/<cmd>")
def commandtest(cmd):
    return f"<h1>{cmd}</h1>"


if __name__ == "__main__":
    app.run(debug=True)
