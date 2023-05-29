from flask import Flask, render_template, request, jsonify, render_template, session, make_response, Markup, send_from_directory
import os
from datetime import datetime
import vol2, malzclass, re
from bs4 import BeautifulSoup

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
        return render_template("AutoDashboard.html", file_path=file_path)


@app.route('/generate_report', methods=['POST'])
def generate_report():
    manDict = request.json
    

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

    # Pslist =============================================================================================
    pslist_data = manDict.get('windows.pslist.PsList',{})
    if 'windows.pslist.PsList' in manDict and bool(pslist_data):
        header1_values = None
        for value in pslist_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(pslist_data)
        pslist_content = ''
        for value in pslist_data.values():
            counter = 0
            pslist_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 11:
                    break
                pslist_row += f'<td>{value[indexval]}</td>'
                counter+=1
            pslist_row += '</tr>'
            pslist_content += pslist_row
        html_content = html_content.replace('{PSLIST_CONTENT}', pslist_content)
    elif bool(pslist_data) == False:
        html_content = html_content.replace('{PSLIST_CONTENT}', 'kosong')
    
    # Pstree =============================================================================================
    pstree_data = manDict.get('windows.pstree.PsTree',{})
    if 'windows.pstree.PsTree' in manDict and bool(pstree_data):
        header1_values = None
        for value in pstree_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(pstree_data)
        pstree_content = ''
        for value in pstree_data.values():
            counter = 0
            pstree_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 10:
                    break
                pstree_row += f'<td>{value[indexval]}</td>'
                counter+=1
            pstree_row += '</tr>'
            pstree_content += pstree_row
        html_content = html_content.replace('{PSTREE_CONTENT}', pstree_content)
    elif bool(pstree_data) == False:
        html_content = html_content.replace('{PSTREE_CONTENT}', 'kosong')
    
    # Psscan =============================================================================================
    psscan_data = manDict.get('windows.psscan.PsScan',{})
    if 'windows.psscan.PsScan' in manDict and bool(psscan_data):
        header1_values = None
        for value in psscan_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(psscan_data)
        psscan_content = ''
        for value in psscan_data.values():
            counter = 0
            psscan_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 11:
                    break
                psscan_row += f'<td>{value[indexval]}</td>'
                counter+=1
            psscan_row += '</tr>'
            psscan_content += psscan_row
        html_content = html_content.replace('{PSSCAN_CONTENT}', psscan_content)
    elif bool(psscan_data) == False:
        html_content = html_content.replace('{PSSCAN_CONTENT}', 'kosong')

    # Netscan =============================================================================================
    netscan_data = manDict.get('windows.netscan.NetScan',{})
    if 'windows.netscan.NetScan' in manDict and bool(netscan_data):
        header1_values = None
        for value in netscan_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(netscan_data)
        netscan_content = ''
        for value in netscan_data.values():
            counter = 0
            netscan_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 10:
                    break
                netscan_row += f'<td>{value[indexval]}</td>'
                counter+=1
            netscan_row += '</tr>'
            netscan_content += netscan_row
        html_content = html_content.replace('{NETSCAN_CONTENT}', netscan_content)
    elif bool(netscan_data) == False:
        html_content = html_content.replace('{NETSCAN_CONTENT}', 'kosong')
    
    # Dlllist =============================================================================================
    dlllist_data = manDict.get('windows.dlllist.DllList',{})
    if 'windows.dlllist.DllList' in manDict and bool(dlllist_data):
        header1_values = None
        for value in dlllist_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(dlllist_data)
        dlllist_content = ''
        for value in dlllist_data.values():
            counter = 0
            dlllist_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 8:
                    break
                dlllist_row += f'<td>{value[indexval]}</td>'
                counter+=1
            dlllist_row += '</tr>'
            dlllist_content += dlllist_row
        html_content = html_content.replace('{DLLLIST_CONTENT}', dlllist_content)
    elif bool(dlllist_data) == False:
        html_content = html_content.replace('{DLLLIST_CONTENT}', 'kosong')
    
    # Printkey =============================================================================================
    printkey_data = manDict.get('windows.registry.printkey.PrintKey',{})
    if 'windows.registry.printkey.PrintKey' in manDict and bool(printkey_data):
        header1_values = None
        for value in printkey_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(printkey_data)
        printkey_content = ''
        for value in printkey_data.values():
            counter = 0
            printkey_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 7:
                    break
                printkey_row += f'<td>{value[indexval]}</td>'
                counter+=1
            printkey_row += '</tr>'
            printkey_content += printkey_row
        html_content = html_content.replace('{PRINTKEY_CONTENT}', printkey_content)
    elif bool(printkey_data) == False:
        html_content = html_content.replace('{PRINTKEY_CONTENT}', 'kosong')

    # Malfind =============================================================================================
    malfind_data = manDict.get('windows.malfind.Malfind',{})
    if 'windows.malfind.Malfind' in manDict and bool(malfind_data):
        header1_values = None
        for value in malfind_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(malfind_data)
        malfind_content = ''
        for value in malfind_data.values():
            counter = 0
            malfind_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 11:
                    break
                malfind_row += f'<td>{value[indexval]}</td>'
                counter+=1
            malfind_row += '</tr>'
            malfind_content += malfind_row
        html_content = html_content.replace('{MALFIND_CONTENT}', malfind_content)
    elif bool(malfind_data) == False:
        html_content = html_content.replace('{MALFIND_CONTENT}', 'kosong')

    # Cmdline =============================================================================================
    cmdline_data = manDict.get('windows.cmdline.CmdLine',{})
    if 'windows.cmdline.CmdLine' in manDict and bool(cmdline_data):
        header1_values = None
        for value in cmdline_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(cmdline_data)
        cmdline_content = ''
        for value in cmdline_data.values():
            counter = 0
            cmdline_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 3:
                    break
                cmdline_row += f'<td>{value[indexval]}</td>'
                counter+=1
            cmdline_row += '</tr>'
            cmdline_content += cmdline_row
        html_content = html_content.replace('{CMDLINE_CONTENT}', cmdline_content)
    elif bool(cmdline_data) == False:
        html_content = html_content.replace('{CMDLINE_CONTENT}', 'kosong')
    # Tentukan direktori tujuan untuk menyimpan file HTML yang diunduh
    destination_directory = os.path.join(os.getcwd(), 'static', 'reports')
    if not os.path.exists(destination_directory):
        os.makedirs(destination_directory)

    # Simpan file HTML di direktori tujuan
    tanggal_waktu_sekarang = datetime.now()
    deretan_angka = tanggal_waktu_sekarang.strftime('%Y%m%d%H%M%S')
    report_filename = 'report ' + deretan_angka + '.html'
    session["fileName"] = report_filename
    report_path = os.path.join(destination_directory, report_filename)
    with open(report_path, 'w') as report_file:
        report_file.write(html_content)

    # Kembalikan file HTML yang diunduh
    response = make_response(html_content)
    response.headers['Content-Disposition'] = 'attachment; filename=data.html'
    response.headers['Content-type'] = 'text/html'

    return response


@app.route('/processAuto', methods=['POST'])
def process_formAuto():
    autoDict = {}
    autoDict.clear()
    malware = request.form.get('malware')
    filePath = session.get('filePath')
    if malware == "wannacry":
        t = malzclass.WannaCry(filepath=filePath, outputpath="./outputtest")
        autoDict = t.run()
    elif malware == "emotet":
        pass
    elif malware == "stuxnet":
        pass
    print(autoDict)
    html_content = generate_html(autoDict)
    tanggal_waktu_sekarang = datetime.now()
    deretan_angka = tanggal_waktu_sekarang.strftime('%Y-%m-%d_%H%M%S')
    # Menyimpan file HTML di folder /static/reports
    filename = "data_" + deretan_angka + ".html"
    session["fileName"] = filename
    save_path = os.path.join(app.static_folder, 'reports')
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    file_path = os.path.join(save_path, filename)

    with open(file_path, 'w') as file:
        file.write(html_content)

    # Mengirimkan file HTML yang akan diunduh
    response = make_response(html_content)
    response.headers['Content-Disposition'] = 'attachment; filename=data.html'
    response.headers['Content-type'] = 'text/html'

    return response

@app.route('/open_report', methods=['GET'])
def open_report():
    filename = session.get('fileName')  # Ganti dengan nama file HTML yang ingin dibuka
    return send_from_directory('static/reports', filename)

def generate_html(data):
    html = "<html><body>"
    html += "<h1>Data Dictionary</h1>"
    html += "<table>"
    for key, value in data.items():
        html += "<tr><td>{}</td><td>{}</td></tr>".format(key, value)
    html += "</table>"
    html += "</body></html>"

    return Markup(html)

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

    print(command)
    data_dict = vol2.run(command,filePath,"./outputtest",[])
    # data_dict = vol2.run("windows.psscan.PsScan","./wanncry.vmem","./outputtest",[])
    # print("File: "+filePath)
    print(data_dict)
    return jsonify(data_dict)

    # "File: "+ return jsonify({"command": command, "File Path": filePath, "PID": pid, "Offset": offset, "Key": key, "Include Corrupt": includeCorrupt, "Recurse": recurse, "Dump": dump,  "physic": physical})


@app.route("/<cmd>")
def commandtest(cmd):
    return f"<h1>{cmd}</h1>"


if __name__ == "__main__":
    app.run(debug=True)
