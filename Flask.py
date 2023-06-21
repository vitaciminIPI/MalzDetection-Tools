from flask import Flask, render_template, request, jsonify, render_template, session, make_response, Markup, send_from_directory, abort
import os, secrets
from datetime import datetime
import vol2, malzclass, vol3
from bs4 import BeautifulSoup
from werkzeug.datastructures import Headers

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.errorhandler(500)
def handle_internal_server_error(e):
    return render_template('error.html', error_code=500), 500

@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' *; style-src 'self' 'unsafe-inline' *; font-src 'self' *; img-src 'self' *; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';"
    return response

@app.before_request
def block_question_mark_urls():
    if '?' in request.url:
        abort(403)

@app.route('/.htaccess')
@app.route('/._darcs')
@app.route('/.bzr')
@app.route('/.hg')
@app.route('/BitKeeper')
def block_access():
    abort(403)

@app.route("/ManualDashboard", methods=["POST", "GET"])
def manual():
    file_path = os.path.abspath(__file__).replace('\\', '/')
    if request.method == "POST":
        csrf_token = request.form.get('csrf_token')
        if csrf_token != session['csrf_token']:
            abort(403)
        file = request.files['file']
        file_name = os.path.abspath(file.filename)
        upload_directory = os.path.join(app.root_path)
        file_path = os.path.join(upload_directory, file_name)
        file.save(file_path)
        session["filePath"] = file_path
        return make_response('', 204)
    else:
        csrf_token = secrets.token_hex(32)
        session["csrf_token"] = csrf_token
        return render_template("ManualDashboard.html", file_path=file_path, csrf_token=csrf_token)


@app.route('/')
@app.route('/index')
@app.route('/index.html')
def index():
    return render_template('index.html')


@app.route("/AutoDashboard", methods=["POST", "GET"])
def auto():
    file_path = os.path.abspath(__file__).replace('\\', '/')
    if request.method == "POST":
        csrf_token = request.form.get('csrf_token')
        if csrf_token != session['csrf_token']:
            abort(403)
        file = request.files['file']
        file_name = os.path.abspath(file.filename)
        session["fileNameOri"] = file_name
        upload_directory = os.path.join(app.root_path)
        file_path = os.path.join(upload_directory, file_name)
        file.save(file_path)
        session["filePath"] = file_path
        return make_response('', 204)
    else:
        csrf_token = secrets.token_hex(32)
        session["csrf_token"] = csrf_token
        return render_template("AutoDashboard.html", file_path=file_path, csrf_token=csrf_token)


@app.route('/generate_report', methods=['POST'])
def generate_report():
    csrf_token = request.form.get('csrf_token')
    if csrf_token != session['csrf_token']:
        abort(403)
    manDict = request.json
    # print(manDict)

    with open('templates/generateReport.html', 'r') as template_file:
        template_content = template_file.read()
    # print(manDict['windows.info.Info']['layer_name'])
    # Isi template dengan konten yang diinginkan
    # Misalnya, Anda dapat menggunakan Jinja untuk mengganti placeholder dengan nilai yang diinginkan
    # Di sini, kita hanya akan mengganti placeholder {{ content }} dengan string "Ini adalah konten yang diinginkan"

    # Info =============================================================================================
    info_data = manDict.get('windows.info.Info',{})
    if 'windows.info.Info' in manDict and bool(info_data):
        html_content = template_content.replace('{{ info }}', 'Memory File Information: ')
        html_content = html_content.replace('{{ lname }}', manDict['windows.info.Info']['layer_name'][0])
        html_content = html_content.replace('{{ lmemory }}', manDict['windows.info.Info']['memory_layer'][0])
        html_content = html_content.replace(
            '{{ systime }}', manDict['windows.info.Info']['SystemTime'][0])
        html_content = html_content.replace('{{ sysroot }}', manDict['windows.info.Info']['NtSystemRoot'][0])
    elif bool(info_data) == False:
        html_content = template_content.replace('{{ info }}', 'kosong')

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

    # Netstat =============================================================================================
    netstat_data = manDict.get('windows.netstat.NetStat',{})
    if 'windows.netstat.NetStat' in manDict and bool(netstat_data):
        header1_values = None
        for value in netstat_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(netstat_data)
        netstat_content = ''
        for value in netstat_data.values():
            counter = 0
            netstat_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 10:
                    break
                netstat_row += f'<td>{value[indexval]}</td>'
                counter+=1
            netstat_row += '</tr>'
            netstat_content += netstat_row
        html_content = html_content.replace('{NETSTAT_CONTENT}', netstat_content)
    elif bool(netstat_data) == False:
        html_content = html_content.replace('{NETSTAT_CONTENT}', 'kosong')

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
    
    # Handles =============================================================================================
    handles_data = manDict.get('windows.handles.Handles',{})
    if 'windows.handles.Handles' in manDict and bool(handles_data):
        header1_values = None
        for value in handles_data.values():
            if isinstance(value, list):
                header1_values = value
                break
        num_header1_values = len(header1_values)
        num_keys_key1 = len(handles_data)
        handles_content = ''
        for value in handles_data.values():
            counter = 0
            handles_row = '<tr>'
            for indexval in range(num_header1_values):
                if counter == 7:
                    break
                handles_row += f'<td>{value[indexval]}</td>'
                counter+=1
            handles_row += '</tr>'
            handles_content += handles_row
        html_content = html_content.replace('{HANDLES_CONTENT}', handles_content)
    elif bool(handles_data) == False:
        html_content = html_content.replace('{HANDLES_CONTENT}', 'kosong')

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

data = {
           'iocs': {
                'ldrmod': ['\\Users\\labib\\Desktop\\@WanaDecryptor@.exe', '\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', '\\Users\\labib\\Desktop\\WannaCry.EXE', '\\Program Files\\Windows Sidebar\\en-US\\sbdrop.dll.mui', '\\Windows\\System32\\en-US\\searchfolder.dll.mui', '\\Users\\labib\\Desktop\\@WanaDecryptor@.exe', '\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', '\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '\\Users\\labib\\Desktop\\TaskData\\Tor\\taskhsvc.exe', '\\Users\\labib\\Desktop\\TaskData\\Tor\\zlib1.dll', '\\Windows\\SysWOW64\\en-US\\KernelBase.dll.mui', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libssp-0.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libeay32.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\ssleay32.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libgcc_s_sjlj-1.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libevent-2-0-5.dll'], 
                
                'wanna_file': ['\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\46.WNCRYTows\\Caches\\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000002.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\hibsys.WNCRYT', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db'], 
                
                'filescan': ['\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\46.WNCRYTows\\Caches\\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000002.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\Desktop\\00000000.eky', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\hibsys.WNCRYT', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Roaming\\tor\\lock', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db'], 
                
                'mutex': ['MsWinZonesCacheCounterMutexA', 'MsWinZonesCacheCounterMutexA0'], 
                
                'wanna_path': ['\\Device\\HarddiskVolume1\\Users\\labib\\AppData\\Roaming\\tor\\lock'], 
                
                'handles': ['MsWinZonesCacheCounterMutexA', 'MsWinZonesCacheCounterMutexA0', '\\Device\\HarddiskVolume1\\Users\\labib\\Desktop\\00000000.eky', '\\Device\\HarddiskVolume1\\Users\\labib\\AppData\\Local\\Temp\\hibsys.WNCRYT', '\\Device\\HarddiskVolume1\\Users\\labib\\AppData\\Roaming\\tor\\lock']
                },

            'ldrmod': {
                'Pid': [2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 2464, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1340, 1588, 1588, 1588, 1588, 1588, 1588, 1588, 1588, 1588, 2664, 2664, 2664, 2664, 2664, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2752, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092, 2092],

                'Process': ['@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'WannaCry.EXE', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'explorer.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'vmtoolsd.exe', 'taskmgr.exe', 'taskmgr.exe', 'taskmgr.exe', 'taskmgr.exe', 'taskmgr.exe', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe', 'taskhsvc.exe'],

                'Base': ['0x74ee0000', '0x400000', '0x320000', '0x290000', '0x735e0000', '0x73380000', '0x733c0000', '0x73440000', '0x73fa0000', '0x73ea0000', '0x73e70000', '0x73bc0000', '0x73e80000', '0x73ee0000', '0x74d50000', '0x74070000', '0x74e90000', '0x76970000', '0x75710000', '0x752c0000', '0x74f40000', '0x74f30000', '0x74ef0000', '0x75020000', '0x750c0000', '0x75350000', '0x752e0000', '0x75670000', '0x755d0000', '0x75700000', '0x76640000', '0x758c0000', '0x75810000', '0x75880000', '0x759b0000', '0x76760000', '0x76960000', '0x76d70000', '0x76ba0000', '0x76ad0000', '0x76e80000', '0x76e20000', '0x76f80000', '0x77200000', '0x773e0000', '0x74ee0000', '0x400000', '0x74010000', '0x73f70000', '0x73ee0000', '0x73f60000', '0x73fa0000', '0x74070000', '0x74050000', '0x74e90000', '0x74d50000', '0x76ba0000', '0x75710000', '0x752c0000', '0x74f40000', '0x74f30000', '0x75020000', '0x75350000', '0x752e0000', '0x755d0000', '0x75580000', '0x758c0000', '0x75810000', '0x76970000', '0x759b0000', '0x76ad0000', '0x773e0000', '0x76e20000', '0x76d70000', '0x76f80000', '0x77200000', '0x2d50000', '0x3dc0000', '0x73700000', '0xb3b0000', '0x76fe0000', '0x748b0000', '0x74da0000', '0x77200000', '0x77100000', '0x773d0000', '0x7fef9b00000', '0x7fef4330000', '0x7fef2a20000', '0x7fef1540000', '0x7fef04e0000', '0x7fef0380000', '0xfff90000', '0x7fef03a0000', '0x7fef0c30000', '0x7fef0a30000', '0x7fef21b0000', '0x7fef15a0000', '0x7fef2160000', '0x7fef22d0000', '0x7fef22c0000', '0x7fef28d0000', '0x7fef3e30000', '0x7fef3be0000', '0x7fef2ca0000', '0x7fef2aa0000', '0x7fef3b40000', '0x7fef3d80000', '0x7fef3cc0000', '0x7fef3dd0000', '0x7fef3fa0000', '0x7fef3e60000', '0x7fef3e50000', '0x7fef3e70000', '0x7fef3e90000', '0x7fef40b0000', '0x7fef4090000', '0x7fef42f0000', '0x7fef5ed0000', '0x7fef5160000', '0x7fef4810000', '0x7fef44d0000', '0x7fef43b0000', '0x7fef4700000', '0x7fef4890000', '0x7fef4870000', '0x7fef48b0000', '0x7fef4f20000', '0x7fef5770000', '0x7fef5490000', '0x7fef51c0000', '0x7fef51a0000', '0x7fef5470000', '0x7fef5590000', '0x7fef5b10000', '0x7fef57e0000', '0x7fef58a0000', '0x7fef5e00000', '0x7fef88d0000', '0x7fef7a00000', '0x7fef72f0000', '0x7fef6c40000', '0x7fef64c0000', '0x7fef6c70000', '0x7fef73a0000', '0x7fef7300000', '0x7fef8300000', '0x7fef8110000', '0x7fef7a80000', '0x7fef84c0000', '0x7fef84b0000', '0x7fef8510000', '0x7fef94b0000', '0x7fef8a50000', '0x7fef88e0000', '0x7fef8ba0000', '0x7fef9500000', '0x7fef94f0000', '0x7fef97a0000', '0x7fef9580000', '0x7fef9920000', '0x7fefd240000', '0x7fefb8a0000', '0x7fefb250000', '0x7fefad70000', '0x7fefabf0000', '0x7fefa6e0000', '0x7fef9f50000', '0x7fefa730000', '0x7fefaca0000', '0x7fefac70000', '0x7fefaf30000', '0x7fefae50000', '0x7fefae70000', '0x7fefb030000', '0x7fefafc0000', '0x7fefafe0000', '0x7fefb120000', '0x7fefb350000', '0x7fefb2b0000', '0x7fefb270000', '0x7fefb310000', '0x7fefb300000', '0x7fefb430000', '0x7fefb410000', '0x7fefb3a0000', '0x7fefb420000', '0x7fefb590000', '0x7fefb530000', '0x7fefb5b0000', '0x7fefcf50000', '0x7fefc480000', '0x7fefbb40000', '0x7fefb950000', '0x7fefb900000', '0x7fefb930000', '0x7fefbac0000', '0x7fefba90000', '0x7fefbb10000', '0x7fefbe20000', '0x7fefbd40000', '0x7fefc2b0000', '0x7fefbf30000', '0x7fefc460000', '0x7fefcbc0000', '0x7fefc5f0000', '0x7fefc530000', '0x7fefc4a0000', '0x7fefc780000', '0x7fefceb0000', '0x7fefcbe0000', '0x7fefd040000', '0x7fefcfb0000', '0x7fefcfe0000', '0x7fefd110000', '0x7fefd0f0000', '0x7fefd050000', '0x7fefd1f0000', '0x7fefd120000', '0x7fefd200000', '0x7feff310000', '0x7fefdb40000', '0x7fefd6b0000', '0x7fefd520000', '0x7fefd2d0000', '0x7fefd2b0000', '0x7fefd3b0000', '0x7fefd5b0000', '0x7fefd610000', '0x7fefd8f0000', '0x7fefd850000', '0x7fefd720000', '0x7fefda10000', '0x7fefda00000', '0x7fefef00000', '0x7fefddf0000', '0x7fefdc40000', '0x7fefdd10000', '0x7fefde70000', '0x7fefec00000', '0x7fefef20000', '0x7feff130000', '0x7feff4c0000', '0x7feff340000', '0x77200000', '0x13fda0000', '0x7fef7350000', '0x7fefc530000', '0x7fefcbc0000', '0x7fefd040000', '0x7fefd0f0000', '0x7fefdb40000', '0x7fefda10000', '0xff0c0000', '0x7fefbb40000', '0x7fefb950000', '0x7fefdb40000', '0x7fefef20000', '0x74ee0000', '0x400000', '0x250000', '0x260000', '0x735e0000', '0x72d20000', '0x733c0000', '0x73440000', '0x73fa0000', '0x73ea0000', '0x73bc0000', '0x73e80000', '0x73ee0000', '0x73f60000', '0x74070000', '0x74e90000', '0x76970000', '0x75710000', '0x752c0000', '0x74f40000', '0x74f30000', '0x74ef0000', '0x75020000', '0x750c0000', '0x75350000', '0x752e0000', '0x75670000', '0x755d0000', '0x75700000', '0x76640000', '0x758c0000', '0x75810000', '0x75880000', '0x759b0000', '0x76760000', '0x76960000', '0x76d70000', '0x76ba0000', '0x76ad0000', '0x76e80000', '0x76e20000', '0x76f80000', '0x77200000', '0x773e0000', '0x74ee0000', '0xaf0000', '0x72f70000', '0x3180000', '0x72e20000', '0x72e50000', '0x72e40000', '0x72e70000', '0x73ee0000', '0x732d0000', '0x73030000', '0x72fa0000', '0x73250000', '0x73380000', '0x732f0000', '0x73e60000', '0x73440000', '0x73e70000', '0x74010000', '0x73f60000', '0x73f70000', '0x74070000', '0x74050000', '0x74e90000', '0x76ba0000', '0x75710000', '0x752e0000', '0x75020000', '0x74f40000', '0x74f30000', '0x752c0000', '0x755d0000', '0x75350000', '0x75330000', '0x753e0000', '0x75580000', '0x75700000', '0x75670000', '0x758c0000', '0x75810000', '0x75880000', '0x76970000', '0x768a0000', '0x759b0000', '0x76930000', '0x76ad0000', '0x773e0000', '0x76e20000', '0x76d70000', '0x76f80000', '0x77200000'], 

                'InLoad': [True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, True, False, False, False, False, False, True, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, False, True, False, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, False, False, False, False, False, False, False, False, False, False, False, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True], 

                'InInit': [True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, False, False, False, False, False, False, True, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, False, True, False, True, True, True, True, True, True, True, True, True, True, True, True, False, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, False, True, True, True, True, True, True, True, False, True, True, True, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True], 

                'InMem': [True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, True, False, False, False, False, False, True, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, False, True, False, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, False, False, False, False, False, False, False, False, False, False, False, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True], 

                'MappedPath': ['\\Windows\\System32\\wow64cpu.dll', '\\Users\\labib\\Desktop\\@WanaDecryptor@.exe', '\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', '\\Windows\\SysWOW64\\mfc42.dll', '\\Windows\\SysWOW64\\mswsock.dll', '\\Windows\\SysWOW64\\riched20.dll', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2\\comctl32.dll', '\\Windows\\SysWOW64\\msvcp60.dll', '\\Windows\\SysWOW64\\odbcint.dll', '\\Windows\\SysWOW64\\WSHTCPIP.DLL', '\\Windows\\SysWOW64\\odbc32.dll', '\\Windows\\SysWOW64\\dwmapi.dll', '\\Windows\\SysWOW64\\uxtheme.dll', '\\Windows\\SysWOW64\\apphelp.dll', '\\Windows\\System32\\wow64win.dll', '\\Windows\\System32\\wow64.dll', '\\Windows\\SysWOW64\\ole32.dll', '\\Windows\\SysWOW64\\user32.dll', '\\Windows\\SysWOW64\\sechost.dll', '\\Windows\\SysWOW64\\sspicli.dll', '\\Windows\\SysWOW64\\cryptbase.dll', '\\Windows\\SysWOW64\\riched32.dll', '\\Windows\\SysWOW64\\advapi32.dll', '\\Windows\\SysWOW64\\iertutil.dll', '\\Windows\\SysWOW64\\gdi32.dll', '\\Windows\\SysWOW64\\KernelBase.dll', '\\Windows\\SysWOW64\\oleaut32.dll', '\\Windows\\SysWOW64\\usp10.dll', '\\Windows\\SysWOW64\\nsi.dll', '\\Windows\\SysWOW64\\crypt32.dll', '\\Windows\\SysWOW64\\rpcrt4.dll', '\\Windows\\SysWOW64\\lpk.dll', '\\Windows\\SysWOW64\\ws2_32.dll', '\\Windows\\SysWOW64\\shell32.dll', '\\Windows\\SysWOW64\\urlmon.dll', '\\Windows\\SysWOW64\\msasn1.dll', '\\Windows\\SysWOW64\\msvcrt.dll', '\\Windows\\SysWOW64\\kernel32.dll', '\\Windows\\SysWOW64\\msctf.dll', '\\Windows\\SysWOW64\\wininet.dll', '\\Windows\\SysWOW64\\shlwapi.dll', '\\Windows\\SysWOW64\\imm32.dll', '\\Windows\\System32\\ntdll.dll', '\\Windows\\SysWOW64\\ntdll.dll', '\\Windows\\System32\\wow64cpu.dll', '\\Users\\labib\\Desktop\\WannaCry.EXE', '\\Windows\\SysWOW64\\rsaenh.dll', '\\Windows\\SysWOW64\\ntmarta.dll', '\\Windows\\SysWOW64\\uxtheme.dll', '\\Windows\\SysWOW64\\profapi.dll', '\\Windows\\SysWOW64\\msvcp60.dll', '\\Windows\\System32\\wow64win.dll', '\\Windows\\SysWOW64\\cryptsp.dll', '\\Windows\\System32\\wow64.dll', '\\Windows\\SysWOW64\\apphelp.dll', '\\Windows\\SysWOW64\\kernel32.dll', '\\Windows\\SysWOW64\\user32.dll', '\\Windows\\SysWOW64\\sechost.dll', '\\Windows\\SysWOW64\\sspicli.dll', '\\Windows\\SysWOW64\\cryptbase.dll', '\\Windows\\SysWOW64\\advapi32.dll', '\\Windows\\SysWOW64\\gdi32.dll', '\\Windows\\SysWOW64\\KernelBase.dll', '\\Windows\\SysWOW64\\usp10.dll', '\\Windows\\SysWOW64\\Wldap32.dll', '\\Windows\\SysWOW64\\rpcrt4.dll', '\\Windows\\SysWOW64\\lpk.dll', '\\Windows\\SysWOW64\\ole32.dll', '\\Windows\\SysWOW64\\shell32.dll', '\\Windows\\SysWOW64\\msctf.dll', '\\Windows\\SysWOW64\\ntdll.dll', '\\Windows\\SysWOW64\\shlwapi.dll', '\\Windows\\SysWOW64\\msvcrt.dll', '\\Windows\\SysWOW64\\imm32.dll', '\\Windows\\System32\\ntdll.dll', '\\Program Files\\Windows Sidebar\\en-US\\sbdrop.dll.mui', '\\Windows\\System32\\en-US\\searchfolder.dll.mui', '\\Windows\\System32\\ksuser.dll', '\\Windows\\System32\\imageres.dll', '\\Windows\\System32\\kernel32.dll', '\\Windows\\System32\\NlsLexicons0009.dll', '\\Windows\\System32\\FXSRESM.dll', '\\Windows\\System32\\ntdll.dll', '\\Windows\\System32\\user32.dll', '\\Windows\\System32\\psapi.dll', '\\Windows\\System32\\ExplorerFrame.dll', '\\Windows\\System32\\hgcpl.dll', '\\Windows\\System32\\StructuredQuery.dll', '\\Windows\\System32\\oleacc.dll', '\\Windows\\System32\\wscui.cpl', '\\Windows\\System32\\wercplsupport.dll', '\\Windows\\explorer.exe', '\\Windows\\System32\\werconcpl.dll', '\\Windows\\System32\\wscinterop.dll', '\\Windows\\System32\\wscapi.dll', '\\Program Files\\Internet Explorer\\ieproxy.dll', '\\Windows\\System32\\ieframe.dll', '\\Windows\\System32\\hcproviders.dll', '\\Windows\\System32\\NlsData0009.dll', '\\Windows\\System32\\SensApi.dll', '\\Windows\\System32\\NaturalLanguage6.dll', '\\Windows\\System32\\wlanapi.dll', '\\Windows\\System32\\FXSST.dll', '\\Windows\\System32\\UIAnimation.dll', '\\Windows\\System32\\SearchFolder.dll', '\\Windows\\System32\\FXSAPI.dll', '\\Windows\\System32\\QAGENT.DLL', '\\Windows\\System32\\bthprops.cpl', '\\Windows\\System32\\WWanAPI.dll', '\\Windows\\System32\\msftedit.dll', '\\Windows\\System32\\wlanutil.dll', '\\Windows\\System32\\wwapi.dll', '\\Windows\\System32\\rasman.dll', '\\Windows\\System32\\rasdlg.dll', '\\Program Files\\Windows Sidebar\\sbdrop.dll', '\\Windows\\System32\\thumbcache.dll', '\\Windows\\System32\\provsvc.dll', '\\Windows\\System32\\gameux.dll', '\\Windows\\System32\\PortableDeviceTypes.dll', '\\Windows\\System32\\srchadmin.dll', '\\Windows\\System32\\SyncCenter.dll', '\\Windows\\System32\\imapi2.dll', '\\Windows\\System32\\ActionCenter.dll', '\\Windows\\System32\\QUTIL.DLL', '\\Windows\\System32\\mssprxy.dll', '\\Windows\\System32\\pnidui.dll', '\\Windows\\System32\\tquery.dll', '\\Windows\\System32\\prnfldr.dll', '\\Windows\\System32\\DXP.dll', '\\Windows\\System32\\netshell.dll', '\\Windows\\System32\\WPDShServiceObj.dll', '\\Windows\\System32\\Syncreg.dll', '\\Windows\\System32\\EhStorAPI.dll', '\\Windows\\System32\\stobject.dll', '\\Windows\\System32\\batmeter.dll', '\\Windows\\System32\\comsvcs.dll', '\\Windows\\System32\\rasapi32.dll', '\\Windows\\System32\\linkinfo.dll', '\\Windows\\System32\\netprofm.dll', '\\Windows\\System32\\msacm32.drv', '\\Windows\\System32\\midimap.dll', '\\Windows\\System32\\PortableDeviceApi.dll', '\\Windows\\System32\\msacm32.dll', 'N/A', '\\Windows\\System32\\AudioSes.dll', '\\Windows\\System32\\networkexplorer.dll', '\\Windows\\System32\\msls31.dll', 'N/A', '\\Windows\\System32\\AltTab.dll', '\\Windows\\System32\\npmproxy.dll', '\\Windows\\System32\\wdmaud.drv', '\\Windows\\System32\\IconCodecService.dll', '\\Windows\\System32\\actxprxy.dll', '\\Windows\\System32\\shdocvw.dll', '\\Windows\\System32\\timedate.cpl', '\\Windows\\System32\\ntshrui.dll', '\\Windows\\System32\\cscapi.dll', '\\Windows\\System32\\EhStorShell.dll', '\\Windows\\System32\\msxml6.dll', '\\Windows\\System32\\winmm.dll', '\\Windows\\System32\\KernelBase.dll', '\\Windows\\System32\\uxtheme.dll', '\\Windows\\System32\\wtsapi32.dll', '\\Windows\\System32\\wer.dll', '\\Windows\\System32\\dhcpcsvc.dll', '\\Windows\\System32\\mpr.dll', '\\Windows\\System32\\winspool.drv', '\\Windows\\System32\\rasadhlp.dll', '\\Windows\\System32\\rtutils.dll', '\\Windows\\System32\\dhcpcsvc6.dll', '\\Windows\\System32\\netutils.dll', '\\Windows\\System32\\samcli.dll', '\\Windows\\System32\\wkscli.dll', '\\Windows\\System32\\IPHLPAPI.DLL', '\\Windows\\System32\\winnsi.dll', '\\Windows\\System32\\framedynos.dll', '\\Windows\\System32\\WindowsCodecs.dll', '\\Windows\\System32\\duser.dll', '\\Windows\\System32\\dwmapi.dll', '\\Windows\\System32\\xmllite.dll', '\\Windows\\System32\\SndVolSSO.dll', '\\Windows\\System32\\hid.dll', '\\Windows\\System32\\dui70.dll', '\\Windows\\System32\\slc.dll', '\\Windows\\System32\\es.dll', '\\Windows\\System32\\dsrole.dll', '\\Windows\\System32\\nlaapi.dll', '\\Windows\\System32\\atl.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_2b24536c71ed437a\\GdiPlus.dll', '\\Windows\\System32\\secur32.dll', '\\Windows\\System32\\userenv.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac\\comctl32.dll', '\\Windows\\System32\\propsys.dll', '\\Windows\\System32\\ntmarta.dll', '\\Windows\\System32\\samlib.dll', '\\Windows\\System32\\MMDevAPI.dll', '\\Windows\\System32\\shacct.dll', '\\Windows\\System32\\powrprof.dll', '\\Windows\\System32\\cryptui.dll', '\\Windows\\System32\\avrt.dll', '\\Windows\\System32\\version.dll', '\\Windows\\System32\\authui.dll', '\\Windows\\System32\\gpapi.dll', '\\Windows\\System32\\cryptsp.dll', '\\Windows\\System32\\credssp.dll', '\\Windows\\System32\\rsaenh.dll', '\\Windows\\System32\\devrtl.dll', '\\Windows\\System32\\dnsapi.dll', '\\Windows\\System32\\srvcli.dll', '\\Windows\\System32\\wevtapi.dll', '\\Windows\\System32\\cryptbase.dll', '\\Windows\\System32\\sspicli.dll', '\\Windows\\System32\\apphelp.dll', '\\Windows\\System32\\profapi.dll', '\\Windows\\System32\\RpcRtRemote.dll', '\\Windows\\System32\\sxs.dll', '\\Windows\\System32\\msasn1.dll', '\\Windows\\System32\\winsta.dll', '\\Windows\\System32\\wintrust.dll', '\\Windows\\System32\\imm32.dll', '\\Windows\\System32\\advapi32.dll', '\\Windows\\System32\\gdi32.dll', '\\Windows\\System32\\lpk.dll', '\\Windows\\System32\\cfgmgr32.dll', '\\Windows\\System32\\devobj.dll', '\\Windows\\System32\\crypt32.dll', '\\Windows\\System32\\Wldap32.dll', '\\Windows\\System32\\clbcatq.dll', '\\Windows\\System32\\msctf.dll', '\\Windows\\System32\\msvcrt.dll', '\\Windows\\System32\\wininet.dll', '\\Windows\\System32\\rpcrt4.dll', '\\Windows\\System32\\nsi.dll', '\\Windows\\System32\\sechost.dll', '\\Windows\\System32\\shlwapi.dll', '\\Windows\\System32\\usp10.dll', '\\Windows\\System32\\oleaut32.dll', '\\Windows\\System32\\shell32.dll', '\\Windows\\System32\\iertutil.dll', '\\Windows\\System32\\ole32.dll', '\\Windows\\System32\\setupapi.dll', '\\Windows\\System32\\ws2_32.dll', '\\Windows\\System32\\urlmon.dll', '\\Windows\\System32\\ntdll.dll', '\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmusr\\vmtray.dll', '\\Windows\\System32\\rsaenh.dll', '\\Windows\\System32\\cryptsp.dll', '\\Windows\\System32\\cryptbase.dll', '\\Windows\\System32\\RpcRtRemote.dll', '\\Windows\\System32\\advapi32.dll', '\\Windows\\System32\\rpcrt4.dll', '\\Windows\\System32\\taskmgr.exe', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac\\comctl32.dll', '\\Windows\\System32\\propsys.dll', '\\Windows\\System32\\advapi32.dll', '\\Windows\\System32\\ole32.dll', '\\Windows\\System32\\wow64cpu.dll', '\\Users\\labib\\Desktop\\@WanaDecryptor@.exe', '\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', '\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '\\Windows\\SysWOW64\\mfc42.dll', '\\Windows\\SysWOW64\\msls31.dll', '\\Windows\\SysWOW64\\riched20.dll', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2\\comctl32.dll', '\\Windows\\SysWOW64\\msvcp60.dll', '\\Windows\\SysWOW64\\odbcint.dll', '\\Windows\\SysWOW64\\odbc32.dll', '\\Windows\\SysWOW64\\dwmapi.dll', '\\Windows\\SysWOW64\\uxtheme.dll', '\\Windows\\SysWOW64\\profapi.dll', '\\Windows\\System32\\wow64win.dll', '\\Windows\\System32\\wow64.dll', '\\Windows\\SysWOW64\\ole32.dll', '\\Windows\\SysWOW64\\user32.dll', '\\Windows\\SysWOW64\\sechost.dll', '\\Windows\\SysWOW64\\sspicli.dll', '\\Windows\\SysWOW64\\cryptbase.dll', '\\Windows\\SysWOW64\\riched32.dll', '\\Windows\\SysWOW64\\advapi32.dll', '\\Windows\\SysWOW64\\iertutil.dll', '\\Windows\\SysWOW64\\gdi32.dll', '\\Windows\\SysWOW64\\KernelBase.dll', '\\Windows\\SysWOW64\\oleaut32.dll', '\\Windows\\SysWOW64\\usp10.dll', '\\Windows\\SysWOW64\\nsi.dll', '\\Windows\\SysWOW64\\crypt32.dll', '\\Windows\\SysWOW64\\rpcrt4.dll', '\\Windows\\SysWOW64\\lpk.dll', '\\Windows\\SysWOW64\\ws2_32.dll', '\\Windows\\SysWOW64\\shell32.dll', '\\Windows\\SysWOW64\\urlmon.dll', '\\Windows\\SysWOW64\\msasn1.dll', '\\Windows\\SysWOW64\\msvcrt.dll', '\\Windows\\SysWOW64\\kernel32.dll', '\\Windows\\SysWOW64\\msctf.dll', '\\Windows\\SysWOW64\\wininet.dll', '\\Windows\\SysWOW64\\shlwapi.dll', '\\Windows\\SysWOW64\\imm32.dll', '\\Windows\\System32\\ntdll.dll', '\\Windows\\SysWOW64\\ntdll.dll', '\\Windows\\System32\\wow64cpu.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\taskhsvc.exe', '\\Users\\labib\\Desktop\\TaskData\\Tor\\zlib1.dll', '\\Windows\\SysWOW64\\en-US\\KernelBase.dll.mui', '\\Windows\\SysWOW64\\dhcpcsvc.dll', '\\Windows\\SysWOW64\\IPHLPAPI.DLL', '\\Windows\\SysWOW64\\dhcpcsvc6.dll', '\\Windows\\SysWOW64\\propsys.dll', '\\Windows\\SysWOW64\\uxtheme.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libssp-0.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libeay32.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\ssleay32.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libgcc_s_sjlj-1.dll', '\\Windows\\SysWOW64\\mswsock.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libevent-2-0-5.dll', '\\Windows\\SysWOW64\\winnsi.dll', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2\\comctl32.dll', '\\Windows\\SysWOW64\\WSHTCPIP.DLL', '\\Windows\\SysWOW64\\rsaenh.dll', '\\Windows\\SysWOW64\\profapi.dll', '\\Windows\\SysWOW64\\ntmarta.dll', '\\Windows\\System32\\wow64win.dll', '\\Windows\\SysWOW64\\cryptsp.dll', '\\Windows\\System32\\wow64.dll', '\\Windows\\SysWOW64\\kernel32.dll', '\\Windows\\SysWOW64\\user32.dll', '\\Windows\\SysWOW64\\KernelBase.dll', '\\Windows\\SysWOW64\\advapi32.dll', '\\Windows\\SysWOW64\\sspicli.dll', '\\Windows\\SysWOW64\\cryptbase.dll', '\\Windows\\SysWOW64\\sechost.dll', '\\Windows\\SysWOW64\\usp10.dll', '\\Windows\\SysWOW64\\gdi32.dll', '\\Windows\\SysWOW64\\devobj.dll', '\\Windows\\SysWOW64\\setupapi.dll', '\\Windows\\SysWOW64\\Wldap32.dll', '\\Windows\\SysWOW64\\nsi.dll', '\\Windows\\SysWOW64\\oleaut32.dll', '\\Windows\\SysWOW64\\rpcrt4.dll', '\\Windows\\SysWOW64\\lpk.dll', '\\Windows\\SysWOW64\\ws2_32.dll', '\\Windows\\SysWOW64\\ole32.dll', '\\Windows\\SysWOW64\\clbcatq.dll', '\\Windows\\SysWOW64\\shell32.dll', '\\Windows\\SysWOW64\\cfgmgr32.dll', '\\Windows\\SysWOW64\\msctf.dll', '\\Windows\\SysWOW64\\ntdll.dll', '\\Windows\\SysWOW64\\shlwapi.dll', '\\Windows\\SysWOW64\\msvcrt.dll', '\\Windows\\SysWOW64\\imm32.dll', '\\Windows\\System32\\ntdll.dll']},

            'filescan': {
                'Offset': ['0x1e401360', '0x1e4014b0', '0x1e401600', '0x1e401750', '0x1e401ab0', '0x1e404570', '0x1e405f20', '0x1e406a60', '0x1e406f20', '0x1e4116d0', '0x1e426840', '0x1e427f20', '0x1e430780', '0x1e430a20', '0x1e431910', '0x1e431f20', '0x1e432960', '0x1e435ab0', '0x1e445af0', '0x1e448d80', '0x1e4536d0', '0x1e453820', '0x1e45b1c0', '0x1e45b910', '0x1e45bdd0', '0x1e45f9c0', '0x1e464530', '0x1e464d20', '0x1e465560', '0x1e4663a0', '0x1e466a20', '0x1e4694b0', '0x1e46fe00', '0x1e472280', '0x1e478460', '0x1e485b00', '0x1e487a10', '0x1e489790', '0x1e48bf20', '0x1e4a6a20', '0x1e4a9ab0', '0x1e4aa700', '0x1e4b3c80', '0x1e4b3dd0', '0x1e4b4860', '0x1e4b52a0', '0x1e4b6730', '0x1e4b7b80', '0x1e4b7f20', '0x1e4bfa20', '0x1e4c13a0', '0x1e4c1690', '0x1e4c4700', '0x1e4c6690', '0x1e4c92a0', '0x1e4ca5b0', '0x1e4ccc50', '0x1e4cf360', '0x1e4cf4b0', '0x1e4cf820', '0x1e4d0210', '0x1e4d1780', '0x1e4da070', '0x1e4da1c0', '0x1e4de960', '0x1e4e1dc0', '0x1e4e27f0', '0x1e4e4070', '0x1e4e5830', '0x1e4e6070', '0x1e4e7b10', '0x1e4e85c0', '0x1e4e8f20', '0x1e4e9440', '0x1e4e9900', '0x1e4e9dc0', '0x1e4ea070', '0x1e4eabb0', '0x1e4ebd00', '0x1e4ece20', '0x1e4ed9a0', '0x1e4f14f0', '0x1e4f1c00', '0x1e4faaa0', '0x1e4fabf0', '0x1e4fe250', '0x1e4fee60', '0x1e4ff750', '0x1e503d10', '0x1e504550', '0x1e50a450', '0x1e50af20', '0x1e50bf20', '0x1e515420', '0x1e515800', '0x1e516760', '0x1e516f20', '0x1e51a2a0', '0x1e51f070', '0x1e51f7e0', '0x1e5253e0', '0x1e525f20', '0x1e528ea0', '0x1e5295f0', '0x1e529d10', '0x1e52b330', '0x1e52d3d0', '0x1e52e070', '0x1e52f260', '0x1e52faf0', '0x1e531d30', '0x1e532700', '0x1e5328b0', '0x1e532f20', '0x1e534b90', '0x1e534ce0', '0x1e535a00', '0x1e537c80', '0x1e543a00', '0x1e544350', '0x1e545bd0', '0x1e546300', '0x1e56c070', '0x1e56c570', '0x1e575290', '0x1e575f20', '0x1e5764a0', '0x1e5771e0', '0x1e577490', '0x1e577f20', '0x1e578210', '0x1e591590', '0x1e592070', '0x1e603570', '0x1e603c60', '0x1e603db0', '0x1e604c20', '0x1e606070', '0x1e6077d0', '0x1e608b80', '0x1e60a7d0', '0x1e60ab30', '0x1e60b560', '0x1e60b890', '0x1e60c070', '0x1e60c600', '0x1e60c8a0', '0x1e60cde0', '0x1e60d800', '0x1e60f350', '0x1e60f5f0', '0x1e60fad0', '0x1e60fd70', '0x1e610ab0', '0x1e61a1e0', '0x1e61a330', '0x1e61a4a0', '0x1e61bb40', '0x1e61c460', '0x1e61cc00', '0x1e61dc80', '0x1e61f680', '0x1e61f9f0', '0x1e6206b0', '0x1e620d40', '0x1e625640', '0x1e625860', '0x1e625c80', '0x1e626a30', '0x1e6288c0', '0x1e628e20', '0x1e6292f0', '0x1e6297d0', '0x1e62af20', '0x1e62b1b0', '0x1e62c070', '0x1e62c4b0', '0x1e62d410', '0x1e636a20', '0x1e638910', '0x1e6424d0', '0x1e642bc0', '0x1e6436c0', '0x1e644890', '0x1e645f20', '0x1e646ac0', '0x1e648b90', '0x1e64b530', '0x1e654430', '0x1e6555a0', '0x1e6556f0', '0x1e655a80', '0x1e656290', '0x1e657070', '0x1e657270', '0x1e6575d0', '0x1e658310', '0x1e65b070', '0x1e65c9e0', '0x1e65d540', '0x1e6675d0', '0x1e667930', '0x1e669070', '0x1e669210', '0x1e66d390', '0x1e66e070', '0x1e66e2c0', '0x1e672d70', '0x1e67d2f0', '0x1e67ec80', '0x1e67f2a0', '0x1e680070', '0x1e680ba0', '0x1e681070', '0x1e6817d0', '0x1e681c80', '0x1e682410', '0x1e682560', '0x1e682810', '0x1e684880', '0x1e685310', '0x1e6855f0', '0x1e688670', '0x1e688be0', '0x1e68a760', '0x1e68ba10', '0x1e697670', '0x1e697a10', '0x1e699290', '0x1e699470', '0x1e69bea0', '0x1e69ca80', '0x1e69dc50', '0x1e69dea0', '0x1e69e410', '0x1e69f3c0', '0x1e6a0070', '0x1e6a3840', '0x1e6a45b0', '0x1e6ae960', '0x1e6af550', '0x1e6aff20', '0x1e6b95c0', '0x1e6bcdd0', '0x1e6bd850', '0x1e6be070', '0x1e6bf420', '0x1e6bfc80', '0x1e6bff20', '0x1e6c0770', '0x1e6c0f20', '0x1e6c14d0', '0x1e6c2940', '0x1e6c3680', '0x1e6c4070', '0x1e6c44f0', '0x1e6c61d0', '0x1e6d15b0', '0x1e6d2490', '0x1e6d25e0', '0x1e6d29a0', '0x1e6d2bb0', '0x1e6d6b00', '0x1e6d6f20', '0x1e6d7640', '0x1e6d8f20', '0x1e6d9530', '0x1e6d98a0', '0x1e6d99f0', '0x1e6db590', '0x1e6dcf20', '0x1e6e6400', '0x1e6e84c0', '0x1e6e98c0', '0x1e6eaf20', '0x1e6f35c0', '0x1e6f4df0', '0x1e6f55b0', '0x1e6f9b40', '0x1e6fa3f0', '0x1e6fa7e0', '0x1e6fa990', '0x1e6fd7c0', '0x1e6fdb30', '0x1e6fddd0', '0x1e6ff310', '0x1e7008f0', '0x1e706ae0', '0x1e706c30', '0x1e706d80', '0x1e7075d0', '0x1e708460', '0x1e70a070', '0x1e70a280', '0x1e70a480', '0x1e70ec90', '0x1e70f9b0', '0x1e719360', '0x1e71d6f0', '0x1e71d950', '0x1e71df20', '0x1e759070', '0x1e75c470', '0x1e75fa20', '0x1e760940', '0x1e761f20', '0x1e762070', '0x1e762620', '0x1e763d10', '0x1e764070', '0x1e76a8a0', '0x1e76ab20', '0x1e76b270', '0x1e76ccb0', '0x1e76e810', '0x1e771950', '0x1e77dbc0', '0x1e799980', '0x1e79a620', '0x1e79b320', '0x1e79b900', '0x1e79ef20', '0x1e7a1af0', '0x1e7ad520', '0x1e7b94f0', '0x1e7ba1c0', '0x1e7ba9a0', '0x1e7bea70', '0x1e7c2d20', '0x1e7c5d10', '0x1e7c68f0', '0x1e7c6d10', '0x1e7c6e60', '0x1e7ca590', '0x1e7cc990', '0x1e7ccae0', '0x1e7d6240', '0x1e7dd9e0', '0x1e7dedd0', '0x1e7def20', '0x1e7df500', '0x1e7e04c0', '0x1e7e0f20', '0x1e7e2400', '0x1e7e3420', '0x1e7e4360', '0x1e7e4f20', '0x1e7e6530', '0x1e7eea70', '0x1e7efd40', '0x1e7eff20', '0x1e7f0770', '0x1e7f2070', '0x1e7fb4e0', '0x1e7fcdd0', '0x1e7fd070', '0x1e7fe1e0', '0x1e802070', '0x1e802aa0', '0x1e802bf0', '0x1e803b30', '0x1e805530', '0x1e806070', '0x1e806a00', '0x1e807dd0', '0x1e808070', '0x1e808a50', '0x1e808f20', '0x1e809600', '0x1e80b980', '0x1e80c070', '0x1e80d880', '0x1e80db90', '0x1e80df20', '0x1e80f890', '0x1e811ac0', '0x1e813070', '0x1e814c40', '0x1e815430', '0x1e8158a0', '0x1e8159f0', '0x1e816bc0', '0x1e816d10', '0x1e817cc0', '0x1e8182d0', '0x1e81a9a0', '0x1e81b5d0', '0x1e81b880', '0x1e81ba50', '0x1e820be0', '0x1e820f20', '0x1e825900', '0x1e825a50', '0x1e825cf0', '0x1e826940', '0x1e829a30', '0x1e82a8b0', '0x1e82b400', '0x1e82e550', '0x1e834750', '0x1e834dc0', '0x1e835070', '0x1e835750', '0x1e836740', '0x1e839f20', '0x1e83aa70', '0x1e83bb00', '0x1e83d730', '0x1e83fa60', '0x1e841070', '0x1e841ac0', '0x1e842ab0', '0x1e84c8f0', '0x1e84cf20', '0x1e853730', '0x1e855d20', '0x1e858aa0', '0x1e859730', '0x1e859f20', '0x1e85a5f0', '0x1e85f730', '0x1e861b30', '0x1e861c80', '0x1e862b20', '0x1e862f20', '0x1e863f20', '0x1e866970', '0x1e8679c0', '0x1e867e20', '0x1e86a430', '0x1e86aa60', '0x1e890070', '0x1e891aa0', '0x1e892420', '0x1e8a0a10', '0x1e8a1120', '0x1e8a1270', '0x1e8a1780', '0x1e8a2680', '0x1e8a2a80', '0x1e8a3960', '0x1e8a4070', '0x1e8a5070', '0x1e8a58b0', '0x1e8a79d0', '0x1e8a8cf0', '0x1e8a9f20', '0x1e8aaa70', '0x1e8ac6c0', '0x1e8acb20', '0x1e8acf20', '0x1e8addf0', '0x1e8aee60', '0x1e8afc20', '0x1e8b0610', '0x1e8b13f0', '0x1e8b1680', '0x1e8b3070', '0x1e8b42b0', '0x1e8b5dd0', '0x1e8b6f20', '0x1e8b8ea0', '0x1e8bc3b0', '0x1e8bc840', '0x1e8bca20', '0x1e8c6a00', '0x1e8c8630', '0x1e8ca400', '0x1e8cac50', '0x1e8cae60', '0x1e8cb4e0', '0x1e8cc120', '0x1e8cca60', '0x1e8cdf20', '0x1e8d0d40', '0x1e8d0e90', '0x1e8d1c70', '0x1e8d26a0', '0x1e8d2a90', '0x1e8d4b50', '0x1e8d4ca0', '0x1e8d5500', '0x1e8d6f20', '0x1e8d94c0', '0x1e8d96b0', '0x1e8db7f0', '0x1e8e5f20', '0x1e8e99e0', '0x1e8ebbb0', '0x1e8ed9a0', '0x1e8eebf0', '0x1e8f0dd0', '0x1e8f0f20', '0x1e8f1640', '0x1e8f5dd0', '0x1e8f6700', '0x1e8f6850', '0x1e8f8730', '0x1e8faab0', '0x1e8fd910', '0x1e907b90', '0x1e90d710', '0x1e90f210', '0x1e912c30', '0x1e915a60', '0x1e919370', '0x1e91a360', '0x1e91aa90', '0x1e91bdd0', '0x1e91c520', '0x1e91cf20', '0x1e91e730', '0x1e91f5b0', '0x1e922360', '0x1e923530', '0x1e924540', '0x1e924ec0', '0x1e926990', '0x1e92a880', '0x1e92f1b0', '0x1e92ff20', '0x1e930a40', '0x1e9322a0', '0x1e932450', '0x1e9336a0', '0x1e941bc0', '0x1e942360', '0x1e942580', '0x1e942850', '0x1e947bc0', '0x1e949920', '0x1e94bd60', '0x1e94d1a0', '0x1e94f670', '0x1e950660', '0x1e951c70', '0x1e9535f0', '0x1e95fda0', '0x1e986ec0', '0x1e98b500', '0x1e98bc80', '0x1e98bf20', '0x1e99ba50', '0x1e99c6c0', '0x1e9a7570', '0x1e9a8430', '0x1e9a86e0', '0x1e9a9830', '0x1e9a9b90', '0x1e9acdb0', '0x1e9ae9a0', '0x1e9af820', '0x1e9b1670', '0x1e9b2c00', '0x1e9b3070', '0x1e9b3480', '0x1e9b3a30', '0x1e9b3cd0', '0x1e9b4920', '0x1e9b4b40', '0x1e9b56a0', '0x1e9b5aa0', '0x1e9b6c80', '0x1e9b8340', '0x1e9b8bc0', '0x1e9b9960', '0x1e9bbaf0', '0x1e9bc070', '0x1e9bcb20', '0x1e9be770', '0x1e9c23a0', '0x1e9c28b0', '0x1e9c58c0', '0x1e9c68f0', '0x1e9c7f20', '0x1e9c86f0', '0x1e9c8ad0', '0x1e9c9350', '0x1e9cb830', '0x1e9cc260', '0x1e9ccdd0', '0x1e9ccf20', '0x1e9d09e0', '0x1e9d25c0', '0x1e9d3740', '0x1e9d4070', '0x1e9d4f20', '0x1e9d5680', '0x1e9d6550', '0x1e9d6f20', '0x1e9d7470', '0x1e9d75c0', '0x1e9d77d0', '0x1e9d8320', '0x1e9d8470', '0x1e9d9320', '0x1e9d96f0', '0x1e9d9ca0', '0x1e9da380', '0x1e9dac50', '0x1e9e5560', '0x1e9e6070', '0x1e9e67d0', '0x1e9e6dd0', '0x1e9ec400', '0x1e9efd00', '0x1e9f2660', '0x1e9fb490', '0x1e9fbc60', '0x1e9fc610', '0x1e9fc8a0', '0x1e9ff7a0', '0x1ea1c2e0', '0x1ea1f860', '0x1ea25590', '0x1ea25bf0', '0x1ea25f20', '0x1ea263d0', '0x1ea27800', '0x1ea28590', '0x1ea29f20', '0x1ea2fd50', '0x1ea30d00', '0x1ea34070', '0x1ea342e0', '0x1ea35b00', '0x1ea35f20', '0x1ea38250', '0x1ea383a0', '0x1ea39d10', '0x1ea3a280', '0x1ea3aeb0', '0x1ea3b370', '0x1ea3c170', '0x1ea3c820', '0x1ea3d070', '0x1ea3e220', '0x1ea3e370', '0x1ea3edd0', '0x1ea3ef20', '0x1ea3faa0', '0x1ea3fd50', '0x1ea41be0', '0x1ea42070', '0x1ea42b20', '0x1ea438d0', '0x1ea43bf0', '0x1ea44310', '0x1ea44460', '0x1ea45ab0', '0x1ea4af20', '0x1ea4b360', '0x1ea4cbc0', '0x1ea4d4f0', '0x1ea4d8d0', '0x1ea4dc50', '0x1ea4e570', '0x1ea4f6f0', '0x1ea51070', '0x1ea52360', '0x1ea53700', '0x1ea53ad0', '0x1ea55530', '0x1ea56070', '0x1ea56380', '0x1ea5fb50', '0x1ea601a0', '0x1ea60a30', '0x1ea60b80', '0x1ea61070', '0x1ea62280', '0x1ea62450', '0x1ea65140', '0x1ea66200', '0x1ea667a0', '0x1ea68420', '0x1ea6a740', '0x1ea6a8c0', '0x1ea6b9c0', '0x1ea6d680', '0x1ea6dbf0', '0x1ea6dd40', '0x1ea6fed0', '0x1ea72070', '0x1ea72b70', '0x1ea74e90', '0x1ea75a90', '0x1ea76070', '0x1ea76340', '0x1ea76490', '0x1ea77070', '0x1ea77d50', '0x1ea79f20', '0x1ea7ab40', '0x1ea7af20', '0x1ea7b240', '0x1ea7b9e0', '0x1ea7ddc0', '0x1ea7fa50', '0x1ea80e60', '0x1ea85070', '0x1ea855f0', '0x1ea86ca0', '0x1ea87950', '0x1ea88cc0', '0x1ea89070', '0x1ea89410', '0x1ea8aad0', '0x1ea8af20', '0x1ea8b6a0', '0x1ea8d660', '0x1ea8dc60', '0x1ea8e070', '0x1ea8ef20', '0x1ea90f20', '0x1ea91930', '0x1ea92b40', '0x1ea944f0', '0x1ea94b60', '0x1ea94d30', '0x1ea973e0', '0x1ea97f20', '0x1ea98b80', '0x1ea99f20', '0x1ea9bf20', '0x1ea9c070', '0x1ea9ca20', '0x1ea9f730', '0x1eaa0430', '0x1eaa2f20', '0x1eaa4880', '0x1eaa4f20', '0x1eaa6730', '0x1eaaedc0', '0x1eaaff20', '0x1eab1a90', '0x1eab3a20', '0x1eab5980', '0x1eabaa20', '0x1eabcf20', '0x1eac1880', '0x1eac2730', '0x1eac4f20', '0x1eac5670', '0x1eac6070', '0x1eac6690', '0x1eac6aa0', '0x1eac7d80', '0x1eac8bc0', '0x1eacb070', '0x1eacdbc0', '0x1eace250', '0x1eace940', '0x1eacf950', '0x1eacfd50', '0x1ead16b0', '0x1ead1ae0', '0x1ead2920', '0x1ead2ea0', '0x1ead4e60', '0x1ead5960', '0x1ead5b90', '0x1ead6070', '0x1ead7d00', '0x1ead83d0', '0x1eadada0', '0x1eadb070', '0x1eaddbe0', '0x1eade9c0', '0x1eadeca0', '0x1eadf3d0', '0x1eae2730', '0x1eae2880', '0x1eae3a70', '0x1eae5dd0', '0x1eae6da0', '0x1eae7340', '0x1eae7740', '0x1eae7a00', '0x1eae7df0', '0x1eae7f20', '0x1eaeb350', '0x1eaec8e0', '0x1eaef380', '0x1eaf19a0', '0x1eaf1e60', '0x1eaf2740', '0x1eaf2e60', '0x1eaf6f20', '0x1eafaf20', '0x1eafd070', '0x1eafe070', '0x1eafebf0', '0x1eb02d10', '0x1eb063e0', '0x1eb09070', '0x1eb0b4e0', '0x1eb0b6b0', '0x1eb0de60', '0x1eb0e070', '0x1eb0f5e0', '0x1eb104c0', '0x1eb122a0', '0x1eb123f0', '0x1eb12600', '0x1eb14280', '0x1eb144a0', '0x1eb15380', '0x1eb15e90', '0x1eb18340', '0x1eb198d0', '0x1eb1b070', '0x1eb201a0', '0x1eb23a50', '0x1eb26450', '0x1eb268a0', '0x1eb28aa0', '0x1eb293b0', '0x1eb298d0', '0x1eb2cd00', '0x1eb2d3f0', '0x1eb2fa10', '0x1eb30200', '0x1eb30b20', '0x1eb34180', '0x1eb35b20', '0x1eb36740', '0x1eb36930', '0x1eb37300', '0x1eb37f20', '0x1eb3a5f0', '0x1eb3a740', '0x1eb3abf0', '0x1eb3f490', '0x1eb3fc70', '0x1eb3ff20', '0x1eb44880', '0x1eb45730', '0x1eb47230', '0x1eb47a70', '0x1eb4b3a0', '0x1eb4caa0', '0x1eb4d070', '0x1eb4d300', '0x1eb4e210', '0x1eb4eb20', '0x1eb50070', '0x1eb508d0', '0x1eb50de0', '0x1eb514c0', '0x1eb52260', '0x1eb533b0', '0x1eb53c90', '0x1eb553c0', '0x1eb55970', '0x1eb56070', '0x1eb56250', '0x1eb565e0', '0x1eb56730', '0x1eb57070', '0x1eb57dd0', '0x1eb58c90', '0x1eb59960', '0x1eb59dd0', '0x1eb5a410', '0x1eb5cdc0', '0x1eb5db20', '0x1eb5e230', '0x1eb5f370', '0x1eb602a0', '0x1eb60b30', '0x1eb62290', '0x1eb628c0', '0x1eb65540', '0x1eb66110', '0x1eb66f20', '0x1eb68f20', '0x1eb69750', '0x1eb69d00', '0x1eb6a530', '0x1eb6a8a0', '0x1eb6cab0', '0x1eb6cd20', '0x1eb706b0', '0x1eb718c0', '0x1eb73f20', '0x1eb75740', '0x1eb75d00', '0x1eb76500', '0x1eb772a0', '0x1eb792b0', '0x1eb79a50', '0x1eb7f8e0', '0x1eb81070', '0x1eb81220', '0x1eb81740', '0x1eb83d10', '0x1eb83f20', '0x1eb88880', '0x1eb88b20', '0x1eb89070', '0x1eb8a210', '0x1eb8af20', '0x1eb8b9b0', '0x1eb8c6b0', '0x1eb8de20', '0x1eb8fb00', '0x1eb90ad0', '0x1eb91af0', '0x1eb93730', '0x1eb939d0', '0x1eb93f20', '0x1eb94390', '0x1eb94560', '0x1eb96890', '0x1eb96dc0', '0x1eb97b20', '0x1eb98f20', '0x1eb9b740', '0x1eb9d190', '0x1eb9f680', '0x1eb9fab0', '0x1eba0070', '0x1eba1880', '0x1eba3e60', '0x1eba4e60', '0x1eba5f20', '0x1eba66a0', '0x1eba9bc0', '0x1eba9d10', '0x1ebabc10', '0x1ebaf210', '0x1ebb0f20', '0x1ebb3750', '0x1ebb4070', '0x1ebb55e0', '0x1ebb5bc0', '0x1ebb5d10', '0x1ebb8610', '0x1ebba070', '0x1ebbaac0', '0x1ebbe420', '0x1ebc2070', '0x1ebc2600', '0x1ebc3070', '0x1ebc48f0', '0x1ebc5730', '0x1ebc5c80', '0x1ebc5dd0', '0x1ebc6620', '0x1ebc6f20', '0x1ebc81d0', '0x1ebc86b0', '0x1ebca5f0', '0x1ebcc510', '0x1ebccf20', '0x1ebcf4b0', '0x1ebcf600', '0x1ebcfa20', '0x1ebd25e0', '0x1ebd29a0', '0x1ebd3510', '0x1ebd6330', '0x1ebd7070', '0x1ebd8650', '0x1ebd8880', '0x1ebd9a90', '0x1ebd9c40', '0x1ebdaf20', '0x1ebdbd10', '0x1ebde970', '0x1ebdef20', '0x1ebdfa20', '0x1ebe0490', '0x1ebe05e0', '0x1ebe0f20', '0x1ebe3070', '0x1ebe3980', '0x1ebe8bd0', '0x1ebe8d20', '0x1ebe8f20', '0x1ebea920', '0x1ebecf20', '0x1ebef170', '0x1ebf4070', '0x1ebf8420', '0x1ec23370', '0x1ed7fcd0', '0x1ed7ff20', '0x1ed87dd0', '0x1ed87f20', '0x1ed99d50', '0x1ed9b070', '0x1ed9fd10', '0x1eda3860', '0x1edaa7d0', '0x1edab9e0', '0x1edabd50', '0x1edae350', '0x1edae6c0', '0x1edaf610', '0x1edb4a60', '0x1edb4bb0', '0x1edb4d00', '0x1edb4e50', '0x1edb5700', '0x1edb81d0', '0x1edb83f0', '0x1edba070', '0x1edc0d00', '0x1edc2070', '0x1edc2700', '0x1edc5b80', '0x1edc6070', '0x1edc63d0', '0x1edcaf20', '0x1edd5c10', '0x1edd5d60', '0x1edd64a0', '0x1eddb310', '0x1eddc220', '0x1eddf240', '0x1ede1820', '0x1ede26b0', '0x1ede3b40', '0x1ede4f20', '0x1edff210', '0x1ee962c0', '0x1ef1b960', '0x1ef1c310', '0x1ef1c460', '0x1ef23f20', '0x1ef24f20', '0x1ef275a0', '0x1ef369e0', '0x1ef4f070', '0x1ef4f300', '0x1ef4fd70', '0x1ef52bc0', '0x1ef536e0', '0x1ef53990', '0x1ef582f0', '0x1ef63a30', '0x1efc93d0', '0x1efca5b0', '0x1efcb560', '0x1efd9d50', '0x1efe2f20', '0x1efe64f0', '0x1efe6910', '0x1efe7850', '0x1efebf20', '0x1efee830', '0x1efefb90', '0x1efefe40', '0x1eff0440', '0x1eff0c60', '0x1eff1d40', '0x1eff55f0', '0x1f407e20', '0x1f40cb10', '0x1f40d5e0', '0x1f40df20', '0x1f40e5a0', '0x1f417d50', '0x1f418970', '0x1f418c30', '0x1f419f20', '0x1f41a070', '0x1f4291e0', '0x1f429c30', '0x1f42bab0', '0x1f442f20', '0x1f444070', '0x1f45a9b0', '0x1f471a20', '0x1f471ba0', '0x1f47d970', '0x1f47dc20', '0x1f480750', '0x1f485590', '0x1f6e8140', '0x1f6eb4f0', '0x1f726490', '0x1f726730', '0x1f726d10', '0x1f727660', '0x1f7277b0', '0x1f727f20', '0x1f729d50', '0x1f730d00', '0x1f731ba0', '0x1f7366d0', '0x1f737240', '0x1f737680', '0x1f7395c0', '0x1f740050', '0x1f755bc0', '0x1f761730', '0x1f763070', '0x1f764e40', '0x1f767a20', '0x1f769ac0', '0x1f769dc0', '0x1f76a3f0', '0x1f76a6a0', '0x1f76aac0', '0x1f76adc0', '0x1f76b1a0', '0x1f76b3c0', '0x1f76ba70', '0x1f76cdd0', '0x1f76cf20', '0x1f7738d0', '0x1f779970', '0x1f779c70', '0x1f779f20', '0x1f77a070', '0x1f77a610', '0x1f77a940', '0x1f77abf0', '0x1f77af20', '0x1f77b860', '0x1f78af20', '0x1f78b2d0', '0x1f78d4b0', '0x1f7a0c00', '0x1f7a0dd0', '0x1f7a0f20', '0x1f7a7ac0', '0x1f7ad900', '0x1f7b9070', '0x1f7c2540', '0x1f7c33b0', '0x1f7c39c0', '0x1f7c5760', '0x1f7c58d0', '0x1f7c8d10', '0x1f7ccdd0', '0x1f7df390', '0x1f7df670', '0x1f7eee60', '0x1f7f0bb0', '0x1f7f92a0', '0x1f7f9c20', '0x1f8193b0', '0x1f81bea0', '0x1f821ea0', '0x1f8235b0', '0x1f82b2f0', '0x1f82d3f0', '0x1f82d540', '0x1f82d690', '0x1f82d7e0', '0x1f82d930', '0x1f82da80', '0x1f82dbd0', '0x1f82ff20', '0x1f8372b0', '0x1f837880', '0x1f83b510', '0x1f83d3d0', '0x1f83d520', '0x1f83f520', '0x1f83fa30', '0x1f841340', '0x1f8452d0', '0x1f8475f0', '0x1f847720', '0x1f847850', '0x1f84d6a0', '0x1f84d7d0', '0x1f84df20', '0x1f84f570', '0x1f84ff20', '0x1f853300', '0x1f853590', '0x1f85b320', '0x1f85dc20', '0x1f85f320', '0x1f861320', '0x1f8634c0', '0x1f865990', '0x1f889c10', '0x1f8b5c20', '0x1f8bf870', '0x1f8bfc00', '0x1f8bfd50', '0x1f8bfea0', '0x1f8d32b0', '0x1f8ddac0', '0x1f8dddc0', '0x1f8f1670', '0x1f8fb2b0', '0x1f905410', '0x1f90f140', '0x1f9236d0', '0x1f92d6d0', '0x1f9370f0', '0x1f9376d0', '0x1f941b30', '0x1f9552f0', '0x1f955420', '0x1f969f20', '0x1fa0fb50', '0x1fa0fe20', '0x1fa11f20', '0x1fa4b7d0', '0x1fa4b9e0', '0x1fa4bb30', '0x1fa4bf20', '0x1fa4ca20', '0x1fa533e0', '0x1fa54bd0', '0x1fa55f20', '0x1fb71380', '0x1fb752c0', '0x1fb77d10', '0x1fb7b460', '0x1fb834e0', '0x1fb857e0', '0x1fb8b5e0', '0x1fb8b800', '0x1fb93520', '0x1fb95530', '0x1fb97ba0', '0x1fb99a20', '0x1fb99e20', '0x1fb9da20', '0x1fb9fd40', '0x1fba13e0', '0x1fba1e30', '0x1fba35a0', '0x1fba5ae0', '0x1fba5f20', '0x1fba7df0', '0x1fba7f20', '0x1fba9310', '0x1fba9f20', '0x1fbab380', '0x1fbab7f0', '0x1fbaf530', '0x1fbb33b0', '0x1fbb5a30', '0x1fbb5f20', '0x1fbb7cd0', '0x1fbbb840', '0x1fbbb990', '0x1fbf35c0', '0x1fbfbae0', '0x1fcce270', '0x1fde46d0', '0x1fde4820', '0x1fde4970', '0x1fde5680', '0x1fde5b30', '0x1fde6f20', '0x1fe61070', '0x1fe94b00', '0x1fed1f20', '0x1fed28b0', '0x1fed4900', '0x1ff1b070', '0x1ff1d940', '0x1ff1df20', '0x1ff24f20', '0x1ff2a7d0', '0x1ff2aa40', '0x1ff2b6a0', '0x1ff47f20', '0x1ff71590'],

                'Name' : ['\\ProgramData\\Microsoft\\Windows\\Start Menu', '\\ProgramData\\Microsoft\\Windows\\Start Menu', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Windows\\System32\\mtxoci.dll', '\\Windows\\System32\\msdtcprx.dll', '\\Windows\\System32\\xolehlp.dll', '\\Windows\\System32\\mtxclu.dll', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Windows\\System32\\msdtc.exe', '\\Windows\\System32\\msdtctm.dll', '\\Windows\\System32\\msdtclog.dll', '\\Windows\\System32\\en-US\\msdtc.exe.mui', '\\Windows\\System32', '\\Windows\\System32\\msdtcVSp1res.dll', '\\$Directory', '\\Windows\\System32\\netshell.dll', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Windows\\SysWOW64\\uxtheme.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx', '\\Endpoint', '\\Endpoint', '\\Windows\\System32\\wshbth.dll', '\\$Directory', '\\Windows\\System32\\en-US\\msdtcVSp1res.dll.mui', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Windows\\System32\\Msdtc\\Trace\\dtctrace.log', '\\$Directory', '\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\Updates', '\\Endpoint', '\\Windows\\System32\\AltTab.dll', '\\Windows\\System32\\en-US\\elscore.dll.mui', '\\Windows\\System32', '\\Windows\\System32\\NaturalLanguage6.dll', '\\$Directory', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx', '\\Windows\\System32\\C_1256.NLS', '\\$Directory', '\\$Directory', '\\Windows\\System32\\WPDShServiceObj.dll', '\\Windows\\System32\\PortableDeviceTypes.dll', '\\Windows\\System32\\QUTIL.DLL', '\\Windows\\System32', '\\Windows\\System32\\mssrch.dll', '\\Windows\\System32\\pnidui.dll', '\\Windows\\System32\\esent.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\msidle.dll', '\\Windows\\System32\\mssprxy.dll', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\$Directory', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\PropMap\\CiPT0000.000', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Windows\\System32\\srchadmin.dll', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex\\SystemIndex.2.Crwl', '\\$Directory', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\catroot2\\{127D0A1D-4EF2-11D1-8608-00C04FC295EE}\\catdb', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex\\SystemIndex.2.gthr', '\\Windows\\System32\\en-US\\tquery.dll.mui', '\\Windows\\System32\\oleacc.dll', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb', '\\Windows\\System32\\msshooks.dll', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\SecStore\\CiST0000.000', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\INDEX.000', '\\$Directory', '\\Windows\\Fonts\\sserife.fon', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\00010001.wid', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\00010007.wid', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\00010007.wsb', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\00010001.dir', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\00010001.ci', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\00010007.ci', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Projects\\SystemIndex\\Indexer\\CiFiles\\00010007.dir', '\\MsFteWds', '\\Windows\\System32\\oleaccrc.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\ieframe.dll', '\\Windows\\System32\\config\\TxR\\{016888cc-6c6f-11de-8d1d-001e0bcde3ec}.TxR.1.regtrans-ms', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2\\comctl32.dll', '\\Windows\\System32\\mscoree.dll', '\\Windows\\System32\\NapiNSP.dll', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\tzres.dll', '\\Windows\\System32\\rsaenh.dll', '\\MsFteWds', '\\Windows\\SysWOW64\\mswsock.dll', '\\Windows\\System32\\C_1251.NLS', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Windows\\System32\\pnrpnsp.dll', '\\Windows\\System32\\mssph.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\imapi2.dll', '\\Endpoint', '\\Users\\labib\\AppData\\Local\\Temp\\FXSAPIDebugLogFile.txt', '\\Windows\\System32\\hgcpl.dll', '\\Windows\\System32', '\\browser', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Users\\labib\\Desktop\\taskdl.exe', '\\Windows\\System32\\FntCache.dll', '\\Windows\\System32\\FXSST.dll', '\\Windows\\System32\\mapi32.dll', '\\Windows\\winsxs\\amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.4940_none_88df89932faf0bf6\\msvcr80.dll', '\\Windows\\System32\\en-US\\VSSVC.exe.mui', '\\Windows\\SysWOW64\\msls31.dll', '\\Windows\\System32\\virtdisk.dll', '\\browser', '\\browser', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\wwapi.dll', '\\Windows\\winsxs\\amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.4940_none_88df89932faf0bf6', '\\Windows\\SysWOW64\\imm32.dll', '\\Program Files\\Windows Sidebar\\en-US\\sbdrop.dll.mui', '\\lsass', '\\Windows\\System32\\browcli.dll', '\\Windows\\System32\\perfos.dll', '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Windows\\WindowsUpdate.log', '\\System Volume Information\\Syscache.hve.LOG1', '\\Windows\\System32\\sppobjs.dll', '\\Windows\\System32\\NlsData000c.dll', '\\Windows\\System32\\NlsLexicons0416.dll', '\\Windows\\System32\\NlsData0416.dll', '\\System Volume Information\\Syscache.hve.LOG2', '\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\CORPerfMonExt.dll', '\\Windows\\System32\\fltLib.dll', '\\Windows\\System32\\winmm.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_2b24536c71ed437a', '\\Windows\\System32\\snmpapi.dll', '\\Windows\\System32\\wsnmp32.dll', '\\Windows\\System32\\dxgi.dll', '\\Windows\\System32\\api-ms-win-core-processthreads-l1-1-1.dll', '\\Windows\\System32\\api-ms-win-core-file-l2-1-0.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\msacm32.drv', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Application-Experience%4Program-Compatibility-Assistant.evtx', '\\Windows\\System32\\api-ms-win-core-synch-l1-2-0.dll', '\\Windows\\System32\\api-ms-win-crt-string-l1-1-0.dll', '\\Windows\\System32\\EhStorShell.dll', '\\Windows\\Registration\\R000000000006.clb', '\\MsFteWds', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Application-Experience%4Program-Telemetry.evtx', '\\Windows\\Fonts\\cour.ttf', '\\ProgramData\\Microsoft\\Windows\\Caches\\{40FC8D7D-05ED-4FEB-B03B-6C100659EF5C}.2.ver0x0000000000000001.db', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\NlsData000a.dll', '\\Windows\\System32\\en-US\\gameux.dll.mui', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Application-Experience%4Program-Compatibility-Troubleshooter.evtx', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Application-Experience%4Program-Inventory.evtx', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Application-Experience%4Problem-Steps-Recorder.evtx', '\\Windows\\System32\\api-ms-win-crt-convert-l1-1-0.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx', '\\Windows\\System32\\ntshrui.dll', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Windows\\System32\\cscapi.dll', '\\Windows\\System32\\api-ms-win-crt-stdio-l1-1-0.dll', '\\$Directory', '\\Windows\\System32\\api-ms-win-crt-math-l1-1-0.dll', '\\Windows\\System32\\IconCodecService.dll', '\\Windows\\System32\\msxml6r.dll', '\\Windows\\System32\\C_1258.NLS', '\\Windows\\System32\\api-ms-win-crt-locale-l1-1-0.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-International%4Operational.evtx', '\\Windows\\System32\\WSDMon.dll', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\glib-2.0.dll', '\\Windows\\System32\\usbmon.dll', '\\Windows\\System32\\WSDApi.dll', '\\Windows\\System32', '\\Windows\\System32\\fundisc.dll', '\\Windows\\System32\\webservices.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.7600.16385_en-us_106f9be843a9b4e3\\comctl32.dll.mui', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\Fonts\\StaticCache.dat', '\\Windows\\System32\\timedate.cpl', '\\Windows\\winsxs\\amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.7600.16385_en-us_106f9be843a9b4e3', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\libxmlsec-openssl.dll', '\\Windows\\System32\\actxprxy.dll', '\\$Directory', '\\Users\\labib\\AppData\\Local\\Temp\\46.WNCRYTows\\Caches\\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000002.db', '\\Program Files\\VMware\\VMware Tools\\intl.dll', '\\Windows\\System32\\wbem\\WmiPrvSE.exe', '\\$Directory', '\\Windows\\System32', '\\Windows\\SysWOW64\\msvcp60.dll', '\\Windows\\Temp\\vmware-vmsvc-SYSTEM.log', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Windows\\System32\\imm32.dll', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Windows\\System32\\nci.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Diagnosis-Scheduled%4Operational.evtx', '\\Windows\\System32\\mfc140enu.dll', '\\$Directory', '\\Windows\\System32\\gameux.dll', '\\Windows\\System32\\wbem\\cimwin32.dll', '\\MsFteWds', '\\Windows\\System32', '\\Program Files\\VMware\\VMware Tools\\vmtools.dll', '\\Windows\\System32\\msls31.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\Fonts\\StaticCache.dat', '\\Windows\\System32\\wbem\\wbemess.dll', '\\Program Files\\VMware\\VMware Tools\\hgfs.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\common\\hgfsServer.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\common\\vix.dll', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Program Files\\VMware\\VMware Tools\\plugins\\common\\hgfsUsability.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\autoUpgrade.dll', '\\$Directory', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\autoLogon.dll', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmusr\\darkModeSync.dll', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Windows\\System32\\networkexplorer.dll', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\deployPkgPlugin.dll', '\\$Directory', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmusr\\unity.dll', '\\Windows\\System32\\msvcp140.dll', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Recent', '\\$Directory', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Windows\\System32\\wbemcomn.dll', '\\$Directory', '\\Windows\\System32\\wbem\\MOF', '\\Program Files\\VMware\\VMware Tools\\ssleay32.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmusr\\desktopEvents.dll', '\\Program Files\\VMware\\VMware Tools\\deployPkg.dll', '\\Program Files\\VMware\\VMware Tools\\libeay32.dll', '\\Windows\\System32\\wbem\\WmiDcPrv.dll', '\\Windows\\System32\\wbem\\WinMgmtR.dll', '\\Windows\\System32\\wdscore.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmusr\\dndcp.dll', '\\Windows\\System32\\netcfgx.dll', '\\Windows\\System32\\wbem\\wbemprox.dll', '\\Program Files\\VMware\\VMware Tools\\sigc-2.0.dll', '\\Windows\\System32\\wbem\\fastprox.dll', '\\Windows\\System32\\C_1250.NLS', '\\Windows\\System32\\ksuser.dll', '\\Windows\\System32\\NlsLexicons0009.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_5.82.7601.17514_none_a4d6a923711520a9', '\\Windows\\System32\\SearchFolder.dll', '\\Windows\\SysWOW64\\propsys.dll', '\\Windows\\System32\\ntdsapi.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\wdmaud.drv', '\\Windows\\System32\\wbem\\esscli.dll', '\\$Directory', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\guestInfo.dll', '\\Windows\\System32\\sscore.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\vmbackup.dll', '\\Windows\\System32\\en-US\\MMDevAPI.dll.mui', '\\Windows\\System32\\wbem\\wbemsvc.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\powerOps.dll', '\\vgauth-service', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\diskWiper.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmusr\\vmtray.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\hwUpgradeHelper.dll', '\\Windows\\System32\\AudioSes.dll', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\timeSync.dll', '\\Windows\\System32\\en-US\\conhost.exe.mui', '\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '\\Windows\\System32\\api-ms-win-crt-multibyte-l1-1-0.dll', '\\Windows\\System32\\ActionCenter.dll', '\\Windows\\System32\\wbem\\wmiutils.dll', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\tmp.edb', '\\', '\\Windows\\System32\\wbem\\repdrvfs.dll', '\\Windows\\System32\\utildll.dll', '\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA', '\\Windows\\System32\\wercplsupport.dll', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\MSStmp.log', '\\Windows\\System32\\en-US\\SyncCenter.dll.mui', '\\Windows\\System32\\SyncCenter.dll', '\\Windows\\System32\\wbem\\Repository\\MAPPING3.MAP', '\\Windows\\System32', '\\$Directory', '\\Windows\\System32\\wbem\\Repository\\MAPPING2.MAP', '\\Windows\\System32\\wbem\\Repository\\INDEX.BTR', '\\Windows\\System32\\wbem\\Repository\\MAPPING1.MAP', '\\', '\\srvsvc', '\\Endpoint', '\\Endpoint', '\\Winsock2\\CatalogChangeListener-1e8-0', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Windows\\System32\\SearchProtocolHost.exe', '\\Windows\\System32\\winrnr.dll', '\\Endpoint', '\\Endpoint', '\\Windows\\SysWOW64\\WSHTCPIP.DLL', '\\Windows\\System32\\npmproxy.dll', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Windows\\System32', '\\Windows\\System32\\wbem\\WmiPerfClass.dll', '\\Windows\\System32\\dimsjob.dll', '\\Windows\\System32\\shfolder.dll', '\\Windows\\SysWOW64\\ntmarta.dll', '\\Windows', '\\Windows\\System32\\pnpts.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Resource-Exhaustion-Detector%4Operational.evtx', '\\Windows\\System32', '\\Windows\\System32\\perftrack.dll', '\\Windows\\System32\\radardt.dll', '\\Windows\\Registration\\{02D4B3F1-FD88-11D1-960D-00805FC79235}.{A2DB3B73-28DE-4843-BC55-8D74714591D5}.crmlog', '\\Windows\\System32\\wdiasqmmodule.dll', '\\Windows\\System32\\framedynos.dll', '\\Windows\\System32\\txflog.dll', '\\Windows\\System32\\wlanutil.dll', '\\Windows\\System32\\wlanapi.dll', '\\Windows', '\\$Directory', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\$Directory', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-NetworkAccessProtection%4Operational.evtx', '\\Windows\\System32\\QAGENT.DLL', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-NetworkProfile%4Operational.evtx', '\\Windows\\SysWOW64\\dwmapi.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\SysWOW64\\apphelp.dll', '\\Program Files\\Windows Sidebar\\sbdrop.dll', '\\Windows\\Fonts\\StaticCache.dat', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Users\\labib\\Desktop\\TaskData\\Tor\\zlib1.dll', '\\Windows\\System32\\catsrvut.dll', '\\Endpoint', '\\Endpoint', '\\Windows\\System32\\DXP.dll', '\\Windows\\System32\\catroot2\\edb.log', '\\Windows\\Fonts\\StaticCache.dat', '\\Winsock2\\CatalogChangeListener-1f0-0', '\\Windows\\System32\\comsvcs.dll', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\Msdtc\\MSDTC.LOG', '\\Windows\\System32\\stdole2.tlb', '\\Windows\\Fonts\\segoeuib.ttf', '\\Windows\\System32\\C_1253.NLS', '\\Windows\\System32\\en-US\\gameux.dll.mui', '\\Windows\\System32\\appinfo.dll', '\\Endpoint', '\\Windows\\System32\\batmeter.dll', '\\Windows\\System32\\C_1254.NLS', '\\Windows\\SysWOW64\\riched32.dll', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned', '\\$Directory', '\\Winsock2\\CatalogChangeListener-2a4-0', '\\Endpoint', '\\Endpoint', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\Burn', '\\Endpoint', '\\Windows\\System32\\WSHTCPIP.DLL', '\\ProgramData\\Microsoft\\Windows\\Caches\\{DDF571F2-BE98-426D-8288-1A9A39C3FDA2}.2.ver0x0000000000000002.db', '\\Endpoint', '\\Endpoint', '\\ProgramData\\VMware\\VMware VGAuth\\logfile.txt.0', '\\Endpoint', '\\Windows\\System32\\EhStorAPI.dll', '\\Endpoint', '\\Endpoint', '\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf', '\\Endpoint', '\\Endpoint', '\\Windows\\Fonts\\StaticCache.dat', '\\$Directory', '\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe', '\\Endpoint', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libeay32.dll', '\\Endpoint', '\\Endpoint', '\\Winsock2\\CatalogChangeListener-17c-0', '\\wkssvc', '\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT.LOG2', '\\Windows', '\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT.LOG1', '\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT', '\\LSM_API_service', '\\LSM_API_service', '\\epmapper', '\\epmapper', '\\epmapper', '\\LSM_API_service', '\\Windows\\System32\\version.dll', '\\Windows\\System32', '\\Windows\\System32\\sqmapi.dll', '\\wkssvc', '\\Windows\\System32', '\\Program Files\\VMware\\VMware Tools\\VMToolsHook64.dll', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\Burn', '\\Windows\\System32\\shdocvw.dll', '\\Windows\\System32\\FXSAPI.dll', '\\Windows\\System32\\wiarpc.dll', '\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms', '\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\ssleay32.dll', '\\Windows\\System32\\aelupsvc.dll', '\\Windows\\System32\\wfapigp.dll', '\\Endpoint', '\\Windows\\Registration\\R000000000006.clb', '\\Device\\HarddiskVolume1\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\$ConvertToNonresident', '\\Windows\\System32\\rasadhlp.dll', '\\Windows\\System32\\wscinterop.dll', '\\$Directory', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\$Directory', '\\Windows\\System32\\config\\TxR\\{016888cc-6c6f-11de-8d1d-001e0bcde3ec}.TxR.2.regtrans-ms', '\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{D2B0B133-42ED-44D3-809A-46EBB62BA863}\\mpengine.dll', '\\Windows\\System32\\cryptui.dll', '\\Windows\\System32\\winevt\\Logs\\Application.evtx', '\\eventlog', '\\Windows\\System32\\authui.dll', '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\lastalive0.dat', '\\eventlog', '\\Windows\\System32\\wbem\\ntevt.dll', '\\Windows\\Fonts\\cambriab.ttf', '\\Windows\\System32', '\\Program Files\\Windows Defender\\MpSvc.dll', '\\Endpoint', '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\lastalive1.dat', '\\Windows\\WindowsShell.Manifest', '\\MsFteWds', '\\Windows\\System32\\MMDevAPI.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac\\comctl32.dll', '\\Windows\\System32\\PortableDeviceApi.dll', '\\$Directory', '\\Windows\\System32\\avrt.dll', '\\Endpoint', '\\Endpoint', '\\Windows\\System32\\winevt\\Logs\\System.evtx', '\\Windows\\System32\\msxml6.dll', '\\Windows\\System32\\winevt\\Logs\\Security.evtx', '\\$PrepareToShrinkFileSize', '\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx', '\\$PrepareToShrinkFileSize', '\\Windows\\System32\\winevt\\Logs\\HardwareEvents.evtx', '\\Windows\\System32\\winevt\\Logs\\Internet Explorer.evtx', '\\Windows\\System32\\shacct.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-User Profile Service%4Operational.evtx', '\\Windows\\Registration\\R000000000006.clb', '\\Program Files\\Internet Explorer\\ieproxy.dll', '\\Endpoint', '\\Windows\\System32\\winevt\\Logs\\Key Management Service.evtx', '\\Windows\\System32\\propsys.dll', '\\Windows\\System32\\en-US\\bthprops.cpl.mui', '\\Windows\\Registration\\R000000000006.clb', '\\elineouttopo', '\\emicintopo', '\\Windows\\System32\\ntmarta.dll', '\\Windows\\System32\\wer.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-Power%4Thermal-Operational.evtx', '\\Windows\\SysWOW64\\profapi.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-WHEA%4Operational.evtx', '\\elineouttopo', '\\$ConvertToNonresident', '\\Windows\\System32\\samlib.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-WHEA%4Errors.evtx', '\\Windows\\Registration\\R000000000006.clb', '\\emicinwave', '\\elineoutwave', '\\emicintopo', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-NlaSvc%4Operational.evtx', '\\Windows\\System32\\dsrole.dll', '\\Windows\\System32\\uxtheme.dll', '\\Windows\\System32\\gpsvc.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\atl.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_2b24536c71ed437a\\GdiPlus.dll', '\\Windows\\System32\\dui70.dll', '\\Windows\\System32\\nlaapi.dll', '\\Windows\\System32', '\\Windows\\System32\\es.dll', '\\Windows\\System32\\slc.dll', '\\lsass', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\SndVolSSO.dll', '\\Windows\\System32\\duser.dll', '\\Windows\\System32\\hid.dll', '\\Windows\\System32\\dwmapi.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Diagnosis-DPS%4Operational.evtx', '\\Windows\\System32\\uxsms.dll', '\\Windows\\System32\\xmllite.dll', '\\Windows\\System32\\wtsapi32.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-NCSI%4Operational.evtx', '\\Windows\\System32\\ncobjapi.dll', '\\Windows\\System32\\imageres.dll', '\\Windows\\System32\\WindowsCodecs.dll', '\\Windows\\System32\\winbrand.dll', '\\Windows\\System32', '\\Windows\\System32\\dnsrslvr.dll', '\\$Directory', '\\Windows\\System32\\IPHLPAPI.DLL', '\\Windows\\System32\\nrpsrv.dll', '\\Windows\\System32\\wow64win.dll', '\\Windows\\System32\\winnsi.dll', '\\Windows\\System32\\netutils.dll', '\\Windows\\System32\\credui.dll', '\\Windows\\System32\\wkscli.dll', '\\Windows\\System32\\dhcpcore6.dll', '\\Windows\\System32\\samcli.dll', '\\Windows\\System32\\FWPUCLNT.DLL', '\\Windows\\System32\\rtutils.dll', '\\Windows\\System32\\rasman.dll', '\\Windows\\System32\\rasapi32.dll', '\\Windows\\System32\\dnsext.dll', '\\Windows\\System32\\drivers\\etc', '\\Windows\\System32\\dhcpcsvc6.dll', '\\Endpoint', '\\Windows\\Fonts\\StaticCache.dat', '\\Windows\\System32\\dhcpcsvc.dll', '\\Endpoint', '\\Windows\\System32\\taskcomp.dll', '\\Windows\\Tasks\\SCHEDLGU.TXT', '\\Windows\\System32\\en-US\\duser.dll.mui', '\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\catroot2\\edb.log', '\\Windows\\System32\\ktmw32.dll', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Windows\\System32\\UXInit.dll', '\\Windows\\System32\\fveapi.dll', '\\Windows\\System32\\tbs.dll', '\\Windows\\System32\\fvecerts.dll', '\\atsvc', '\\Endpoint', '\\Windows\\System32\\diagperf.dll', '\\Windows\\System32', '\\Program Files\\VMware\\VMware Tools\\gobject-2.0.dll', '\\PIPE_EVENTROOT\\CIMV2SCM EVENT PROVIDER', '\\Windows\\System32\\msftedit.dll', '\\$Directory', '\\Windows\\System32\\en-US\\KernelBase.dll.mui', '\\Windows\\System32\\ssdpapi.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\sfc.dll', '\\Windows\\System32\\spoolss.dll', '\\Windows\\Fonts\\times.ttf', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Program Files\\Windows Defender\\MpRTP.dll', '\\Windows\\System32\\spool\\prtprocs\\x64\\winprint.dll', '\\Windows\\System32\\vcruntime140.dll', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Windows\\SysWOW64\\rsaenh.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\ssleay32.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\$Directory', '\\Windows\\Temp\\vmware-vmusr-labib.log', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libssp-0.dll', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\libeay32.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\taskhsvc.exe', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\WER\\ERC', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\intl.dll', '\\Windows\\System32\\win32spl.dll', '\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '\\Users\\labib\\Desktop\\00000000.eky', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\pcre.dll', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\srvsvc', '\\Windows\\Fonts\\segoeuii.ttf', '\\Windows\\System32', '\\Windows\\System32\\elslad.dll', '\\Windows\\System32\\Apphlpdm.dll', '\\Windows\\System32\\en-US\\wdmaud.drv.mui', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Admin.evtx', '\\Windows\\System32\\PrintIsolationProxy.dll', '\\Windows\\explorer.exe', '\\Users\\labib\\Desktop\\WannaCry.EXE', '\\wkssvc', '\\Windows\\System32', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-NetworkAccessProtection%4WHC.evtx', '\\$Directory', '\\trkwks', '\\trkwks', '\\trkwks', '\\Windows\\System32\\en-US\\SyncCenter.dll.mui', '\\System Volume Information\\tracking.log', '\\$Extend\\$ObjId', '\\Windows\\System32\\FXSMON.dll', '\\$Directory', '\\Windows\\System32\\dwmredir.dll', '\\$Directory', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2', '\\Windows\\System32\\en-US\\hgcpl.dll.mui', '\\Windows\\System32\\fdPnp.dll', '\\Windows\\System32\\wuaueng.dll', '\\Windows\\System32\\ELSCore.dll', '\\Windows\\System32\\tcpmon.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-StoreMgr%4Operational.evtx', '\\Windows\\System32\\dwmcore.dll', '\\Windows\\System32', '\\Windows\\System32\\api-ms-win-crt-runtime-l1-1-0.dll', '\\Windows\\System32\\ucrtbase.dll', '\\Windows\\System32\\ExplorerFrame.dll', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libevent-2-0-5.dll', '\\Windows\\System32', '\\Windows\\System32\\d3d10_1.dll', '\\Windows\\System32\\cabinet.dll', '\\Windows\\System32\\d3d10_1core.dll', '\\$Directory', '\\Windows\\System32\\sxs.dll', '\\Windows\\Fonts\\micross.ttf', '\\Windows\\Fonts\\tahoma.ttf', '\\Windows\\System32\\cryptsvc.dll', '\\Windows\\System32\\wbem\\WmiPerfInst.dll', '\\Windows\\Fonts\\segoeui.ttf', '\\Windows\\System32\\en-US\\oleaccrc.dll.mui', '\\Windows\\System32\\cryptsp.dll', '\\Windows\\System32\\api-ms-win-core-timezone-l1-1-0.dll', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Windows\\Fonts\\marlett.ttf', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\midimap.dll', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Libraries', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Libraries', '\\Windows\\System32\\wbem\\WmiPrvSD.dll', '\\Windows\\System32\\comsvcs.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\msacm32.dll', '\\Windows\\System32\\resutils.dll', '\\Endpoint', '\\Device\\HarddiskVolume1\\Windows\\ServiceProfiles\\LocalService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\$Directory', '\\Program Files\\Windows Defender\\MpClient.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4WHC.evtx', '\\$Directory', '\\Windows\\Globalization\\Sorting\\SortDefault.nls', '\\InitShutdown', '\\InitShutdown', '\\Windows\\System32\\WlS0WndH.dll', '\\InitShutdown', '\\Windows\\System32\\wdigest.dll', '\\$Directory', '\\Windows\\System32\\services.exe', '\\MsFteWds', '\\Windows\\System32\\sspicli.dll', '\\Windows\\System32\\hcproviders.dll', '\\wkssvc', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportArchive', '\\Windows\\System32\\cryptbase.dll', '\\Windows\\System32\\wmsgapi.dll', '\\Windows\\System32\\lsass.exe', '\\Windows\\System32', '\\Windows\\System32\\wevtsvc.dll', '\\Windows\\System32\\apphelp.dll', '\\Windows\\System32\\lsm.exe', '\\Windows\\System32', '\\Windows\\System32\\sysntfy.dll', '\\Windows\\System32\\lsasrv.dll', '\\Windows\\System32', '\\Windows\\System32\\C_28591.NLS', '\\Windows\\System32\\scext.dll', '\\Windows\\System32\\sspisrv.dll', '\\Windows\\System32\\scesrv.dll', '\\Windows\\System32\\FXSRESM.dll', '\\Windows\\System32\\secur32.dll', '\\Windows\\System32\\api-ms-win-core-localization-l1-2-0.dll', '\\Windows\\System32\\srvcli.dll', '\\Windows\\System32\\tquery.dll', '\\Windows\\System32\\en-US\\ipconfig.exe.mui', '\\Winsock2\\CatalogChangeListener-2fc-0', '\\eventlog', '\\Windows\\System32\\api-ms-win-crt-filesystem-l1-1-0.dll', '\\Windows\\System32\\PlaySndSrv.dll', '\\Windows\\System32\\samsrv.dll', '\\Windows\\System32\\cryptdll.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\resolutionSet.dll', '\\Windows\\System32\\wevtapi.dll', '\\Windows\\System32\\clusapi.dll', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\libxml2.dll', '\\Windows\\System32\\audiosrv.dll', '\\Windows\\System32', '\\Windows\\winsxs\\amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.7600.16385_en-us_106f9be843a9b4e3\\comctl32.dll.mui', '\\Endpoint', '\\atsvc', '\\Windows\\Tasks', '\\Windows\\System32\\NlsLexicons002a.dll', '\\Windows\\System32\\BFE.DLL', '\\Windows\\System32\\cngaudit.dll', '\\Windows\\System32\\config\\SECURITY.LOG1', '\\Windows\\System32\\authz.dll', '\\Windows\\System32\\umb.dll', '\\Windows\\System32\\bcrypt.dll', '\\Windows\\System32\\ncrypt.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\config\\SECURITY.LOG2', '\\srvsvc', '\\Windows\\System32\\SensApi.dll', '\\Windows\\System32\\config\\SECURITY', '\\Windows\\System32\\msprivs.dll', '\\Windows\\System32\\browser.dll', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\index.dat', '\\Windows\\System32\\mpr.dll', '\\Windows\\System32\\netprofm.dll', '\\Windows\\System32\\config\\RegBack\\SECURITY', '\\Endpoint', '\\Endpoint', '\\Windows\\System32\\netapi32.dll', '\\atsvc', '\\Windows\\System32\\bthserv.dll', '\\Windows\\System32\\pcasvc.dll', '\\Windows\\System32\\nlasvc.dll', '\\Windows\\System32\\taskmgr.exe', '\\Endpoint', '\\Windows\\System32\\wscui.cpl', '\\Windows\\System32\\NlsData0021.dll', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WindowsBackup%4ActionCenter.evtx', '\\Windows\\System32\\netman.dll', '\\Windows\\System32\\netjoin.dll', '\\Windows\\System32\\comres.dll', '\\Windows\\System32\\nsisvc.dll', '\\Users\\labib\\ntuser.dat.LOG1', '\\Windows\\System32\\pdh.dll', '\\Users\\labib\\ntuser.dat.LOG2', '\\Users\\labib\\NTUSER.DAT', '\\Windows\\System32\\negoexts.dll', '\\Windows\\System32\\dnsapi.dll', '\\Windows\\System32\\en-US\\duser.dll.mui', '\\Windows\\System32', '\\Windows\\System32\\wow64cpu.dll', '\\Windows\\System32\\trkwks.dll', '\\Windows\\System32\\msvcirt.dll', '\\Windows\\System32\\provthrd.dll', '\\Windows\\System32\\tdh.dll', '\\Windows\\System32\\SPInf.dll', '\\Windows\\System32\\devrtl.dll', '\\Windows\\System32\\wship6.dll', '\\$Directory', '\\Windows\\System32\\dhcpcore.dll', '\\Users\\labib\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms', '\\Windows\\Fonts\\arialbd.ttf', '\\Windows\\System32\\en-US\\wuaueng.dll.mui', '\\Windows\\debug\\PASSWD.LOG', '\\Windows\\System32\\logoncli.dll', '\\Windows\\System32\\netlogon.dll', '\\Users\\labib\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf', '\\Windows\\System32\\schannel.dll', '\\Device\\HarddiskVolume1\\Users\\labib\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\Windows\\System32\\dps.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Users\\labib\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms', '\\Windows\\System32\\rsaenh.dll', '\\Windows\\System32\\pku2u.dll', '\\Windows\\System32\\TSpkg.dll', '\\lsass', '\\Windows\\System32\\bcryptprimitives.dll', '\\Windows\\System32\\en-US\\searchfolder.dll.mui', '\\Windows\\System32\\api-ms-win-crt-process-l1-1-0.dll', '\\Windows\\System32\\en-US\\netshell.dll.mui', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2', '\\Windows\\System32\\efslsaext.dll', '\\Windows\\SysWOW64\\riched20.dll', '\\Windows\\System32\\credssp.dll', '\\protected_storage', '\\Windows\\System32\\sppwinob.dll', '\\Endpoint', '\\Device\\HarddiskVolume1\\Users\\labib\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\protected_storage', '\\protected_storage', '\\Windows\\System32\\config\\SAM', '\\Windows\\System32\\config\\SAM.LOG2', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\index.dat', '\\Windows\\System32\\ncsi.dll', '\\Windows\\System32\\scecli.dll', '\\Windows\\System32\\config\\SAM.LOG1', '\\Windows\\System32\\config\\RegBack\\SAM', '\\Windows\\System32', '\\Windows\\System32\\gpapi.dll', '\\Windows\\System32\\en-US\\srchadmin.dll.mui', '\\Windows\\System32\\NlsLexicons0021.dll', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\StructuredQuery.dll', '\\Windows\\System32\\provsvc.dll', '\\$Directory', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat{bc91da41-7091-11eb-9781-e82a44f3ec6c}.TMContainer00000000000000000002.regtrans-ms', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat{bc91da41-7091-11eb-9781-e82a44f3ec6c}.TMContainer00000000000000000001.regtrans-ms', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\Users\\labib\\AppData\\Local\\Temp\\hibsys.WNCRYT', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\api-ms-win-crt-conio-l1-1-0.dll', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat', '\\Windows\\System32\\config\\TxR\\{016888cc-6c6f-11de-8d1d-001e0bcde3ec}.TxR.blf', '\\srvsvc', '\\$Directory', '\\Windows\\SoftwareDistribution\\ReportingEvents.log', '\\Windows\\System32\\C_1257.NLS', '\\Windows\\System32\\aepic.dll', '\\Windows\\System32\\vsstrace.dll', '\\$Directory', '\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat{bc91da41-7091-11eb-9781-e82a44f3ec6c}.TM.blf', '\\Windows\\System32\\localspl.dll', '\\ProgramData\\Microsoft\\Windows Defender\\IMpService925A3ACA-C353-458A-AC8D-A7E5EB378092.lock', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Credentials', '\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\CacheManager\\MpSfc.bin', '\\Windows\\System32\\wfp\\wfpdiag.etl', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe', '\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My', '\\$Directory', '\\$ConvertToNonresident', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Endpoint', '\\Windows\\System32\\C_949.NLS', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Diagnostics-Performance%4Operational.evtx', '\\Users\\labib\\Desktop\\TaskData\\Tor\\libgcc_s_sjlj-1.dll', '\\Windows\\System32\\wkssvc.dll', '\\Windows\\Fonts\\StaticCache.dat', '\\Windows\\System32\\iphlpsvc.dll', '\\$Directory', '\\Windows\\System32\\srvsvc.dll', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-07132009-221054.log', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-GroupPolicy%4Operational.evtx', '\\Users\\labib\\Desktop', '\\Windows\\System32\\inetpp.dll', '\\Windows\\System32\\webio.dll', '\\Windows\\System32\\lmhsvc.dll', '\\Windows\\System32\\api-ms-win-crt-environment-l1-1-0.dll', '\\Endpoint', '\\Windows\\System32\\en-US\\FirewallAPI.dll.mui', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\wuapi.dll', '\\Windows\\System32\\en-US\\MMDevAPI.dll.mui', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\umpo.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\SysWOW64\\cryptsp.dll', '\\Windows\\System32\\config\\TxR\\{016888cc-6c6f-11de-8d1d-001e0bcde3ec}.TxR.0.regtrans-ms', '\\Windows\\System32\\profsvc.dll', '\\$Directory', '\\Windows\\System32', '\\$Directory', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Endpoint', '\\$Directory', '\\Windows\\System32\\werconcpl.dll', '\\Windows\\System32\\wbem\\wbemcore.dll', '\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTMsMpPsSession7.etl', '\\Device\\HarddiskVolume1\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat{bc91da41-7091-11eb-9781-e82a44f3ec6c}.TM', '\\Device\\HarddiskVolume1\\Users\\labib\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat{bc91da41-7091-11eb-9781-e82a44f3ec6c}.TM', '\\Users\\labib\\AppData\\Local\\Microsoft\\Credentials', '\\Endpoint', '\\$Directory', '\\Windows\\System32\\api-ms-win-crt-heap-l1-1-0.dll', '\\Windows\\System32\\api-ms-win-core-file-l1-2-0.dll', '\\Users\\labib\\AppData\\Local\\Temp\\47.WNCRYTows\\Explorer\\thumbcache_256.db', '\\Windows\\System32\\mfc140u.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\RpcEpMap.dll', '\\Windows\\System32\\7B296FB0-376B-497e-B012-9C450E1B7327-5P-0.C7483456-A289-439d-8115-601632D005A0', '\\$Directory', '\\Windows\\System32\\taskschd.dll', '\\Windows\\System32\\HotStartUserAgent.dll', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2', '\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\libxmlsec.dll', '\\Windows\\System32\\schedsvc.dll', '\\$Directory', '\\Windows\\System32\\dllhost.exe', '\\Windows\\System32\\UIAnimation.dll', '\\Windows\\System32\\Sens.dll', '\\Windows\\System32\\NlsData0000.dll', '\\Windows\\System32\\shsvcs.dll', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\index.dat', '\\Windows\\System32\\7B296FB0-376B-497e-B012-9C450E1B7327-5P-1.C7483456-A289-439d-8115-601632D005A0', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\$Directory', '\\Windows\\System32\\mspatcha.dll', '\\Windows\\System32\\spoolsv.exe', '\\Program Files\\VMware\\VMware Tools\\suspend-vm-default.bat', '\\Windows\\Fonts', '\\Windows\\System32\\themeservice.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Program Files\\VMware\\VMware Tools\\pcre.dll', '\\Users\\labib\\AppData\\Local\\Temp\\48.WNCRYTows\\Explorer\\thumbcache_32.db', '\\Windows\\System32\\dwm.exe', '\\Windows\\System32\\dssenh.dll', '\\ProgramData\\Microsoft\\Windows\\Caches\\cversions.2.db', '\\keysvc', '\\$Directory', '\\Windows\\System32\\wdi.dll', '\\Windows\\System32\\schedcli.dll', '\\Windows\\System32\\winhttp.dll', '\\Users\\labib\\Desktop', '\\Windows\\System32\\en-US\\cmd.exe.mui', '\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', '\\Windows\\System32\\security.dll', '\\$Directory', '\\$ConvertToNonresident', '\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', '\\$Directory', '\\Windows\\System32\\wbem\\WMIsvc.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.7600.16385_en-us_106f9be843a9b4e3', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_5.82.7601.17514_none_a4d6a923711520a9\\comctl32.dll', '\\SystemRoot\\System32\\Config\\TxR\\{016888cc-6c6f-11de-8d1d-001e0bcde3ec}.TxR', '\\$Directory', '\\Users\\labib\\Desktop', '\\Users\\labib\\Desktop', '\\Windows\\SysWOW64\\mfc42.dll', '\\Windows\\SysWOW64\\winnsi.dll', '\\Users\\labib\\Desktop', '\\Windows\\WindowsUpdate.log', '\\keysvc', '\\$Directory', '\\keysvc', '\\Windows\\System32\\SearchIndexer.exe', '\\Users\\Public\\Desktop', '\\ntsvcs', '\\scerpc', '\\ntsvcs', '\\ntsvcs', '\\$PrepareToShrinkFileSize', '\\scerpc', '\\scerpc', '\\Windows\\System32\\wscapi.dll', '\\Windows\\System32\\PortableDeviceConnectApi.dll', '\\Windows\\System32\\ubpm.dll', '\\Windows\\System32\\vsocklib.dll', '\\$Directory', '\\Windows\\System32\\MPSSVC.dll', '\\Windows\\System32', '\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\MSS.log', '\\$Directory', '\\ProgramData\\Microsoft\\Windows\\Caches\\{6AF0698E-D558-4F6E-9B3C-3716689AF493}.2.ver0x000000000000000a.db', '\\Windows\\System32\\svchost.exe', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Dhcp-Client%4Admin.evtx', '\\Users\\Public\\Desktop', '\\Windows\\System32\\linkinfo.dll', '\\Windows\\System32\\dbghelp.dll', '\\plugplay', '\\Windows\\System32\\VSSVC.exe', '\\plugplay', '\\plugplay', '\\Windows\\System32\\NlsLexicons000a.dll', '\\Windows\\System32\\userenv.dll', '\\Windows\\System32\\en-US\\FirewallAPI.dll.mui', '\\Windows\\System32', '\\Windows\\System32\\msutb.dll', '\\Windows\\System32\\taskhost.exe', '\\$ConvertToNonresident', '\\Program Files\\VMware\\VMware Tools\\glib-2.0.dll', '\\Program Files\\VMware\\VMware Tools\\gmodule-2.0.dll', '\\Windows\\System32\\pcwum.dll', '\\Windows\\System32\\vssapi.dll', '\\Windows\\System32\\powrprof.dll', '\\Windows\\System32\\MsCtfMonitor.dll', '\\Windows\\System32\\en-US\\lsm.exe.mui', '\\Windows\\System32\\catroot2\\{127D0A1D-4EF2-11D1-8608-00C04FC295EE}\\catdb', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\System Volume Information\\Syscache.hve', '\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms', '\\Windows\\System32', '\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT', '\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT.LOG1', '\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT.LOG2', '\\$Directory', '\\Windows\\System32\\rpcss.dll', '\\Windows\\System32\\api-ms-win-crt-time-l1-1-0.dll', '\\Windows\\System32\\stdole2.tlb', '\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms', '\\Windows\\System32\\en-US\\wdmaud.drv.mui', '\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Dhcpv6-Client%4Admin.evtx', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Winlogon%4Operational.evtx', '\\$ConvertToNonresident', '\\Device\\HarddiskVolume1\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\Device\\HarddiskVolume1\\Windows\\ServiceProfiles\\NetworkService\\NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\Windows\\System32\\en-US\\timedate.cpl.mui', '\\$Directory', '\\$Directory', '\\Windows\\Fonts\\cga80woa.fon', '\\$Directory', '\\Windows\\Fonts\\vgasys.fon', '\\Windows\\System32\\vss_ps.dll', '\\Windows\\winsxs\\amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.4940_none_88df89932faf0bf6', '\\Windows\\System32\\sxssrv.dll', '\\$Directory', '\\$Directory', '\\Windows\\System32', '\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu', '\\Windows\\SysWOW64\\odbc32.dll', '\\Users\\labib\\AppData\\Local\\Temp\\49.WNCRYTows\\Explorer\\thumbcache_96.db', '\\$Directory', '\\Windows\\System32\\bthprops.cpl', '\\Windows\\System32\\NlsLexicons000c.dll', '\\lsass', '\\Windows\\System32\\winlogon.exe', '\\Windows\\SysWOW64\\IPHLPAPI.DLL', '\\Windows\\System32', '\\$Directory', '\\Windows\\System32\\WWanAPI.dll', '\\$Directory', '\\Program Files\\VMware\\VMware Tools\\suspend-vm-default.bat', '\\Endpoint', '\\Windows\\System32\\winsta.dll', '\\Windows\\System32\\sfc_os.dll', '\\Windows\\System32\\winspool.drv', '\\Windows\\System32\\profapi.dll', '\\Windows\\SysWOW64\\dhcpcsvc6.dll', '\\Windows\\System32\\perfdisk.dll', '\\Windows\\System32\\NlsData0009.dll', '\\Windows\\System32\\kerberos.dll', '\\Windows\\System32\\RpcRtRemote.dll', '\\$Directory', '\\$Directory', '\\Windows\\System32\\mswsock.dll', '\\Windows\\System32\\Query.dll', '\\Windows\\System32\\msv1_0.dll', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Windows\\SysWOW64\\msvcrt.dll', '\\Windows\\SysWOW64\\comctl32.dll', '\\Windows\\SysWOW64\\kernel32.dll', '\\Windows\\SysWOW64\\msctf.dll', '\\Windows\\SysWOW64\\normaliz.dll', '\\Windows\\SysWOW64\\wintrust.dll', '\\Windows\\SysWOW64\\ole32.dll', '\\Windows\\SysWOW64\\msasn1.dll', '\\Windows\\System32\\csrss.exe', '\\Windows\\System32\\config\\DEFAULT.LOG2', '\\Windows\\SysWOW64\\advapi32.dll', '\\Windows\\System32\\catroot2\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\\catdb', '\\Windows\\SysWOW64\\en-US\\KernelBase.dll.mui', '\\Windows\\System32', '\\$Directory', '\\Windows\\bootstat.dat', '\\$Directory', '\\Endpoint', '\\AsyncConnectHlp', '\\Windows\\System32\\config\\DEFAULT.LOG1', '\\Windows\\System32\\Syncreg.dll', '\\Windows\\System32\\config\\RegBack\\DEFAULT', '\\Windows\\System32\\config\\DEFAULT', '\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Known Folders API Service.evtx', '\\Users\\labib\\Desktop\\@WanaDecryptor@.exe', '\\AsyncConnectHlp', '\\Windows\\System32\\csrsrv.dll', '\\Windows\\System32', '\\Windows\\System32\\basesrv.dll', '\\Windows\\System32\\locale.nls', '\\Windows\\System32\\winsrv.dll', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\PerfCounter.dll', '\\Windows\\System32\\difxapi.dll', '\\Windows\\System32\\crypt32.dll', '\\Windows\\System32\\kernel32.dll', '\\Windows\\System32\\lpk.dll', '\\Windows\\System32\\sechost.dll', '\\Windows\\System32\\comctl32.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\umpnpmgr.dll', '\\Windows\\System32\\devobj.dll', '\\Windows\\System32\\msvcrt.dll', '\\$Directory', '\\Windows\\SysWOW64\\shlwapi.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32', '\\Users\\labib\\Desktop', '\\Windows\\System32\\ole32.dll', '\\Windows', '\\Windows\\System32\\imagehlp.dll', '\\Windows\\System32\\oleaut32.dll', '\\Windows\\System32\\NlsData002a.dll', '\\Users\\labib\\AppData\\Local\\Temp\\56.WNCRYTows\\Explorer\\thumbcache_sr.db', '\\Windows\\System32\\shell32.dll', '\\Windows\\System32\\shlwapi.dll', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts', '\\Users\\labib\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts', '\\Windows\\System32\\prnfldr.dll', '\\Windows\\System32\\mfcsubs.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\System32\\catsrv.dll', '\\$Mft', '$PATH_TABLE$', '\\$Directory', '\\Windows\\System32\\wintrust.dll', '\\Windows\\SysWOW64\\crypt32.dll', '\\$Directory', '\\Windows\\SysWOW64\\imagehlp.dll', '\\$Directory', '\\$Directory', '\\Windows\\SysWOW64\\cfgmgr32.dll', '\\Windows\\SysWOW64\\clbcatq.dll', '\\Windows\\SysWOW64\\urlmon.dll', '\\', '\\Windows\\SysWOW64\\psapi.dll', '\\Windows\\SysWOW64\\rpcrt4.dll', '\\Windows\\SysWOW64\\cryptbase.dll', '\\Windows\\SysWOW64\\ws2_32.dll', '\\Windows\\SysWOW64\\user32.dll', '\\Windows\\SysWOW64\\nsi.dll', '\\pagefile.sys', '\\Windows\\SysWOW64\\shell32.dll', '\\$Directory', '\\Program Files\\VMware\\VMware Tools\\glibmm-2.4.dll', '\\Windows\\System32\\wsock32.dll', '\\Windows\\Registration\\R000000000006.clb', '\\Windows\\SysWOW64\\KernelBase.dll', '\\Windows\\SysWOW64\\comdlg32.dll', '\\Windows\\SysWOW64\\devobj.dll', '\\Windows\\SysWOW64\\sspicli.dll', '\\Windows\\SysWOW64\\Wldap32.dll', '\\Windows\\SysWOW64\\gdi32.dll', '\\Windows\\SysWOW64\\usp10.dll', '\\Windows\\SysWOW64\\sechost.dll', '\\Windows\\SysWOW64\\iertutil.dll', '\\Winsock2\\CatalogChangeListener-338-0', '\\Windows\\System32\\KernelBase.dll', '\\Windows\\Microsoft.NET\\Framework64\\v2.0.50727\\mscorwks.dll', '\\Windows\\System32\\wininit.exe', '\\Windows\\SysWOW64\\odbcint.dll', '\\Windows\\Fonts\\ega40woa.fon', '\\Windows\\SysWOW64\\imm32.dll', '\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '\\Windows\\Fonts\\cambria.ttc', '\\Windows\\System32\\wininet.dll', '\\Windows\\System32\\advapi32.dll', '\\Windows\\SysWOW64\\lpk.dll', '\\Windows\\System32\\usp10.dll', '\\$Directory', '\\Windows\\System32\\ws2_32.dll', '\\Windows\\System32\\user32.dll', '\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTDiagLog.etl', '\\Windows\\System32\\wdi\\LogFiles\\WdiContextLog.etl.001', '\\$Directory', '\\Endpoint', '\\Windows\\System32\\Wldap32.dll', '\\Windows\\System32\\gdi32.dll', '\\Windows\\System32\\wscsvc.dll', '\\Windows\\System32\\ipconfig.exe', '\\Windows\\System32\\apisetschema.dll', '\\Windows\\System32\\smss.exe', '\\Windows', '\\ProtectedPrefix\\NetWorkService', '\\ProtectedPrefix\\LocalService', '\\ProtectedPrefix\\LocalService', '\\ProtectedPrefix\\Administrators', '\\ProtectedPrefix\\Administrators', '\\ProtectedPrefix', '\\ProtectedPrefix', '\\ProtectedPrefix\\NetWorkService', '\\Windows\\System32\\config\\SOFTWARE', '\\Windows\\System32\\comdlg32.dll', '\\Boot\\BCD.LOG', '\\$Directory', '\\$Directory', '\\Windows\\Registration\\R000000000006.clb', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Windows\\System32\\config\\RegBack\\SYSTEM', '\\Boot\\BCD', '\\Windows\\System32\\config\\SYSTEM.LOG1', '\\Windows\\System32\\config\\SOFTWARE.LOG1', '\\Windows\\System32\\config\\SYSTEM.LOG2', '\\Windows\\System32\\config\\SOFTWARE.LOG2', '\\Windows\\System32\\config\\TxR\\{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms', '\\Windows\\System32\\config\\SYSTEM', '\\$Directory', '\\Windows\\System32\\urlmon.dll', '\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTEventLog-Application.etl', '\\$Directory', '\\Windows\\System32\\config\\TxR\\{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf', '\\Windows\\System32\\config\\RegBack\\SOFTWARE', '\\Windows\\System32\\imm32.dll', '\\$Directory', '\\Windows\\System32\\clbcatq.dll', '\\Windows\\System32\\cfgmgr32.dll', '\\Windows\\System32\\msasn1.dll', '\\Windows\\SysWOW64\\wininet.dll', '\\Windows\\System32\\stobject.dll', '\\Windows\\System32\\en-US\\ActionCenter.dll.mui', '\\Windows\\System32\\sppsvc.exe', '\\Windows\\System32\\en-US\\FirewallAPI.dll.mui', '\\Windows\\System32\\msctf.dll', '\\Windows\\SysWOW64\\oleaut32.dll', '\\Windows\\SysWOW64\\setupapi.dll', '\\Windows\\System32\\config\\TxR\\{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms', '\\$Directory', '\\$Directory', '\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTEventlog-Security.etl', '\\Windows\\System32\\psapi.dll', '\\SystemRoot\\System32\\Config\\TxR\\{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\Windows\\System32\\setupapi.dll', '\\SystemRoot\\System32\\Config\\TxR\\{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TM', '\\Program Files\\VMware\\VMware Tools\\plugins\\vmsvc\\bitMapper.dll', '\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTUBPM.etl', '\\Windows\\System32\\LogFiles\\WMI\\RtBackup\\EtwRTEventLog-System.etl', '\\$Directory', '\\Windows\\System32\\C_1255.NLS', '\\$Directory', '\\Windows\\System32\\cmd.exe', '\\Windows\\System32\\catsrvps.dll', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\System32\\conhost.exe', '\\Users\\labib\\AppData\\Local\\Temp\\55.WNCRYTows\\Explorer\\thumbcache_1024.db', '\\Windows\\System32\\thumbcache.dll', '\\Users\\labib\\AppData\\Roaming\\tor\\lock', '\\Windows\\System32\\wow64.dll', '\\$MftMirr', '\\$LogFile', '\\$Directory', '\\$Directory', '\\$BitMap', '\\$Mft', '\\Windows\\System32\\rpcrt4.dll', '\\System Volume Information\\{3808876b-c176-4e48-b7ae-04046e6cc752}', '\\Device\\HarddiskVolume1\\$Extend\\$RmMetadata\\$TxfLog\\$TxfLog', 'TxfLog', '\\System Volume Information\\{ba4fffe6-703e-11eb-a09b-e82a44f3ec6c}{3808876b-c176-4e48-b7ae-04046e6cc752}', '\\$Directory', '\\$Directory', '\\$Extend\\$RmMetadata\\$TxfLog\\$TxfLog.blf', '\\Windows\\System32\\normaliz.dll', '\\$Directory', '\\Windows\\SysWOW64\\ntdll.dll', '\\Windows\\System32\\iertutil.dll', '\\Windows\\SysWOW64\\difxapi.dll', '\\$Directory', '\\Windows\\System32\\ntdll.dll', '\\System Volume Information\\{8fd8153b-7069-11eb-a771-e82a44f3ec6c}{3808876b-c176-4e48-b7ae-04046e6cc752}', '\\$Directory', '\\$Directory', '\\$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000002', '\\$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000001', '\\Device\\HarddiskVolume1\\$Extend\\$RmMetadata\\$TxfLog\\$TxfLog', '\\$Directory', '\\$Directory', '\\System Volume Information\\{bc91da4d-7091-11eb-9781-e82a44f3ec6c}{3808876b-c176-4e48-b7ae-04046e6cc752}', '\\$Directory', '\\Windows\\winsxs\\amd64_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.4940_none_88df89932faf0bf6', '\\Users\\labib\\AppData\\Local\\Temp\\50.WNCRYTows\\Explorer\\thumbcache_idx.db', '\\Windows\\System32\\rasdlg.dll', '\\Windows\\SysWOW64\\dhcpcsvc.dll', '\\System Volume Information\\{bc91da7f-7091-11eb-9781-e82a44f3ec6c}{3808876b-c176-4e48-b7ae-04046e6cc752}', '\\$Directory', '\\Windows\\System32\\en-US\\shlwapi.dll.mui', '\\Program Files\\VMware\\VMware Tools\\icudt44l.dat', '\\Windows\\System32\\SearchFilterHost.exe', '\\Windows\\winsxs\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_fa396087175ac9ac', '\\Windows\\Registration\\R000000000006.clb', '\\$Directory', '\\Windows\\System32\\en-US\\win32k.sys.mui', '\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', '\\$Directory', '\\$Directory', '\\Windows\\System32\\FirewallAPI.dll', '\\Windows\\Fonts\\cga40woa.fon', '\\Windows\\System32', '\\Windows\\Fonts\\dosapp.fon', '\\System Volume Information\\{bc91da83-7091-11eb-9781-e82a44f3ec6c}{3808876b-c176-4e48-b7ae-04046e6cc752}', '\\Windows\\System32\\nsi.dll', '\\Windows\\System32\\en-US\\urlmon.dll.mui', '\\$Directory', '\\Windows\\Fonts\\vgaoem.fon'],

                'Size': ['0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8', '0xd8']}
        }
@app.route('/processAuto', methods=['POST'])
def process_formAuto():
    csrf_token = request.form.get('csrf_token')
    if csrf_token != session['csrf_token']:
        abort(403)
    autoDict = {}
    autoDict.clear()
    malware = request.form.get('malware')
    filePath = session.get('filePath')

    if malware == "wannacry":
        t = malzclass.WannaCryV1(filepath=filePath, outputpath="./outputtest")
        autoDict = t.run()
        with open('templates/generateReportAutoWanncry.html', 'r') as template_file:
            template_content = template_file.read()

        temp = str(autoDict['ipv4'])
        temp = temp.replace('[', '').replace(']', '').replace('"', '')
        html_content = template_content.replace('{IPV4}', temp)

        cmdline_autoDict = autoDict.get('dict_cmdline', {})
        cmdline_headers = ''
        for key in cmdline_autoDict.keys():
            if key == "Args":
                continue
            cmdline_headers += f'<th>{key}</th>'
        cmdline_content = ''
        index = 0
        for value in cmdline_autoDict['PID']:
                cmdline_row = '<tr>'
                cmdline_row += f'<td>{value}</td>'
                cmdline_row += f'<td>{cmdline_autoDict["Process"][index]}</td>'
                cmdline_row += '</tr>'
                cmdline_content += cmdline_row
                index+=1
        html_content = html_content.replace('{SUSPID_HEADER}', cmdline_headers)
        html_content = html_content.replace('{SUSPID_CONTENT}', cmdline_content)

        index = 0
        hidpid_content = ''
        for value in autoDict['hidden_pid']:
            hidpid_row = '<tr>'
            hidpid_row += f'<td>{autoDict["hidden_pid"][index]}</td>'
            hidpid_row += '</tr>'
            hidpid_content += hidpid_row
            index+=1
        html_content = html_content.replace('{HIDPID}', hidpid_content)

        lengthPID = len(autoDict['sus_pid'])
        html_content = html_content.replace('{COUNTPID}', str(lengthPID))

        temp = str(autoDict['sus_pid'])
        temp = temp.replace('[', '').replace(']', '').replace('"', '')
        html_content = html_content.replace('{SUSPID}', temp)

        dlllist_autoDict = autoDict.get('dict_dlllist', {})
        dlllist_headers = ''
        for key in dlllist_autoDict.keys():
            dlllist_headers += f'<th>{key}</th>'
        dlllist_content = ''
        index = 0
        for value in dlllist_autoDict['PID']:
                dlllist_row = '<tr>'
                dlllist_row += f'<td>{value}</td>'
                dlllist_row += f'<td>{dlllist_autoDict["Process"][index]}</td>'
                dlllist_row += f'<td>{dlllist_autoDict["Base"][index]}</td>'
                dlllist_row += f'<td>{dlllist_autoDict["Size"][index]}</td>'
                dlllist_row += f'<td>{dlllist_autoDict["Name"][index]}</td>'
                dlllist_row += f'<td>{dlllist_autoDict["Path"][index]}</td>'
                dlllist_row += f'<td>{dlllist_autoDict["LoadTime"][index]}</td>'
                dlllist_row += f'<td>{dlllist_autoDict["File output"][index]}</td>'
                dlllist_row += '</tr>'
                dlllist_content += dlllist_row
                index+=1
        html_content = html_content.replace('{DLLLIST_HEADER}', dlllist_headers)
        html_content = html_content.replace('{DLLLIST_CONTENT}', dlllist_content)

        ldrmod_autoDict = autoDict.get('ldrmod', {})
        ldrmod_headers = ''
        for key in ldrmod_autoDict.keys():
            ldrmod_headers += f'<th>{key}</th>'
        ldrmod_content = ''
        index = 0
        for value in ldrmod_autoDict['Pid']:
                ldrmod_row = '<tr>'
                ldrmod_row += f'<td>{ldrmod_autoDict["Pid"][index]}</td>'
                ldrmod_row += f'<td>{ldrmod_autoDict["Process"][index]}</td>'
                ldrmod_row += f'<td>{ldrmod_autoDict["Base"][index]}</td>'
                ldrmod_row += f'<td>{ldrmod_autoDict["InLoad"][index]}</td>'
                ldrmod_row += f'<td>{ldrmod_autoDict["InInit"][index]}</td>'
                ldrmod_row += f'<td>{ldrmod_autoDict["InMem"][index]}</td>'
                ldrmod_row += f'<td>{ldrmod_autoDict["MappedPath"][index]}</td>'
                ldrmod_row += '</tr>'
                ldrmod_content += ldrmod_row
                index+=1
        html_content = html_content.replace('{LDRMOD_HEADER}', ldrmod_headers)
        html_content = html_content.replace('{LDRMOD_CONTENT}', ldrmod_content)

        ldrmodioc_autoDict = autoDict.get('iocs', {})
        index = 0
        ldrmodioc_content = ''
        for value in ldrmodioc_autoDict['ldrmod']:
            ldrmodioc_row = '<tr>'
            ldrmodioc_row += f'<td>{value}</td>'
            ldrmodioc_row += '</tr>'
            ldrmodioc_content += ldrmodioc_row
            index+=1
        html_content = html_content.replace('{LDRMODIOC_CONTENT}', ldrmodioc_content)

        filescan_autoDict = autoDict.get('filescan', {})
        filescan_headers = ''
        for key in filescan_autoDict.keys():
            filescan_headers += f'<th>{key}</th>'
        filescan_content = ''
        index = 0
        for value in filescan_autoDict['Offset']:
                filescan_row = '<tr>'
                filescan_row += f'<td>{value}</td>'
                filescan_row += f'<td>{filescan_autoDict["Name"][index]}</td>'
                filescan_row += f'<td>{filescan_autoDict["Size"][index]}</td>'
                filescan_row += '</tr>'
                filescan_content += filescan_row
                index+=1
        html_content = html_content.replace('{FILESCAN_HEADER}', filescan_headers)
        html_content = html_content.replace('{FILESCAN_CONTENT}', filescan_content)

        filescanioc_autoDict = autoDict.get('iocs', {})
        index = 0
        filescanioc_content = ''
        for value in filescanioc_autoDict['filescan']:
            filescanioc_row = '<tr>'
            filescanioc_row += f'<td>{value}</td>'
            filescanioc_row += '</tr>'
            filescanioc_content += filescanioc_row
            index+=1
        html_content = html_content.replace('{FILESCANIOC_CONTENT}', filescanioc_content)

        handles_autoDict = autoDict.get('dict_handles', {})
        handles_headers = ''
        for key in handles_autoDict.keys():
            handles_headers += f'<th>{key}</th>'
        handles_content = ''
        index = 0
        for value in handles_autoDict['PID']:
                handles_row = '<tr>'
                handles_row += f'<td>{value}</td>'
                handles_row += f'<td>{handles_autoDict["Process"][index]}</td>'
                handles_row += f'<td>{handles_autoDict["Offset"][index]}</td>'
                handles_row += f'<td>{handles_autoDict["HandleValue"][index]}</td>'
                handles_row += f'<td>{handles_autoDict["Type"][index]}</td>'
                handles_row += f'<td>{handles_autoDict["GrantedAccess"][index]}</td>'
                handles_row += f'<td>{handles_autoDict["Name"][index]}</td>'
                handles_row += '</tr>'
                handles_content += handles_row
                index+=1
        html_content = html_content.replace('{HANDLES_HEADER}', handles_headers)
        html_content = html_content.replace('{HANDLES_CONTENT}', handles_content)

        handlesioc_autoDict = autoDict.get('iocs', {})
        index = 0
        handlesioc_content = ''
        for value in handlesioc_autoDict['handles']:
            handlesioc_row = '<tr>'
            handlesioc_row += f'<td>{value}</td>'
            handlesioc_row += '</tr>'
            handlesioc_content += handlesioc_row
            index+=1
        html_content = html_content.replace('{HANDLESIOC_CONTENT}', handlesioc_content)

        mutexioc_autoDict = autoDict.get('iocs', {})
        index = 0
        mutexioc_content = ''
        for value in mutexioc_autoDict['mutex']:
            mutexioc_row = '<tr>'
            mutexioc_row += f'<td>{value}</td>'
            mutexioc_row += '</tr>'
            mutexioc_content += mutexioc_row
            index+=1
        html_content = html_content.replace('{MUTEX_CONTENT}', mutexioc_content)

        wanna_pathioc_autoDict = autoDict.get('iocs', {})
        index = 0
        wanna_pathioc_content = ''
        for value in wanna_pathioc_autoDict['wanna_path']:
            wanna_pathioc_row = '<tr>'
            wanna_pathioc_row += f'<td>{value}</td>'
            wanna_pathioc_row += '</tr>'
            wanna_pathioc_content += wanna_pathioc_row
            index+=1
        html_content = html_content.replace('{WANNAPATH_CONTENT}', wanna_pathioc_content)

        cmdline_autoDict = autoDict.get('dict_cmdline', {})
        cmdline_headers = ''
        for key in cmdline_autoDict.keys():
            cmdline_headers += f'<th>{key}</th>'
        cmdline_content = ''
        index = 0
        for value in cmdline_autoDict['PID']:
                cmdline_row = '<tr>'
                cmdline_row += f'<td>{value}</td>'
                cmdline_row += f'<td>{cmdline_autoDict["Process"][index]}</td>'
                cmdline_row += f'<td>{cmdline_autoDict["Args"][index]}</td>'
                cmdline_row += '</tr>'
                cmdline_content += cmdline_row
                index+=1
        html_content = html_content.replace('{CMDLINE_HEADER}', cmdline_headers)
        html_content = html_content.replace('{CMDLINE_CONTENT}', cmdline_content)

        registry_content = ''
        index = 0
        for value in autoDict['registry']:
            registry_row = '<tr>'
            angka = len(autoDict['registry'][0])
            # print(autoDict['registry'][0][1])
            for x in range(angka):
                registry_row += f'<td>{autoDict["registry"][index][x]}</td>'
            registry_row += '</tr>'
            registry_content += registry_row
            index+=1
        html_content = html_content.replace('{REGISTRY_CONTENT}', registry_content)

        summary_content = ''
        index = 0
        for value in autoDict['pid']:
            summary_row = '<tr>'
            summary_row += f'<td>{autoDict["pid"][index]}</td>'
            summary_row += f'<td>{autoDict["process_name"][index]}</td>'
            summary_row += f'<td>{autoDict["malware_types"][index]}</td>'
            summary_row += '</tr>'
            summary_content += summary_row
            index+=1
        html_content = html_content.replace('{SUMMARY_CONTENT}', summary_content)

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
    elif malware == "metasploit":
        t = malzclass.MetasPreter(filepath=filePath, outputpath="./outputtest")
        autoDict = t.run()
        with open('templates/generateReportAutoMetasploit.html', 'r') as template_file:
            template_content = template_file.read()
        
        info_autoDict = autoDict.get('info', {})
        info_headers = ''
        for key in info_autoDict.keys():
            info_headers += f'<th>{key}</th>'
        info_content = ''
        index = 0
        for value in info_autoDict['Variable']:
                info_row = '<tr>'
                info_row += f'<td>{info_autoDict["Variable"][index]}</td>'
                info_row += f'<td>{info_autoDict["Value"][index]}</td>'
                info_row += '</tr>'
                info_content += info_row
                index+=1
        html_content = template_content.replace('{INFO_HEADER}', info_headers)
        html_content = html_content.replace('{INFO_CONTENT}', info_content)

        temp = str(autoDict['injected_code'])
        temp = temp.replace('[', '').replace(']', '').replace('"', '')
        html_content = html_content.replace('{EXE_NAME}', temp)

        temp = str(autoDict['pid'])
        temp = temp.replace('[', '').replace(']', '').replace('"', '')
        html_content = html_content.replace('{PID}', temp)

        html_content = html_content.replace('{METAS_CONNECT}', autoDict['metas_connect'])
        temp = str(autoDict['ipv4'])
        temp = temp.replace('[', '').replace(']', '').replace('"', '')
        html_content = html_content.replace('{IPV4}', temp)
        html_content = html_content.replace('{METAS_TCP_STATE}', autoDict['metas_tcp_state'])
        temp = str(autoDict['metas_port'])
        temp = temp.replace('[', '').replace(']', '').replace('"', '')
        html_content = html_content.replace('{METAS_PORT}', temp)
        html_content = html_content.replace('{METAS_CONNECT}', autoDict['metas_connect'])

        temp = len(autoDict['ipv4'])
        html_content = html_content.replace('{COUNT_IP}', str(temp))
        temp = str(autoDict['ipv4'])
        temp = temp.replace('[', '').replace(']', '').replace('"', '')
        html_content = html_content.replace('{MALIP}', temp)

        temp_content = ""
        for i in range(len(autoDict['pid'])):
            temp_content = temp_content+ "PID "+ str(autoDict['pid'][i]) + " is malware with type "+ autoDict['malware_types'][i] +"<br>"
        
        html_content = html_content.replace('{CONCLUSION}',temp_content)

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
    elif malware == "stuxnet":
        t = malzclass.StuxNet(filepath=filePath, outputpath="./outputtest")
        autoDict = t.run()
        with open('templates/generateReportAutoStuxnet.html', 'r') as template_file:
            template_content = template_file.read()

        info_autoDict = autoDict.get('info', {})
        # print(info_autoDict)
        info_headers = ''
        for key in info_autoDict.keys():
            info_headers += f'<th>{key}</th>'
        info_content = ''
        index = 0
        for value in info_autoDict['Variable']:
                info_row = '<tr>'
                print(info_autoDict["Variable"][index])
                info_row += f'<td>{info_autoDict["Variable"][index]}</td>'
                info_row += f'<td>{info_autoDict["Value"][index]}</td>'
                info_row += '</tr>'
                info_content += info_row
                index+=1
        html_content = template_content.replace('{INFO_HEADER}', info_headers)
        html_content = html_content.replace('{INFO_CONTENT}', info_content)

        html_content = html_content.replace('{SAMEPROCESS}', autoDict['process_name'][0])

        index = 0
        anolpid_content = ''
        for value in autoDict['pid']:
            anolpid_row = '<tr>'
            anolpid_row += f'<td>{value}</td>'
            anolpid_row += '</tr>'
            anolpid_content += anolpid_row
            index+=1
        html_content = html_content.replace('{ANOLPID}', anolpid_content)

        ssdt_autoDict = autoDict.get('ssdt', {})
        ssdt_headers = ''
        for key in ssdt_autoDict.keys():
            ssdt_headers += f'<th>{key}</th>'
        ssdt_content = ''
        index = 0
        for value in ssdt_autoDict['Index']:
                ssdt_row = '<tr>'
                ssdt_row += f'<td>{ssdt_autoDict["Index"][index]}</td>'
                ssdt_row += f'<td>{ssdt_autoDict["Address"][index]}</td>'
                ssdt_row += f'<td>{ssdt_autoDict["Module"][index]}</td>'
                ssdt_row += f'<td>{ssdt_autoDict["Symbol"][index]}</td>'
                ssdt_row += '</tr>'
                ssdt_content += ssdt_row
                index+=1
        html_content = html_content.replace('{SSDT_HEADER}', ssdt_headers)
        html_content = html_content.replace('{SSDT_CONTENT}', ssdt_content)

        callbacks_autoDict = autoDict.get('callbacks', {})
        callbacks_headers = ''
        for key in callbacks_autoDict.keys():
            callbacks_headers += f'<th>{key}</th>'
        callbacks_content = ''
        index = 0
        for value in callbacks_autoDict['Type']:
                callbacks_row = '<tr>'
                callbacks_row += f'<td>{callbacks_autoDict["Type"][index]}</td>'
                callbacks_row += f'<td>{callbacks_autoDict["Callback"][index]}</td>'
                callbacks_row += f'<td>{callbacks_autoDict["Module"][index]}</td>'
                callbacks_row += f'<td>{callbacks_autoDict["Symbol"][index]}</td>'
                callbacks_row += f'<td>{callbacks_autoDict["Detail"][index]}</td>'
                callbacks_row += '</tr>'
                callbacks_content += callbacks_row
                index+=1
        html_content = html_content.replace('{CALLBACKS_HEADER}', callbacks_headers)
        html_content = html_content.replace('{CALLBACKS_CONTENT}', callbacks_content)

        temp_content = ""
        for i in range(len(autoDict['pid'])):
            temp_content = temp_content+ "PID "+ str(autoDict['pid'][i]) + " is malware with type "+ autoDict['malware_types'][i] +"<br>"
        
        html_content = html_content.replace('{CONCLUSION}',temp_content)

        tanggal_waktu_sekarang = datetime.now()
        deretan_angka = tanggal_waktu_sekarang.strftime('%Y-%m-%d_%H%M%S')
        # Menyimpan file HTML di folder /static/reports
        filename = "autoDict_" + deretan_angka + ".html"
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
    
    
def create_html_table(data):
    html = ''

    for key, value in data.items():
        if not value:
            continue

        html += f'<h2>{key}</h2>'
        html += '<table>'
        html += '<tr>'

        if isinstance(value, dict):
            inner_keys = value.keys()
            for inner_key in inner_keys:
                html += f'<th>{inner_key}</th>'
        else:
            html += f'<th>{key}</th>'


        html += '</tr>'
        html += '<tr>'

        if isinstance(value, dict):
            inner_values = value.values()
            for inner_value in inner_values:
                if isinstance(inner_value, list):
                    html += '<td>'
                    html += '<ul>'
                    for item in inner_value:
                        html += f'<li>{item}</li>'
                    html += '</ul>'
                    html += '</td>'
                else:
                    html += f'<td>{inner_value}</td>'
        elif isinstance(value, list):
            for item in value:
                html += '<tr>'
                html += f'<td>{item}</td>'
                html += '</tr>'
        else:
            html += '<tr>'
            html += f'<td>{value}</td>'
            html += '</tr>'

        html += '</tr>'
        html += '</table>'

    return html

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
    form_data = request.form
    command = ""
    filePath = session.get('filePath')
    argsForm = {}
    csrf_token = request.form.get('csrf_token')
    if csrf_token != session['csrf_token']:
        abort(403)
    data_dict = {}
    data_dict.clear()
    for key, value in form_data.items():
        if key == "command":
            command = value
        elif key == "pid-fieldvalue":
            if value:
                argsForm['pid'] = int(value)
        elif key == "offset-fieldvalue":
            if value:
                argsForm['offset'] = value
        elif key == "key-fieldvalue":
            if value:
                argsForm['key'] = value
        elif key == "physical-check":
            if value:
                argsForm['physical'] = True
        elif key == "include-corruptCheck":
            if value:
                argsForm['include_corrupt'] = True
        elif key == "dumpCheck":
            if value:
                argsForm['dump'] = True

    # print(command)
    print(argsForm)
    data_dict = vol3.run(command,filePath,"./outputtest",argsForm)
    # data_dict = vol2.run("windows.psscan.PsScan","./wanncry.vmem","./outputtest",[])
    # print("File: "+filePath)
    # print(data_dict)
    return jsonify(data_dict)

    # "File: "+ return jsonify({"command": command, "File Path": filePath, "PID": pid, "Offset": offset, "Key": key, "Include Corrupt": includeCorrupt, "Recurse": recurse, "Dump": dump,  "physic": physical})


@app.route("/<cmd>")
def commandtest(cmd):
    return f"<h1>{cmd}</h1>"


if __name__ == "__main__":
    app.run(debug=True)
