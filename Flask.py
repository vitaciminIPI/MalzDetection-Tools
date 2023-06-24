from flask import Flask, render_template, request, jsonify, render_template, session, make_response, Markup, send_from_directory, abort
import os, secrets
from datetime import datetime
import malzclass, vol3

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
    manDict = request.json
    with open('templates/generateReport.html', 'r') as template_file:
        template_content = template_file.read()
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
            'info': {
                'Variable': ['Kernel Base', 'DTB', 'Symbols', 'Is64Bit', 'IsPAE', 'layer_name', 'memory_layer', 'KdVersionBlock', 'Major/Minor', 'MachineType', 'KeNumberProcessors', 'SystemTime', 'NtSystemRoot', 'NtProductType', 'NtMajorVersion', 'NtMinorVersion', 'PE MajorOperatingSystemVersion', 'PE MinorOperatingSystemVersion', 'PE Machine', 'PE TimeDateStamp'], 

                'Value': ['0xf80312013000', '0x1aa000', 'file:///C:/Users/HERY/Documents/Skripsi/volatility3-2.4.1/volatility3/symbols/windows/ntkrnlmp.pdb/DCD0B9772B46C59FF6E45DFBB3D1AE7B-1.json.xz', 'True', 'False', '0 WindowsIntel32e', '1 FileLayer', '0xf80312c22388', '15.19041', '34404', '2', '2023-06-12 17:12:25', 'C:\\Windows', 'NtProductWinNt', '10', '0', '10', '0', '34404', 'Wed Mar 22 20:19:37 2090']
                },
            
            'ipv4': [], 

            'pid': [3872, 4568, 3872, 4568], 

            'sus_pid': [], 

            'hidden_pid': [], 

            'process_name': ['@WanaDecryptor', 'Ransomware.wan'],

            'registry': [['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AutoRestartShell', '1', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'Background', '0 0 0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'CachedLogonsCount', '10', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DebugServerCommand', 'no', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DisableBackButton', '1', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'EnableSIHostIntegration', '1', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'ForceUnlockLogon', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'LegalNoticeCaption', '', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'LegalNoticeText', '', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'PasswordExpiryWarning', '5', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'PowerdownAfterShutdown', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'PreCreateKnownFolders', '{A520A1A4-1780-4FF6-BD18-167343C5AF16}', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'ReportBootOk', '1', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'Shell', 'explorer.exe', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'ShellCritical', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'ShellInfrastructure', 'sihost.exe', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'SiHostCritical', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'SiHostReadyTimeOut', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'SiHostRestartCountLimit', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'SiHostRestartTimeGap', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'Userinit', 'C:\\Windows\\system32\\userinit.exe,', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'VMApplet', 'SystemPropertiesPerformance.exe /pagefile', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'WinStationsDisabled', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'scremoveoption', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DisableCAD', '1', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_QWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'LastLogOffEndTimePerfCounter', '62211863834', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'ShutdownFlags', '7', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DisableLockWorkstation', '0', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_DWORD', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'EnableFirstLogonAnimation', '1', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AutoLogonSID', 'S-1-5-21-2929926106-2179945841-3936977681-1001', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'LastUsedUsername', 'mbuhkeder', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AutoAdminLogon', '', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultUserName', '', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultDomainName', '', False], ['datetime.datetime(2023, 6, 13, 6, 52, 8)', '0xac85db246000', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'ShellAppRuntime', 'ShellAppRuntime.exe', False], ['datetime.datetime(2022, 8, 20, 14, 27, 47)', '0xac85db246000', 'REG_EXPAND_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'VBoxTray', '%SystemRoot%\\system32\\VBoxTray.exe', False]],

            'exe_name': ['pid.3872.0x400000.dmp', 'pid.4568.0x400000.dmp'], 

            'mod_name': [], 

            'injected_code': [], 

            'malware_types': ['ransomware.wannacryptor/wannacry', 'ransomware.wannacry/wanna'],

            'dict_dlllist': {
                'PID': [3872, 3872, 3872, 3872, 3872, 4568, 4568, 4568, 4568, 4568],

                'Process': ['@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', 'Ransomware.wan', 
                'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan'], 

                'Base': ['0x400000', '0x7ffc34e30000', '0x7ffc34370000', '0x7ffc34c40000', '0x773f0000', '0x400000', '0x7ffc34e30000', '0x7ffc34370000', '0x7ffc34c40000', '0x773f0000'], 

                'Size': ['0x3d000', '0x1f8000', '0x59000', '0x83000', '0xa000', '0x66b000', '0x1f8000', '0x59000', '0x83000', '0xa000'],

                'Name': ['@WanaDecryptor@.exe', 'ntdll.dll', 'wow64.dll', 'wow64win.dll', 'wow64cpu.dll', 'Ransomware.wannacry.exe', 'ntdll.dll', 'wow64.dll', 'wow64win.dll', 'wow64cpu.dll'], 

                'Path': ['C:\\Users\\mbuhkeder\\Desktop\\@WanaDecryptor@.exe', 'C:\\Windows\\SYSTEM32\\ntdll.dll', 'C:\\Windows\\System32\\wow64.dll', 'C:\\Windows\\System32\\wow64win.dll', 'C:\\Windows\\System32\\wow64cpu.dll', 'C:\\Users\\mbuhkeder\\Desktop\\Ransomware.wannacry.exe', 'C:\\Windows\\SYSTEM32\\ntdll.dll', 'C:\\Windows\\System32\\wow64.dll', 'C:\\Windows\\System32\\wow64win.dll', 'C:\\Windows\\System32\\wow64cpu.dll'], 

                'LoadTime': ['datetime.datetime(2023, 6, 12, 17, 5, 39)', 'datetime.datetime(2023, 6, 12, 17, 5, 39)', 'datetime.datetime(2023, 6, 12, 17, 5, 39)', 'datetime.datetime(2023, 6, 12, 17, 5, 39)', 'datetime.datetime(2023, 6, 12, 17, 5, 39)', 'datetime.datetime(2023, 6, 12, 17, 0, 6)', 'datetime.datetime(2023, 6, 12, 17, 0, 6)', 'datetime.datetime(2023, 6, 12, 17, 0, 6)', 'datetime.datetime(2023, 6, 12, 17, 0, 6)', 'datetime.datetime(2023, 6, 12, 17, 0, 6)'], 

                'File output': ['Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled']
                },

            'dict_cmdline': {
                'PID': [3872, 4568], 
                'Process': ['@WanaDecryptor', 'Ransomware.wan'], 
                'Args': ['"C:\\Users\\mbuhkeder\\Desktop\\@WanaDecryptor@.exe" ', 'C:\\Users\\mbuhkeder\\Desktop\\Ransomware.wannacry.exe -m security']
                },

            'dict_handles': {
                'PID': [3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568],

                'Process': ['@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan'], 

                'Offset': ['0xe3838fc63fe0', '0xe3838fc65fe0', '0xe3838ea3aba0', '0xe3838fe87cc0', '0xe3838faeed80', '0xe38389aa1d60', 
                '0xe3838ea3b3c0', '0xe38389aa12c0', '0xe3838ea3c4d0', '0xe3838fe88830', '0xe3838fe88bb0', '0xe3838fe88c90', '0xe3838fc6b8e0', '0xe3838fc66de0', '0xac85d8ffb660', '0xe3838fd8c630', '0xe3838fc6b360', '0xac85d89a9480', '0xe3838fc6d7e0', '0xe3838ea3cb50', '0xe3838fe88d80', '0xe3838fe71d80', '0xe38389aa1b40', '0xe3838ea3d370', '0xe38389aa36e0', '0xe3838ea3d850', '0xe3838fe876b0', '0xe3838fe87790', '0xe3838fe87f70', '0xe3838fc6d8e0', '0xe3838fc6d360', '0xac85d89a9480', '0xe3838fc7a860', '0xe3838fe87db0', '0xe3838fc41f50', '0xe3838dbf8070', '0xac85dcd66c00', '0xe3838fcc6a10', '0xe3838fe875d0', '0xe3838fe87250', '0xe3838fe88590', '0xe3838fe87330', '0xe3838fe88130', '0xe3838fe87410', '0xe3838fe874f0', '0xe3838fe87870', '0xe3838fe87940', '0xac85df802380', '0xe3838fe88210', '0xac85df803d00', '0xe3838fe6bd80', '0xe38389aa4b10', '0xe3838ea3e140', '0xe38389aa4290', '0xe3838ea3dc60', '0xe3838f654640', '0xac85df806450', '0xac85df804470', '0xe3838fc6df60', '0xac85df803bf0', '0xac85df805df0', '0xac85df803260', '0xe3838ea3f250', '0xe3838fc6ece0', '0xac85df804cf0', '0xac85df806120', '0xe3838fc6e2e0', '0xe3838fe882f0', '0xe3838fe883d0', '0xe3838fe88670', '0xe3838fc6f3e0', '0xe3838fc6f860', '0xe3838fc6f5e0', '0xe3838fc70060', '0xe3838fc6fee0', '0xe3838fc6fe60', '0xe3838fe89630', '0xe3838fe8a190', '0xe3838fe89e10', '0xe3838fe88e50', '0xe3838fe890f0', '0xe3838fe89ef0', '0xe3838fe8a510', '0xe3838fe8a5f0', '0xe3838fe891d0', '0xe3838fe8a7b0', '0xe3838fe892c2', '0xe3838d786b50', '0xe3838d8f6a00', '0xe3838d786b50', '0xe3838fe8a890', '0xe3838fe89390', '0xe3838fe89710', '0xe3838fd9b3b0', '0xe3838fe8d7d0', '0xe3838fe8d990', '0xe3838fe8da70', '0xe3838fe8c9d0', '0xe3838fe8d1b0', '0xe3838fe8d290', '0xe3838fc6fc60', '0xe3838fc6ff60', '0xe3838fe8ebf0', '0xe3838fe8edb0', '0xe3838fe90710', '0xe3838fe91dd0', '0xe3838fe92850', '0xe3838fe931f0', '0xe3838fe92bd0', '0xe3838fe92e70', '0xe3838fe932d0', '0xe3838fe933b0', '0xe3838fe94450', '0xe3838fe93c70', '0xe3838fe941b0', '0xe3838fe940d0', '0xe3838fe94370', '0xe3838fc6dd60', '0xe3838fc70160', '0xe3838fc70ce0', '0xe3838fe93ab0', '0xe3838fe95170', '0xe3838fe95090', '0xe3838fe94290', '0xe3838fe93d50', '0xe3838fe938f0', '0xe3838fc7afe0', '0xe3838fd9ccb0', '0xe3838fc7a6e0', '0xe3838f5de080', '0xac85df808980', '0xe3838fe9b0d0', '0xe3838fb61a80', '0xe3838fe9c170', '0xe3838fe88910', '0xe3838fe9ab90', '0xe3838fe9ac70', '0xac85dc1c1cf0', '0xac85dc1c1e70', '0xe3838fd94b00', '0xe3838fc705e0', '0xac85df80cb60', '0xe3838fc79e60', '0xac85df80e1b0', '0xe3838fe9b610', '0xe3838fe9b7d0', '0xe3838fe9a650', '0xe3838fe9a730', '0xe3838fe9a810', '0xe3838fe9dbb0', '0xe3838fe9d910', '0xe3838fe9c6b0', '0xe3838fe9c790', '0xe3838fe9cb10', '0xe3838fe9cdb0', '0xe3838fe9c5d0', '0xe3838fe9d130', '0xe3838fe9c870', '0xac85dd6212e0', '0xe3838fc7b060', '0xe3838fe9d210', '0xac85df80e810', '0xe3838fe9c410', '0xe3838fe9ccd0', '0xe3838fe9cf70', '0xe3838fe9d9f0', '0xe3838fe9c950', '0xe3838fe9ca30', '0xac85df80cc70', '0xac85df80e920', '0xe3838fc7b160', '0xe3838fc7bce0', '0xe3838fc7a360', '0xe3838fc7a9e0', '0xe3838fc7a260', '0xe3838fc7a2e0', '0xe3838d8f8240', '0xe3838da149a0', '0xe3838fc7a660', '0xe3838fe8bbd0', '0xe3838fd8e890', '0xe3838fc7b4e0', '0xe3838fe8bf50', '0xe3838fe9d670', '0xe3838ebbb990', '0xe3838fe9ce90', '0xe3838fc7b5e0', '0xe3838f5de080', '0xe3838fe9d740', '0xe3838fbcca70', '0xe38389aa3900', '0xe3838f614e10', '0xe38389aa37f0', '0xe3838f614a00', '0xe3838fd5dce0', '0xe3838fe9c330', '0xe3838fe8c3b0', '0xe3838fe8baf0', '0xe3838fe8a350', '0xe3838fe88f30', '0xe3838fe8b070', '0xe3838f64f9b0', '0xac85dea5db40', '0xe3838db2eb60', '0xe3838db33de0', '0xe3838f6109d0', '0xe3838f6ab300', '0xe3838f79c530', '0xe38389aa32a0', '0xe3838f612230', '0xe38389aa1810', '0xe3838f6123d0', '0xe3838f6ab850', '0xe3838f6ab4d0', '0xe3838f6ab070', '0xe3838f499360', '0xe3838f487f60', '0xac85d8ffb660', '0xe3838ed79170', '0xe3838f49b3e0', '0xac85d89a9480', '0xe3838f49b6e0', '0xe3838f610c40', '0xe3838f6aac00', '0xe3838ee45840', '0xe38389aa25e0', '0xe3838f6112c0', '0xe38389aa2910', '0xe3838f6117a0', '0xe3838f6abf50', '0xe3838f6ac110', '0xe3838f6abbd0', '0xe3838f49fb60', '0xe3838f49c360', '0xac85d89a9480', '0xe3838ed833f0', '0xe3838f6ab3f0', '0xe3838fc25390', '0xe3838963d6e0', '0xac85dcd66480', '0xe3838d993ee0', '0xe3838f6aaeb0', '0xe3838f6ab5b0', '0xe3838f6aad00', '0xe3838ea2a530', '0xe38389aa33b0', '0xe3838f611870', '0xe38389aa2e60', '0xe3838f610d10', '0xac85de979890', '0xac85de97c860', '0xe3838fc706e0', '0xac85dec305e0', '0xe3838f6b0e10', '0xe3838f6abd90', '0xe3838f6abaf0', '0xe3838f6ab690', '0xe3838f6aba10', '0xe3838f6ac1f0', '0xe3838f6ac2d0', '0xe3838f6ab770', '0xe3838f6ab930', '0xe3838f6acf10', '0xe3838f49fc60', '0xe3838f613d00', '0xe3838f6ac8f0', '0xac85dec30a20', '0xac85dec30910', '0xac85dec39dd0', '0xe3838f4a5f60', '0xac85dec39550', '0xac85dec3dc80', '0xe3838f4a6460', '0xe3838f6ad0d0', '0xe3838f6ae090', '0xe3838f6ada70', '0xe3838f4a6c60', '0xe3838f4a6860', '0xe3838f4a62e0', '0xe3838f4a6ce0', '0xe3838f4a6d60', '0xe3838f4a6660', '0xe3838f6acc70', '0xe3838f6ac650', '0xe3838f6ad1b0', '0xe3838f6acd50', '0xe3838f6adc30', '0xe3838f6ad290', '0xe3838f6ac730', '0xe3838f6ad990', '0xe3838f6adb50', '0xe3838f6ad370', '0xe3838d6a9260', '0xac85dec3f600', '0xac85dec3c1f0', '0xe3838f6ad450', '0xe3838d6aec60', '0xe3838d6ae8e0', '0xe3838d6ae960', '0xe3838f6ad530', '0xe3838f6acab0', '0xe3838f6ac9d0', '0xe3838d6af160', '0xe3838983a080', '0xe3838ea5b070', '0xe3838f6add10', '0xe3838f6ad610', '0xe3838f6acb90', '0xe3838da59ac0', '0xe3838d8f6430', '0xe3838da59ac0', '0xac85dc0b1a50', '0xac85dcf60af0', '0xac85dcf617b0', '0xac85dcf627a0', '0xe3838f6ace30', '0xe3838f6ad6f0', '0xe3838f6ad7d0', '0xe3838f6addf0', '0xe3838f6aded0', '0xe3838f6ae4f0', '0xe3838f6aea30', '0xe3838f6af4b0', '0xe3838f6aee90', '0xe3838f6af670', '0xe3838f6ae790', '0xe3838f6ae870', '0xe3838f6af590', '0xe3838f6aeb10', '0xac85dc134530', '0xe3838f6aebf0', '0xac85de97cb90', '0xe3838f6af750', '0xe3838f6aedb0', '0xe3838f6aef70', '0xe3838f6af130', '0xe3838f6af830', '0xe3838f6af9f0', '0xac85de97b760', '0xe3838f6afad0', '0xe3838f6af910', '0xac85deda23d0', '0xe3838f6afbb0', '0xe3838f6afc90', '0xe3838f6afd70', '0xac85de982e60', '0xac85de97f3f0', '0xac85dec3f820', '0xac85dec3f930', '0xac85dec3f0b0', '0xac85dec3fe80', '0xac85dec3f2d0', '0xe3838983a080', '0xe3838f2debe0', '0xac85dec40b40', '0xe3838f2e26e0', '0xac85dec400a0', '0xe3838f6ae250', '0xe3838f6ae410', '0xe3838f6ae330', '0xe3838f2e2460', '0xe3838f6134e0', '0xac85dcf5fb00', '0xac85dcf63df0', '0xac85dcf62470', '0xac85dcf62e00', '0xe3838fb57080', '0xe3838ed81960', '0xe3838f6b1340', '0xe3838f4cf890', '0xe3838f6b10c0', '0xe3838ec13560', '0xe38389aa2b30', '0xe3838f612b20', '0xe38389aa22b0', '0xe3838f612cc0', '0xe3838f6b1270', '0xe3838fc731e0', '0xe3838eadf080', '0xe3838d4e0080', '0xe3838ee03060', '0xe3838db53310', '0xe3838f6b00f0', '0xe3838d6b0560', '0xe3838f2e2fe0', '0xe3838f2e3060', '0xe3838f6135b0', '0xe3838f2e3ee0', '0xe3838f613680', '0xe3838f5918e0', '0xe3838f591be0', '0xe3838f591460', '0xe3838f6139c0', '0xe3838f6aff30', '0xe3838f2e5c60', '0xe3838f2e5fe0', '0xe3838f593f60', '0xe3838f5931e0', '0xe3838f593560', '0xe3838f5946e0', '0xe3838f612d90', '0xe3838f6b01d0', '0xe3838f6b0c50', '0xe3838db9a530', '0xe3838f6b0630', '0xe38389aa1e70', '0xe3838f612710', '0xe38389aa26f0', '0xe3838f3bfa80', '0xe3838f596be0', '0xe3838f592fe2', '0xe3838f613dd0', '0xe3838f6dac10', '0xac85dc93f0f0', '0xac85dc93f0f0', '0xe3838e925ce0', '0xe3838f6b1430', '0xe3838e92f5e0', '0xe3838f6b0710', '0xe3838e8df080', '0xe3838e927960', '0xe3838e9294e0', '0xe3838e9279e0', '0xe3838e922c60', '0xe3838e922ee0', '0xe3838e9225e0', '0xe3838e921260', '0xe3838dbd2040', '0xe3838f6b02b0', '0xac85dec40920', '0xac85dec3fa40', '0xac85dd612460', '0xe3838f4993e0', '0xe3838e9272e0', '0xe3838ef96270', '0xe3838ef95670', '0xac85dec3fb50', '0xac85de0d2bc0', '0xe3838f6b0550', '0xe3838f6b09b0', '0xe3838d4dfa80', '0xe3838e8e2b94', '0xe3838f6afe50', '0xe3838f6b08d0', '0xe3838f6b1970', '0xe3838f6b0470', '0xe3838e92a2e0', '0xe3838fa349b0', '0xe3838f6b0a90', '0xe3838f6b0b70', '0xe3838f6b0d30', '0xe3838fa39190', '0xe3838f6b1a50', '0xe3838f6b23f0', '0xe3838f37e080', '0xe3838fa3b8a0', '0xe3838eb43080', '0xe3838e930160', '0xe3838f1c3080', '0xe3838ed846b2', '0xe3838f6b2a02', '0xe3838e930260', '0xe3838eff7080', '0xe3838fc5ed60', '0xe3838e931ce0', '0xe3838f580a60', '0xe3838f5818e0', '0xe3838fb5b540', '0xe3838f581ae0', '0xe3838f60e610', '0xe3838f581f60', '0xe3838f581b60', '0xe3838f581960', '0xe3838f60f0a0', '0xe3838fc7b1e0', '0xe3838d5e6080', '0xe383902665a4', '0xe3838fc73f60', '0xe3838fc77ee0', '0xe3838f580fe0', '0xe3838ec9a080', '0xe3838f5db080', '0xe3838f7eb080', '0xe3838f6e3080', '0xe3838f7a2080', '0xe3838efb2080', '0xe3838ef15080', '0xe3838fc6dfe0', '0xe3838fc60560', '0xe3838e8e4174', '0xe3838fc745e0', '0xe3838f5e2080', '0xe3838f7c0080', '0xe3838fc610e0', '0xe3838fc60be0', '0xe3838e92c8e0', '0xe38387d0f080', '0xe3838f356080', '0xe3838fc66c60', '0xe38390268b24', '0xe3838f57b060', '0xe3838fc5e360', '0xe3838fc73760', '0xe38390267864', '0xe3838fc6bde0', '0xe3838f48e360', '0xe3838e932de0', '0xe3838fc72860', '0xe3838f5797e0', '0xe38389844080', '0xe3838fbac080', '0xe3838fc75060', '0xe3838d4e1080', '0xe3838f758080', '0xe3838fb61080', '0xe3838fc6a9e0', '0xe3838d979f60', '0xe3838fc75e60', '0xe3838fc77460', '0xe3838f036080', '0xe3838fc75160', '0xe3838fc631e0', '0xe3838fc6d560', '0xe38389852080', '0xe3838fc6f060', '0xe3838d6c0080', '0xe3838f2ee080', '0xe3838f7dd080', '0xe383898bc080', '0xe3838dbd1080', '0xe3838fc5f0e0', '0xe3838fc70260', '0xe3838f2da960', '0xe3838e898080', '0xe3838d64b080', '0xe3838fc6f160', '0xe3838fc6fd60', '0xe3838fc63560', '0xe3838fc668e0', '0xe3838fb640c0', '0xe3838d63f080', '0xe3838ee216e0', '0xe3838fc73ee0', '0xe3838e9307e0', '0xe3838f5793e0', '0xe3838fc6e860', '0xe3838f489260', '0xe3838d9f5674', '0xe3838fc6fae0', '0xe3838e9d8080', '0xe3838d6942e0', '0xe3838fb6b080', '0xe3838f4d5080', '0xe3838ec61080', '0xe3838fc6e060', '0xe3838fc5e1e0', '0xe3838f2d04e0', '0xe3838f2d2860', '0xe3838f6e0080', '0xe3838fdd4760', '0xe3838fc7d360', '0xe3838fc5fe60', '0xe3838f76a080', '0xe3838fc73a60', '0xe3838dbf9080', '0xe3838f7aa080', '0xe3838fc020c0', '0xe3838fc77b60', '0xe3838fc5f060', '0xe3838f76e080', '0xe3838fbab080', '0xe3838ea64080', '0xe3838f35d080', '0xe3838fc0a080', '0xe3838fd61080', '0xe3838f492760', '0xe3838fc7aae0', '0xe3838fc6d9e0', '0xe3838fb54080', '0xe38389841080', '0xe3838f49a0e0', '0xe3838fc5fb60', '0xe3838fc632e0', '0xe3838fc708e0', '0xe3838ee042e0', '0xe3838f2db160', '0xe3838fc63d60', '0xe3838eae0080', '0xe3838eb9e080', '0xe3838f76f080', '0xe3838fc78160', '0xe3838e81f080', '0xe3838ee1b360', '0xe3838f57e760', '0xe3838f357080', '0xe3838db64080', '0xe3838f7e0080', '0xe3838e8e1424', '0xe3838f781080', '0xe3838f043080', '0xe3838eb9f080', '0xe3838fc86080', '0xe3838fc70560', '0xe38389653394', '0xe3838e930960', '0xe3838eddf080', '0xe3838db1c080', '0xe3838d64c080', '0xe3838fc6eee0', '0xe3838f76d080', '0xe3838f1bd080', '0xe3838f5f1080', '0xe3838fc73de0', '0xe3838fc0c080', '0xe3838f5e1080', '0xe3838fc6e4e0', '0xe3838fc701e0', '0xe3838e9306e0', '0xe3838d6a06e0', '0xe3838fdccc60', '0xe3838e9302e0', '0xe3838f2ce260', '0xe3838f578260', '0xe3838f2eb080', '0xe3838f48f260', '0xe38389851080', '0xe38389853080', '0xe3838fc766e0', '0xe3838fb66080', '0xe3838983c080', '0xe3838faeb0c0', '0xe3838fd59580', '0xe3838fc5ede0', '0xe3838fc6b5e0', '0xe383902660f4', '0xe3838fbb5080', '0xe3838fc659e0', '0xe3838d5e7080', '0xe3838e9d5080', '0xe3838db22080', '0xe3838f4a66e0', '0xe3838fc5ea60', '0xe3838fe70080', '0xe3838fc6f460', '0xe3838f57cf60', '0xe3838f76b080', '0xe3838fc6d460', '0xe3838fba8080', '0xe3838eb9b080', '0xe3838d6ac0e0', '0xe383896b9080', '0xe3838da1d080', '0xe3838fb68080', '0xe3838f4aa080', '0xe3838f5872e0', '0xe3838fbb4080', '0xe3838fc6ebe0', '0xe3838fc6b260', '0xe3838fc61060', '0xe3838964c4a4', '0xe3838fc6e7e0', '0xe3838ea92080', '0xe3838fc6e760', '0xe3838fe6c100', '0xe3838fbce300', '0xe3838f487660', '0xe3838f6ca080', '0xe3838fc675e0', '0xe3838fc6f560', '0xe3838d9a3080', '0xe3838ee045e0', '0xe3838fc6d3e0', '0xe3838e8e15b4', '0xe3838fc8d080', '0xe3838f48d660', '0xe3838f587fe0', '0xe3838edc40c0', '0xe3838f790080', '0xe3838fc6d4e0', '0xe3838fc75ce0', '0xe3838fc85080', '0xe3838fc7a760', '0xe3838f4a55e0', '0xe3838fc7f0c0', '0xe3838fd5d080', '0xe3838ee21360', '0xe3838fc7db60', '0xe3838fb750c0', '0xe3838f57a460', '0xe3838ee0d760', '0xe3838fbc1080', '0xe3838e84c080', '0xe3838faf8080', '0xe3838ee132e0', '0xe3838fe80080', '0xe3838f499460', '0xe3838fdd4fe0', '0xe3838fb6f080', '0xe3838fe77080', '0xe3838ec43080', '0xe38389650644', '0xe3838fc6b660', '0xe3838ef11080', '0xe3838fa7f080', '0xe3838f48d3e0', '0xe3838faec080', '0xe3838fdd5060', '0xe383906924f4', '0xe3838fc67760', '0xe38387cec080', '0xe3838eb89080', '0xe3838fdccae0', '0xe3838fc76160', '0xe3838f126080', '0xe383906910a4', '0xe3838fc6f7e0', '0xe38390691b94', '0xe3838f750080', '0xe3838fb6e080', '0xe3838fe7a080', '0xe3838f2ddbe0', '0xe3838f1e8080', '0xe3838fc6e3e0', '0xe3838964c4a4', '0xe3838ee191e0', '0xe3838fce7080', '0xe3838fd62080', '0xe3838fc8b080', '0xe3838f4920e0', '0xe3838f5ea0c0', '0xe3838fcec080', '0xe38390666da4', '0xe3838f499260', '0xe3838fc6f2e0', '0xe3838f78e080', '0xe3838fc8a080', '0xe3838fc61960', '0xe3838efac080', '0xe3838fe7c080', '0xe383892ce080', '0xe3838f5791e0', '0xe383906916e4', '0xe38389653394', '0xe383901de080', '0xe3838dbd2040', '0xe3839025e080', '0xe3838fbaf380', '0xe3838fdd5be0'], 

                'HandleValue': ['0x4', '0x8', '0xc', '0x10', '0x14', '0x18', '0x1c', '0x20', '0x24', '0x28', '0x2c', '0x30', '0x34', '0x38', '0x3c', '0x40', '0x44', '0x48', '0x4c', '0x50', '0x54', '0x58', '0x5c', '0x60', '0x64', '0x68', '0x6c', '0x70', '0x74', '0x78', '0x7c', '0x80', '0x84', '0x88', '0x8c', '0x90', '0x94', '0x98', '0x9c', '0xa0', '0xa4', '0xa8', '0xac', '0xb0', '0xb4', '0xb8', '0xbc', '0xc0', '0xc4', '0xc8', '0xcc', '0xd0', '0xd4', '0xd8', '0xdc', '0xe0', '0xe4', '0xe8', '0xec', '0xf0', '0xf4', '0xf8', '0xfc', '0x100', '0x104', '0x108', '0x10c', '0x110', '0x114', '0x118', '0x11c', '0x120', '0x124', '0x128', '0x12c', '0x130', '0x134', '0x138', '0x13c', '0x140', '0x144', '0x148', '0x14c', '0x150', '0x154', '0x158', '0x160', '0x164', '0x168', '0x16c', '0x170', '0x174', '0x178', '0x17c', '0x180', '0x184', '0x188', '0x18c', '0x190', '0x194', '0x198', '0x19c', '0x1a0', '0x1a4', '0x1a8', '0x1ac', '0x1b0', '0x1b4', '0x1b8', '0x1bc', '0x1c0', '0x1c4', '0x1c8', '0x1cc', '0x1d0', '0x1d4', '0x1d8', '0x1dc', '0x1e4', '0x1e8', '0x1ec', '0x1f0', '0x1f4', '0x1f8', '0x1fc', '0x200', '0x204', '0x208', '0x20c', '0x210', '0x214', '0x218', '0x21c', '0x220', '0x224', '0x228', '0x22c', '0x230', '0x234', '0x238', '0x23c', '0x240', '0x244', '0x248', '0x24c', '0x250', '0x254', '0x258', '0x25c', '0x260', '0x264', '0x268', '0x26c', '0x270', '0x274', '0x278', '0x27c', '0x280', '0x284', '0x288', '0x28c', '0x290', '0x294', '0x298', '0x29c', '0x2a0', '0x2a4', '0x2a8', '0x2ac', '0x2b0', '0x2b4', '0x2b8', '0x2bc', '0x2c0', '0x2c4', '0x2c8', '0x2cc', '0x2d0', '0x2d4', '0x2d8', '0x2dc', '0x2e0', '0x2e4', '0x2e8', '0x2ec', '0x2f0', '0x2f4', '0x2f8', '0x300', '0x304', '0x308', '0x30c', '0x310', '0x314', '0x318', '0x31c', '0x320', '0x324', '0x32c', '0x330', '0x334', '0x338', '0x33c', '0x4', '0x8', '0xc', '0x10', '0x14', '0x18', '0x1c', '0x20', '0x24', '0x28', '0x2c', '0x30', '0x34', '0x38', '0x3c', '0x40', '0x44', '0x48', '0x4c', '0x50', '0x54', '0x58', '0x5c', '0x60', '0x64', '0x68', '0x6c', '0x70', '0x74', '0x78', '0x7c', '0x80', '0x84', '0x88', '0x8c', '0x90', '0x94', '0x98', '0x9c', '0xa0', '0xa4', '0xa8', '0xac', '0xb0', '0xb4', '0xb8', '0xbc', '0xc0', '0xc4', '0xc8', '0xcc', '0xd0', '0xd4', '0xd8', '0xdc', '0xe0', '0xe4', '0xe8', '0xec', '0xf0', '0xf4', '0xf8', '0xfc', '0x100', '0x104', '0x108', '0x10c', '0x110', '0x114', '0x118', '0x11c', '0x120', '0x124', '0x128', '0x12c', '0x130', '0x134', '0x138', '0x13c', '0x140', '0x144', '0x148', '0x14c', '0x150', '0x154', '0x158', '0x15c', '0x160', '0x164', '0x168', '0x16c', '0x170', '0x174', '0x178', '0x17c', '0x180', '0x184', '0x188', '0x18c', '0x190', '0x194', '0x198', '0x19c', '0x1a0', '0x1a4', '0x1b0', '0x1b4', '0x1b8', '0x1bc', '0x1c0', '0x1c4', '0x1c8', '0x1cc', '0x1d0', '0x1d4', '0x1d8', '0x1dc', '0x1e0', '0x1e4', '0x1e8', '0x1ec', '0x1f0', '0x1f4', '0x1f8', '0x1fc', '0x200', '0x204', '0x208', '0x20c', '0x210', '0x214', '0x218', '0x21c', '0x220', '0x224', '0x228', '0x22c', '0x230', '0x234', '0x238', '0x23c', '0x240', '0x244', '0x248', '0x24c', '0x250', '0x254', '0x258', '0x25c', '0x260', '0x264', '0x268', '0x26c', '0x270', '0x274', '0x278', '0x27c', '0x280', '0x284', '0x288', '0x28c', '0x290', '0x294', '0x298', '0x2a4', '0x2a8', '0x2ac', '0x2b0', '0x2b4', '0x2b8', '0x2bc', '0x2c0', '0x2c4', '0x2c8', '0x2cc', '0x2d0', '0x2d8', '0x2dc', '0x2e0', '0x2e4', '0x2ec', '0x2f0', '0x2f4', '0x2f8', '0x2fc', '0x300', '0x304', '0x308', '0x30c', '0x310', '0x314', '0x318', '0x31c', '0x320', '0x328', '0x32c', '0x330', '0x334', '0x338', '0x33c', '0x340', '0x344', '0x348', '0x34c', '0x350', '0x358', '0x35c', '0x360', '0x364', '0x368', '0x36c', '0x370', '0x374', '0x378', '0x37c', '0x380', '0x38c', '0x390', '0x394', '0x398', '0x39c', '0x3a0', '0x3a4', '0x3a8', '0x3ac', '0x3b4', '0x3b8', '0x3bc', '0x3c0', '0x3c4', '0x3c8', '0x3cc', '0x3d0', '0x3d8', '0x3dc', '0x3e0', '0x3e4', '0x3e8', '0x3ec', '0x3f0', '0x3f4', '0x3f8', '0x3fc', '0x404', '0x408', '0x40c', '0x410', '0x414', '0x418', '0x41c', '0x420', '0x424', '0x428', '0x42c', '0x430', '0x434', '0x438', '0x43c', '0x440', '0x444', '0x448', '0x44c', '0x450', '0x454', '0x458', '0x45c', '0x460', '0x464', '0x468', '0x46c', '0x470', '0x474', '0x478', '0x47c', '0x480', '0x484', '0x488', '0x490', '0x494', '0x498', '0x49c', '0x4a4', '0x4a8', '0x4ac', '0x4b0', '0x4b4', '0x4b8', '0x4bc', '0x4c0', '0x4c4', '0x4c8', '0x4cc', '0x4d0', '0x4d4', '0x4d8', '0x4e4', '0x4ec', '0x4f4', '0x4f8', '0x4fc', '0x500', '0x504', '0x508', '0x50c', '0x510', '0x514', '0x518', '0x51c', '0x520', '0x524', '0x528', '0x530', '0x534', '0x538', '0x53c', '0x544', '0x548', '0x550', '0x554', '0x558', '0x55c', '0x560', '0x564', '0x568', '0x56c', '0x570', '0x574', '0x578', '0x57c', '0x580', '0x584', '0x588', '0x58c', '0x590', '0x594', '0x598', '0x59c', '0x5a0', '0x5a4', '0x5a8', '0x5ac', '0x5b4', '0x5b8', '0x5c0', '0x5c4', '0x5c8', '0x5cc', '0x5d0', '0x5d4', '0x5d8', '0x5dc', '0x5e0', '0x5e4', '0x5e8', '0x5ec', '0x5f0', '0x5f4', '0x5fc', '0x600', '0x604', '0x608', '0x60c', '0x610', '0x614', '0x618', '0x61c', '0x620', '0x624', '0x628', '0x62c', '0x630', '0x634', '0x638', '0x63c', '0x640', '0x644', '0x648', '0x64c', '0x650', '0x654', '0x658', '0x65c', '0x660', '0x664', '0x668', '0x66c', '0x674', '0x678', '0x67c', '0x684', '0x688', '0x68c', '0x690', '0x694', '0x698', '0x69c', '0x6a0', '0x6a8', '0x6ac', '0x6b0', '0x6b4', '0x6b8', '0x6bc', '0x6c4', '0x6c8', '0x6cc', '0x6d0', '0x6d4', '0x6d8', '0x6dc', '0x6e0', '0x6e4', '0x6ec', '0x6f4', '0x6f8', '0x6fc', '0x700', '0x704', '0x708', '0x70c', '0x710', '0x714', '0x718', '0x71c', '0x720', '0x724', '0x728', '0x72c', '0x734', '0x738', '0x73c', '0x740', '0x748', '0x74c', '0x750', '0x754', '0x75c', '0x760', '0x764', '0x768', '0x76c', '0x770', '0x778', '0x77c', '0x780', '0x784', '0x78c', '0x790', '0x794', '0x798', '0x7a0', '0x7a4', '0x7a8', '0x7ac', '0x7b0', '0x7b8', '0x7bc', '0x7c0', '0x7c4', '0x7cc', '0x7d0', '0x7d8', '0x7dc', '0x7e0', '0x7e4', '0x7e8', '0x7ec', '0x7f0', '0x7f4', '0x7fc', '0x810', '0x818', '0x81c', '0x824', '0x830', '0x840', '0x844', '0x84c', '0x850', '0x854', '0x858', '0x864', '0x86c', '0x870', '0x874', '0x878', '0x87c', '0x880', '0x884', '0x89c', '0x8a0', '0x8a8', '0x8ac', '0x8b4', '0x8bc', '0x8c0', '0x8c8', '0x8cc', '0x8d8', '0x8e0', '0x8e8', '0x8ec', '0x8f0', '0x8f4', '0x8f8', '0x900', '0x904', '0x908', '0x90c', '0x910', '0x940', '0x954', '0x960', '0x974', '0x978', '0x984', '0x988', '0x9a0', '0x9a8', '0x9b0', '0x9bc', '0x9c8', '0x9cc', '0x9d0', '0x9d8', '0x9dc', '0x9e8', '0x9f0', '0x9f8', '0xa04', '0xa08', '0xa20', '0xa24', '0xa3c', '0xa60', '0xa90', '0xa9c', '0xaa0', '0xab4', '0xabc', '0xac4', '0xad0', '0xb38', '0xb98', '0xbcc'], 

                'Type': ['Event', 'Event', 'WaitCompletionPacket', 'IoCompletion', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Event', 'Directory', 'File', 'Event', 'Directory', 'Event', 'WaitCompletionPacket', 'IoCompletion', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Event', 'Directory', 'Event', 'EtwRegistration', 'Mutant', 'ALPC Port', 'Directory', 'Semaphore', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'IoCompletion', 'Key', 'EtwRegistration', 'Key', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'File', 'Key', 'Key', 'Event', 'Key', 'Key', 'Key', 'WaitCompletionPacket', 'Event', 'Key', 'Key', 'Event', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Partition', 'WindowStation', 'Desktop', 'WindowStation', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'File', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Semaphore', 'Semaphore', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Semaphore', 'Semaphore', 'Semaphore', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Semaphore', 'File', 'Semaphore', 'Thread', 'Key', 'EtwRegistration', 'ALPC Port', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Section', 'Section', 'File', 'Event', 'Key', 'Event', 'Key', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Section', 'Semaphore', 'EtwRegistration', 'Key', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Key', 'Key', 'Semaphore', 'Event', 'Semaphore', 'Semaphore', 'Semaphore', 'Semaphore', 'EtwRegistration', 'EtwRegistration', 'Event', 'EtwRegistration', 'File', 'Event', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Thread', 'IoCompletion', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'ALPC Port', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'File', 'Section', 'Event', 'Event', 'WaitCompletionPacket', 'IoCompletion', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Event', 'Directory', 'File', 'Event', 'Directory', 'Event', 'WaitCompletionPacket', 'IoCompletion', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Event', 'Directory', 'File', 'EtwRegistration', 'Mutant', 'ALPC Port', 'Directory', 'Semaphore', 'EtwRegistration', 'EtwRegistration', 'IoCompletion', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'Key', 'Key', 'Event', 'Key', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'WaitCompletionPacket', 'EtwRegistration', 'Key', 'Key', 'Key', 'Event', 'Key', 'Key', 'Event', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Key', 'Key', 'EtwRegistration', 'Semaphore', 'Semaphore', 'Event', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'Thread', 'ALPC Port', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'WindowStation', 'Desktop', 'WindowStation', 'Key', 'Key', 'Key', 'Key', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Section', 'EtwRegistration', 'Key', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Key', 'EtwRegistration', 'EtwRegistration', 'Section', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Key', 'Key', 'Key', 'Key', 'Key', 'Key', 'Key', 'Thread', 'Event', 'Key', 'Event', 'Key', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'WaitCompletionPacket', 'Key', 'Key', 'Key', 'Key', 'Thread', 'File', 'IoCompletion', 'ALPC Port', 'IoCompletion', 'TpWorkerFactory', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'WaitCompletionPacket', 'EtwRegistration', 'Event', 'Thread', 'Thread', 'Event', 'ALPC Port', 'EtwRegistration', 'Event', 'Event', 'Event', 'WaitCompletionPacket', 'Event', 'WaitCompletionPacket', 'Event', 'Event', 'Event', 'WaitCompletionPacket', 'EtwRegistration', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'WaitCompletionPacket', 'EtwRegistration', 'EtwRegistration', 'TpWorkerFactory', 'EtwRegistration', 'IRTimer', 'WaitCompletionPacket', 'IRTimer', 'ALPC Port', 'Event', 'EtwConsumer', 'WaitCompletionPacket', 'ALPC Port', 'Section', 'Section', 'Event', 'EtwRegistration', 'Event', 'EtwRegistration', 'Thread', 'Event', 'Semaphore', 'Semaphore', 'Semaphore', 'Semaphore', 'Semaphore', 'Semaphore', 'Thread', 'EtwRegistration', 'Key', 'Key', 'Section', 'Event', 'Event', 'Mutant', 'Mutant', 'Key', 'Key', 'EtwRegistration', 'EtwRegistration', 'ALPC Port', 'DxgkSharedKeyedMutexObject', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'Event', 'File', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'File', 'EtwRegistration', 'EtwRegistration', 'Thread', 'File', 'Thread', 'Event', 'Thread', 'Desktop', 'EtwRegistration', 'Event', 'Thread', 'Event', 'Event', 'Event', 'Event', 'Thread', 'Event', 'WaitCompletionPacket', 'Event', 'Event', 'Event', 'WaitCompletionPacket', 'Event', 'Thread', 'Session', 'Event', 'Event', 'Event', 'Thread', 'Thread', 'Thread', 'Thread', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'EtwSessionDemuxEntry', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'ActivationObject', 'Event', 'Event', 'Event', 'Directory', 'Event', 'Event', 'Event', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Event', 'Thread', 'Event', 'Event', 'Event', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'UserApcReserve', 'Event', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Event', 'Thread', 'Event', 'Event', 'Event', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'Thread', 'Thread', 'Thread', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Thread', 'Event', 'Event', 'Thread', 'Thread', 'Thread', 'WmiGuid', 'Thread', 'Thread', 'Thread', 'Thread', 'Event', 'Mutant', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'Thread', 'Event', 'Thread', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'ALPC Port', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Event', 'Thread', 'Event', 'Event', 'Thread', 'Event', 'Thread', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Thread', 'Event', 'Thread', 'Event', 'Event', 'Event', 'Session', 'Event', 'Thread', 'Event', 'Thread', 'Thread', 'Event', 'Thread', 'Event', 'Event', 'Thread', 'Event', 'Event', 'Controller', 'Thread', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Thread', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Thread', 'Event', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Thread', 'Event', 'Event', 'Thread', 'Thread', 'Thread', 'WaitCompletionPacket', 'Event', 'Thread', 'Thread', 'Event', 'Thread', 'Event', 'Adapter', 'Event', 'Thread', 'Thread', 'Event', 'Event', 'Thread', 'RawInputManager', 'Event', 'Controller', 'Thread', 'Thread', 'Thread', 'Event', 'Thread', 'Event', 'Session', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'Thread', 'Thread', 'Controller', 'Event', 'Event', 'Thread', 'Thread', 'Event', 'Thread', 'Thread', 'Thread', 'Event', 'ActivationObject', 'Mutant', 'Thread', 'Thread', 'Thread', 'Thread', 'Event'], 

                'GrantedAccess': ['0x1f0003', '0x1f0003', '0x1', '0x1f0003', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x804', '0x804', '0x804', '0x1f0003', '0x1f0003', '0x3', '0x100020', '0x1f0003', '0x3', '0x1f0003', '0x1', '0x1f0003', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x804', '0x804', '0x804', '0x1f0003', '0x1f0003', '0x3', '0x1f0003', '0x804', '0x1f0001', '0x1f0001', '0xf', '0x1f0003', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x1f0003', '0x1', '0x804', '0x1', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x100020', '0x20019', '0x20019', '0x1f0003', '0x20019', '0x20019', '0x9', '0x1', '0x1f0003', '0x20019', '0x20019', '0x1f0003', '0x804', '0x804', '0x804', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x1f0003', '0xf037f', '0xf01ff', '0xf037f', '0x804', '0x804', '0x804', '0x100001', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x100003', '0x100003', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x100003', '0x100003', '0x100003', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x100003', '0x100020', '0x100003', '0x1fffff', '0x20019', '0x804', '0x1f0001', '0x804', '0x804', '0x804', '0x804', '0x4', '0x4', '0x100020', '0x1f0003', '0x20019', '0x1f0003', '0x20019', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x6', '0x100003', '0x804', '0xf003f', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x20019', '0x1', '0x100003', '0x1f0003', '0x100003', '0x100003', '0x100003', '0x100003', '0x804', '0x804', '0x1f0003', '0x804', '0x100001', '0x1f0003', '0x804', '0x804', '0x804', '0x804', '0x1f0003', '0x1fffff', '0x1f0003', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x1f0001', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x120089', '0xf0005', '0x1f0003', '0x1f0003', '0x1', '0x1f0003', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x804', '0x804', '0x804', '0x1f0003', '0x1f0003', '0x3', '0x100020', '0x1f0003', '0x3', '0x1f0003', '0x1', '0x1f0003', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x804', '0x804', '0x804', '0x1f0003', '0x1f0003', '0x3', '0x100020', '0x804', '0x1f0001', '0x1f0001', '0xf', '0x1f0003', '0x804', '0x804', '0x1f0003', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x1', '0x9', '0x1f0003', '0x20019', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x1f0003', '0x1', '0x804', '0xf003f', '0x20019', '0x20019', '0x1f0003', '0x20019', '0x20019', '0x1f0003', '0x804', '0x804', '0x804', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x1f0003', '0x20019', '0x20019', '0x804', '0x100003', '0x100003', '0x1f0003', '0x804', '0x804', '0x804', '0x1f0003', '0x1fffff', '0x1f0001', '0x804', '0x804', '0x804', '0xf016e', '0xf00cf', '0xf016e', '0x1', '0xf003f', '0x20019', '0x20019', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x6', '0x804', '0x1', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0xf003f', '0x804', '0x804', '0xf0007', '0x804', '0x804', '0x804', '0x1', '0x20019', '0x20019', '0x20019', '0x20019', '0x20019', '0x20019', '0x1fffff', '0x1f0003', '0xf003f', '0x1f0003', '0xf003f', '0x804', '0x804', '0x804', '0x1f0003', '0x1', '0x20019', '0x20019', '0x20019', '0x20019', '0x1fffff', '0x100080', '0x1f0003', '0x1f0001', '0x1f0003', '0xf00ff', '0x100002', '0x1', '0x100002', '0x1', '0x804', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0001', '0x804', '0x1f0003', '0x1f0003', '0x1f0003', '0x1', '0x1f0003', '0x1', '0x1f0003', '0x1f0003', '0x1f0003', '0x1', '0x804', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1', '0x804', '0x804', '0xf00ff', '0x804', '0x100002', '0x1', '0x100002', '0x1f0001', '0x1f0003', '0x1f0003', '0x1', '0x1f0001', '0x4', '0x4', '0x1f0003', '0x804', '0x1f0003', '0x804', '0x1fffff', '0x1f0003', '0x100003', '0x100003', '0x100003', '0x100003', '0x100003', '0x100003', '0x1fffff', '0x804', '0x2001f', '0x20019', '0xf0007', '0x1f0003', '0x1f0003', '0x1f0001', '0x1f0001', '0x20019', '0x20019', '0x804', '0x804', '0x1f0001', '0x16019f', '0x804', '0x804', '0x804', '0x804', '0x1f0003', '0x100003', '0x804', '0x804', '0x804', '0x100001', '0x804', '0x804', '0x1fffff', '0x100001', '0x1fffff', '0x1f0003', '0x1fffff', '0x12019f', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1', '0x1f0003', '0x1f0003', '0x1f0003', '0x1', '0x1f0003', '0x1fffff', '0x16019f', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x16019f', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x16019f', '0x1f0003', '0x1f0003', '0x1f0003', '0x16019f', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x16019f', '0x1f0003', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x16019f', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x16019f', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x16019f', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1f0003', '0x16019f', '0x1f0003', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x16019f', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x16019f', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1f0003', '0x16019f', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1f0003', '0x1fffff', '0x16019f', '0x1f0003', '0x16019f', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1f0003', '0x16019f', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x16019f', '0x1f0003', '0x1f0003', '0x1fffff', '0x1fffff', '0x1f0003', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003', '0x16019f', '0x16019f', '0x1fffff', '0x1fffff', '0x1fffff', '0x1fffff', '0x1f0003'],

                'Name': ['', '', '', '', '', '', '', '', '', '', '', '', '', '', 'KnownDlls', '\\Device\\HarddiskVolume2\\Windows', '', 'KnownDlls32', '', '', '', '', '', '', '', '', '', '', '', '', '', 'KnownDlls32', '', '', 'SM0:3872:168:WilStaging_02', '', 'BaseNamedObjects', 'SM0:3872:168:WilStaging_02_p0', '', '', '', '', '', '', '', '', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\CUSTOMLOCALE', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\SESSION MANAGER', '', '', '', '', '', '\\Device\\HarddiskVolume2\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_a8625c1886757984', 'MACHINE', 'MACHINE\\SOFTWARE\\MICROSOFT\\OLE', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\SORTING\\VERSIONS', 'MACHINE', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', '', '', 'USER\\S-1-5-21-2929926106-2179945841-3936977681-1001_CLASSES\\LOCAL SETTINGS\\SOFTWARE\\MICROSOFT', 'USER\\S-1-5-21-2929926106-2179945841-3936977681-1001_CLASSES\\LOCAL SETTINGS', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'WinSta0', 'Default', 'WinSta0', '', '', '', '\\Device\\HarddiskVolume2\\Windows\\System32\\en-US\\MFC42.dll.mui', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '\\Device\\HarddiskVolume2\\ProgramData\\jnzkfmhxqqp252', '', 'Tid 4952 Pid 3872', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\SORTING\\IDS', '', '', '', '', '', '', 'Theme1447555304', 'Theme226775073', '\\Device\\HarddiskVolume2\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_a8625c1886757984', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\WINSOCK2\\PARAMETERS\\PROTOCOL_CATALOG9', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\WINSOCK2\\PARAMETERS\\NAMESPACE_CATALOG5', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'windows_shell_global_counters', '', '', 'USER\\S-1-5-21-2929926106-2179945841-3936977681-1001', '', '', '', '', '', '', 'MACHINE\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\FOLDERDESCRIPTIONS\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\\PROPERTYBAG', 'USER\\S-1-5-21-2929926106-2179945841-3936977681-1001\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER', '', '', '', '', '', '', '', '', '', '', '\\Device\\CNG', '', '', '', '', '', '', 'Tid 4952 Pid 3872', '', '', '', '', '', '', '', '', '', '', '', '', '', '\\Device\\HarddiskVolume2\\Windows\\Fonts\\StaticCache.dat', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'KnownDlls', '\\Device\\HarddiskVolume2\\Windows', '', 'KnownDlls32', '', '', '', '', '', '', '', '', '', '', '', '', '', 'KnownDlls32', '\\Device\\HarddiskVolume2\\Windows\\SysWOW64', '', 'SM0:4568:168:WilStaging_02', '', 'BaseNamedObjects', 'SM0:4568:168:WilStaging_02_p0', '', '', '', '', '', '', '', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\SESSION MANAGER', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\SORTING\\VERSIONS', '', '', '', '', '', '', '', '', '', '', '', '', '', 'MACHINE', 'MACHINE', 'MACHINE\\SOFTWARE\\MICROSOFT\\OLE', '', 'USER\\.DEFAULT\\SOFTWARE\\CLASSES\\LOCAL SETTINGS\\SOFTWARE\\MICROSOFT', 'USER\\.DEFAULT\\SOFTWARE\\CLASSES\\LOCAL SETTINGS', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'USER\\.DEFAULT\\CONTROL PANEL\\INTERNATIONAL', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\SORTING\\IDS', '', '', '', '', '', '', '', '', 'Tid 4576 Pid 4568', '', '', '', '', 'Service-0x0-3e7$', 'Default', 'Service-0x0-3e7$', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\CUSTOMLOCALE', 'USER\\.DEFAULT', 'USER\\.DEFAULT\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS', 'MACHINE\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\5.0\\CACHE', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'windows_shell_global_counters', '', 'USER\\.DEFAULT\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER', '', '', '', '', '', '', 'USER', '', '', '', '', '', '', 'MACHINE\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\INTERNET EXPLORER\\MAIN\\FEATURECONTROL', 'MACHINE\\SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS', 'MACHINE\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS', 'MACHINE\\SOFTWARE\\POLICIES', 'USER\\.DEFAULT\\SOFTWARE\\POLICIES', 'USER\\.DEFAULT\\SOFTWARE', 'MACHINE\\SOFTWARE\\WOW6432NODE', 'Tid 4576 Pid 4568', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\WINSOCK2\\PARAMETERS\\PROTOCOL_CATALOG9', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\WINSOCK2\\PARAMETERS\\NAMESPACE_CATALOG5', '', '', '', '', '', 'USER\\.DEFAULT\\SOFTWARE\\MICROSOFT\\INTERNET EXPLORER\\MAIN', 'MACHINE\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\INTERNET EXPLORER\\MAIN', 'MACHINE\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\INTERNET EXPLORER\\SECURITY', 'MACHINE\\SOFTWARE\\POLICIES\\MICROSOFT\\INTERNET EXPLORER\\MAIN', 'Tid 2728 Pid 4568', '\\Device\\Nsi', '', '', '', '', '', '', '', '', '', '', 'Tid 4356 Pid 4568', 'Tid 2224 Pid 4568', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'F932B6C7-3A20-46A0-B8A0-8894AA421973', 'F932B6C7-3A20-46A0-B8A0-8894AA421973', '', '', '', '', 'Tid 4972 Pid 4568', '', '', '', '', '', '', '', 'Tid 1152 Pid 4568', '', 'USER\\.DEFAULT\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP', 'MACHINE\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP', 'UrlZonesSM_DESKTOP-VAN74KL$', '', '', 'ZonesCacheCounterMutex', 'ZonesLockedCacheCounterMutex', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\TCPIP\\PARAMETERS\\INTERFACES', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\TCPIP6\\PARAMETERS\\INTERFACES', '', '', '', '', '', '', '', '', '', '\\Device\\KsecDD', '', '', '', '\\Device\\KsecDD', '', '', 'Tid 4572 Pid 4568', '\\Device\\CNG', 'Tid 4900 Pid 4568', '', 'Tid 3624 Pid 4568', '', '', '', 'Tid 4020 Pid 4568', '', '', '', '', 'Tid 4536 Pid 4568', '', '', '', '', '', '', '', 'Tid 3956 Pid 4568', '', '', '', '', 'Tid 4160 Pid 4568', 'Tid 2504 Pid 4568', 'Tid 3644 Pid 4568', 'Tid 4416 Pid 4568', 'Tid 2516 Pid 4568', 'Tid 1216 Pid 4568', 'Tid 4776 Pid 4568', '', '', '', '', 'Tid 4488 Pid 4568', 'Tid 4040 Pid 4568', '', '', '', 'Tid 4248 Pid 4568', 'Tid 2840 Pid 4568', '', '', '', '', '', '', '', '', '', '', '', 'Tid 1952 Pid 4568', 'Tid 3540 Pid 4568', '', 'Tid 2576 Pid 4568', 'Tid 1844 Pid 4568', 'Tid 4068 Pid 4568', '', '', '', '', 'Tid 2188 Pid 4568', '', '', '', 'Tid 2836 Pid 4568', '', 'Tid 4076 Pid 4568', 'Tid 4956 Pid 4568', 'Tid 5088 Pid 4568', 'Tid 4644 Pid 4568', 'Tid 1196 Pid 4568', '', '', '', 'Tid 4528 Pid 4568', 'Tid 4916 Pid 4568', '', '', '', '', 'Tid 3268 Pid 4568', 'Tid 3804 Pid 4568', '', '', '', '', '', '', '', '', 'Tid 4164 Pid 4568', '', 'Tid 4808 Pid 4568', 'Tid 1016 Pid 4568', 'Tid 4256 Pid 4568', '', '', '', '', 'Tid 4556 Pid 4568', '', '', '', 'Tid 3564 Pid 4568', '', 'Tid 3336 Pid 4568', 'Tid 4820 Pid 4568', 'Tid 748 Pid 4568', '', '', 'Tid 3092 Pid 4568', 'Tid 580 Pid 4568', 'Tid 4604 Pid 4568', 'Tid 3748 Pid 4568', 'Tid 4816 Pid 4568', 'Tid 4552 Pid 4568', '', '', '', 'Tid 4100 Pid 4568', 'Tid 3364 Pid 4568', '', '', '', '', '', '', '', 'Tid 936 Pid 4568', 'Tid 1392 Pid 4568', 'Tid 2408 Pid 4568', '', 'Tid 3536 Pid 4568', '', '', 'Tid 3848 Pid 4568', 'Tid 4448 Pid 4568', 'Tid 3248 Pid 4568', '', 'Tid 2680 Pid 4568', 'Tid 2788 Pid 4568', 'Tid 3588 Pid 4568', 'Tid 4080 Pid 4568', '', '', '', 'Tid 4264 Pid 4568', 'Tid 1180 Pid 4568', 'Tid 1420 Pid 4568', '', 'Tid 3620 Pid 4568', 'Tid 3692 Pid 4568', 'Tid 3484 Pid 4568', '', 'Tid 4224 Pid 4568', 'Tid 3988 Pid 4568', '', '', '', '', '', '', '', '', 'Tid 1804 Pid 4568', '', 'Tid 3236 Pid 4568', 'Tid 992 Pid 4568', '', 'Tid 4936 Pid 4568', 'Tid 2956 Pid 4568', 'Tid 4452 Pid 4568', 'Tid 2624 Pid 4568', '', '', '', 'Tid 4960 Pid 4568', '', 'Tid 3324 Pid 4568', 'Tid 4628 Pid 4568', 'Tid 628 Pid 4568', '', '', 'Tid 2484 Pid 4568', '', '', 'Tid 2640 Pid 4568', '', 'Tid 3464 Pid 4568', 'Tid 4848 Pid 4568', '', 'Tid 2528 Pid 4568', 'Tid 524 Pid 4568', 'Tid 4024 Pid 4568', 'Tid 4896 Pid 4568', '', 'Tid 2860 Pid 4568', '', '', '', '', '', 'Tid 4784 Pid 4568', '', 'Tid 4968 Pid 4568', 'Tid 4192 Pid 4568', '', 'Tid 3108 Pid 4568', '', '', 'Tid 4744 Pid 4568', '', '', '', 'Tid 3576 Pid 4568', '', '', 'Tid 1284 Pid 4568', 'Tid 4804 Pid 4568', '', '', 'Tid 4560 Pid 4568', '', '', 'Tid 2828 Pid 4568', 'Tid 3212 Pid 4568', '', '', 'Tid 3584 Pid 4568', '', '', 'Tid 952 Pid 4568', 'Tid 2524 Pid 4568', 'Tid 3632 Pid 4568', '', 'Tid 2184 Pid 4568', '', '', 'Tid 1640 Pid 4568', 'Tid 4480 Pid 4568', 'Tid 1868 Pid 4568', '', '', 'Tid 4404 Pid 4568', 'Tid 2412 Pid 4568', '', 'Tid 1048 Pid 4568', '', '', '', 'Tid 4584 Pid 4568', 'Tid 2540 Pid 4568', '', '', 'Tid 2372 Pid 4568', '', '', '', 'Tid 5000 Pid 4568', 'Tid 2620 Pid 4568', 'Tid 2996 Pid 4568', '', 'Tid 3188 Pid 4568', '', '', '', 'Tid 4516 Pid 4568', 'Tid 4196 Pid 4568', 'Tid 2676 Pid 4568', '', 'Tid 5064 Pid 4568', 'Tid 3640 Pid 4568', '', '', '', 'Tid 1880 Pid 4568', 'Tid 4412 Pid 4568', '', 'Tid 4300 Pid 4568', 'Tid 4460 Pid 4568', 'Tid 4104 Pid 4568', '', '', '', 'Tid 4760 Pid 4568', 'Tid 1152 Pid 4568', 'Tid 2904 Pid 4568', 'Tid 4964 Pid 4568', '']
                }, 
        
            'dict_malfind': {},

            'iocs': {
                'ldrmod': ['\\Users\\mbuhkeder\\Desktop\\@WanaDecryptor@.exe', '\\Windows\\System32\\en-US\\MFC42.dll.mui'], 

                'wanna_file': ['\\Python27\\Lib\\site-packages\\pyftpdlib-1.5.6-py2.7.egg-info\\SOURCES.txt.WNCRYT', '\\Python27.x86\\Lib\\idlelib\\idle_test\\README.txt.WNCRYT', '\\Python27\\Lib\\test\\cjkencodings\\iso2022_jp-utf8.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\hu.msg.WNCRYT', '\\Python27\\tcl\\tk8.5\\msgs\\it.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\lv.msg.WNCRYT', '\\Python27\\Lib\\site-packages\\urllib3-1.26.11.dist-info\\LICENSE.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\pl.msg.WNCRYT', '\\Python27\\Tools\\pynche\\namedcolors.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\cs.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\sq.msg.WNCRYT', '\\Python27\\tcl\\tk8.5\\msgs\\sv.msg.WNCRYT', '\\Python27\\LICENSE.txt.WNCRYT', '\\Python27\\Lib\\lib2to3\\Grammar.txt.WNCRYT', '\\Python27\\tcl\\tk8.5\\msgs\\fr.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\gv.msg.WNCRYT', '\\Python37\\Tools\\pynche\\webcolors.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\nl.msg.WNCRYT', '\\Python27\\Lib\\test\\formatfloat_testcases.txt.WNCRYT', '\\Python27\\Tools\\versioncheck\\README.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\ja.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\mk.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\vi.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\sv.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\is.msg.WNCRYT', '\\Python27\\tcl\\tk8.5\\demos\\en.msg.WNCRYT', '\\Python27\\tcl\\tk8.5\\demos\\nl.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\zh.msg.WNCRYT', '\\Python37\\Lib\\site-packages\\numpy\\LICENSE.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\numpy\\random\\tests\\data\\philox-testset-2.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-cityblock-ml-iris.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\conemu-maximus5\\ConEmu\\License.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-jensenshannon-ml-iris.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-euclidean-ml-iris.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-minkowski-3.2-ml-iris.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\random-bool-data.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-spearman-ml.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\wine_data.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\iris.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\boston_house_prices.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\breast_cancer.csv.WNCRYT', '\\Python37\\Lib\\test\\test_email\\data\\msg_07.txt.WNCRYT', '\\Python37\\Lib\\test\\test_email\\data\\msg_43.txt.WNCRYT', '\\Python37\\Lib\\test\\test_email\\data\\msg_22.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\ar.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\ar_jo.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\be.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\bg.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\et.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\fi.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\he.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\fr.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\ga.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\gv.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\hi.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\ta.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\uk.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\he.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\tr.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\zh.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\vi.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\hr.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\hi.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\hu.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\sh.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\th.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\perl5\\core_perl\\unicore\\SpecialCasing.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_31.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_32.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\vim9.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\syntax.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\os_amiga.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\message.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_43.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\map.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\mbyte.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_45.txt.WNCRYT'],

                'filescan': ['\\Python27\\Lib\\site-packages\\pyftpdlib-1.5.6-py2.7.egg-info\\SOURCES.txt.WNCRYT', '\\Python27.x86\\Lib\\idlelib\\idle_test\\README.txt.WNCRYT', '\\Python27\\Lib\\test\\cjkencodings\\iso2022_jp-utf8.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\hu.msg.WNCRYT', '\\Python27\\tcl\\tk8.5\\msgs\\it.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\lv.msg.WNCRYT', '\\Python27\\Lib\\site-packages\\urllib3-1.26.11.dist-info\\LICENSE.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\pl.msg.WNCRYT', '\\Python27\\Tools\\pynche\\namedcolors.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\cs.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\sq.msg.WNCRYT', '\\ProgramData\\jnzkfmhxqqp252\\00000000.eky', '\\Python27\\tcl\\tk8.5\\msgs\\sv.msg.WNCRYT', '\\Python27\\LICENSE.txt.WNCRYT', '\\Python27\\Lib\\lib2to3\\Grammar.txt.WNCRYT', '\\Python27\\tcl\\tk8.5\\msgs\\fr.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\gv.msg.WNCRYT', '\\Python37\\Tools\\pynche\\webcolors.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\nl.msg.WNCRYT', '\\Python27\\Lib\\test\\formatfloat_testcases.txt.WNCRYT', '\\Python27\\Tools\\versioncheck\\README.txt.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\ja.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\mk.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\vi.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\sv.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\is.msg.WNCRYT', '\\Python27\\tcl\\tk8.5\\demos\\en.msg.WNCRYT', '\\Python27\\tcl\\tk8.5\\demos\\nl.msg.WNCRYT', '\\Python27\\tcl\\tcl8.5\\msgs\\zh.msg.WNCRYT', '\\Python37\\Lib\\site-packages\\numpy\\LICENSE.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\numpy\\random\\tests\\data\\philox-testset-2.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-cityblock-ml-iris.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\conemu-maximus5\\ConEmu\\License.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-jensenshannon-ml-iris.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-euclidean-ml-iris.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-minkowski-3.2-ml-iris.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\random-bool-data.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\scipy\\spatial\\tests\\data\\pdist-spearman-ml.txt.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\wine_data.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\iris.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\boston_house_prices.csv.WNCRYT', '\\Python37\\Lib\\site-packages\\sklearn\\datasets\\data\\breast_cancer.csv.WNCRYT', '\\Python37\\Lib\\test\\test_email\\data\\msg_07.txt.WNCRYT', '\\Python37\\Lib\\test\\test_email\\data\\msg_43.txt.WNCRYT', '\\Python37\\Lib\\test\\test_email\\data\\msg_22.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\ar.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\ar_jo.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\be.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\bg.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\et.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\fi.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\he.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\fr.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\ga.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\gv.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\hi.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\ta.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\uk.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\he.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\tr.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\zh.msg.WNCRYT', '\\Python37\\tcl\\tcl8.6\\msgs\\vi.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\hr.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\hi.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\hu.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\sh.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\mingw64\\lib\\tcl8.6\\msgs\\th.msg.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\perl5\\core_perl\\unicore\\SpecialCasing.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_31.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_32.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\vim9.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\syntax.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\os_amiga.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\message.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_43.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\map.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\mbyte.txt.WNCRYT', '\\Tools\\Cmder\\vendor\\git-for-windows\\usr\\share\\vim\\vim82\\doc\\usr_45.txt.WNCRYT'], 

                'mutex': [], 

                'wanna_path': []
                },

            'smb_port': 445, 

            'smb_pid': 4568, 

            'ldrmod': {
                'Pid': [3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 3872, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568, 4568], 

                'Process': ['@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan', 'Ransomware.wan'], 

                'Base': ['0x73aa0000', '0x400000', '0xaa0000', '0x73260000', '0x731c0000', '0x73720000', '0x735c0000', '0x73340000', '0x73660000', '0x737e0000', '0x737a0000', '0x73880000', '0x73800000', '0x73890000', '0x75c10000', '0x74760000', '0x74250000', '0x73cd0000', '0x73cb0000', '0x74020000', '0x742c0000', '0x752d0000', '0x74c90000', '0x74a90000', '0x74a20000', '0x74ad0000', '0x74cc0000', '0x75b00000', '0x75840000', '0x75be0000', '0x77400000', '0x76a00000', '0x76810000', '0x75e70000', '0x75cd0000', '0x76250000', '0x76960000', '0x768b0000', '0x76900000', '0x769d0000', '0x76f50000', '0x76c60000', '0x76a80000', '0x76b80000', '0x76d10000', '0x77250000', '0x77040000', '0x771c0000', '0x773f0000', '0x7ffc34370000', '0x7ffc34e30000', '0x7ffc34c40000', '0x400000', '0x73ea0000', '0x73bd0000', '0x73cb0000', '0x73c10000', '0x73be0000', '0x73c20000', '0x73cd0000', '0x73e80000', '0x75c10000', '0x74a30000', '0x74250000', '0x73f20000', '0x73ec0000', '0x73ff0000', '0x74020000', '0x74720000', '0x742c0000', '0x74a20000', '0x74c90000', '0x74ad0000', '0x74a80000', '0x74ae0000', '0x74b00000', '0x75840000', '0x74cc0000', '0x752d0000', '0x75be0000', '0x75b00000', '0x75c00000', '0x77400000', '0x76d10000', '0x76960000', '0x75e70000', '0x75cd0000', '0x768b0000', '0x76810000', '0x76900000', '0x76a00000', '0x76c60000', '0x77040000', '0x76f50000', '0x76f30000', '0x77250000', '0x771c0000', '0x773f0000', '0x7ffc34370000', '0x7ffc34e30000', '0x7ffc34c40000'], 

                'InLoad': [False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, True, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, True, True],

                'InInit': [False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, True, True], 

                'InMem': [False, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, True, True, True, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, True, True, True], 

                'MappedPath': ['\\Windows\\SysWOW64\\mfc42.dll', '\\Users\\mbuhkeder\\Desktop\\@WanaDecryptor@.exe', '\\Windows\\System32\\en-US\\MFC42.dll.mui', '\\Windows\\SysWOW64\\WinTypes.dll', '\\Windows\\SysWOW64\\TextShaping.dll', '\\Windows\\SysWOW64\\uxtheme.dll', '\\Windows\\SysWOW64\\CoreMessaging.dll', '\\Windows\\SysWOW64\\CoreUIComponents.dll', '\\Windows\\SysWOW64\\TextInputFramework.dll', '\\Windows\\SysWOW64\\usp10.dll', '\\Windows\\SysWOW64\\msls31.dll', '\\Windows\\SysWOW64\\riched32.dll', '\\Windows\\SysWOW64\\riched20.dll', '\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_a8625c1886757984\\comctl32.dll', '\\Windows\\SysWOW64\\msvcrt.dll', '\\Windows\\SysWOW64\\apphelp.dll', '\\Windows\\SysWOW64\\msvcp60.dll', '\\Windows\\SysWOW64\\urlmon.dll', '\\Windows\\SysWOW64\\srvcli.dll', '\\Windows\\SysWOW64\\iertutil.dll', '\\Windows\\SysWOW64\\wininet.dll', '\\Windows\\SysWOW64\\advapi32.dll', '\\Windows\\SysWOW64\\wldp.dll', '\\Windows\\SysWOW64\\ntmarta.dll', '\\Windows\\SysWOW64\\netutils.dll', '\\Windows\\SysWOW64\\kernel.appcore.dll', '\\Windows\\SysWOW64\\windows.storage.dll', '\\Windows\\SysWOW64\\gdi32full.dll', '\\Windows\\SysWOW64\\combase.dll', '\\Windows\\SysWOW64\\win32u.dll', '\\Windows\\SysWOW64\\ntdll.dll', '\\Windows\\SysWOW64\\sechost.dll', '\\Windows\\SysWOW64\\oleaut32.dll', '\\Windows\\SysWOW64\\rpcrt4.dll', '\\Windows\\SysWOW64\\user32.dll', '\\Windows\\SysWOW64\\shell32.dll', '\\Windows\\SysWOW64\\ws2_32.dll', '\\Windows\\SysWOW64\\shlwapi.dll', '\\Windows\\SysWOW64\\bcryptprimitives.dll', '\\Windows\\SysWOW64\\imm32.dll', '\\Windows\\SysWOW64\\kernel32.dll', '\\Windows\\SysWOW64\\gdi32.dll', '\\Windows\\SysWOW64\\ole32.dll', '\\Windows\\SysWOW64\\msctf.dll', '\\Windows\\SysWOW64\\KernelBase.dll', '\\Windows\\SysWOW64\\ucrtbase.dll', '\\Windows\\SysWOW64\\msvcp_win.dll', '\\Windows\\SysWOW64\\SHCore.dll', '\\Windows\\System32\\wow64cpu.dll', '\\Windows\\System32\\wow64.dll', '\\Windows\\System32\\ntdll.dll', '\\Windows\\System32\\wow64win.dll', '\\Users\\mbuhkeder\\Desktop\\Ransomware.wannacry.exe', '\\Windows\\SysWOW64\\dhcpcsvc6.dll', '\\Windows\\SysWOW64\\cryptbase.dll', '\\Windows\\SysWOW64\\srvcli.dll', '\\Windows\\SysWOW64\\rasadhlp.dll', '\\Windows\\SysWOW64\\rsaenh.dll', '\\Windows\\SysWOW64\\dnsapi.dll', '\\Windows\\SysWOW64\\urlmon.dll', '\\Windows\\SysWOW64\\dhcpcsvc.dll', '\\Windows\\SysWOW64\\msvcrt.dll', '\\Windows\\SysWOW64\\OnDemandConnRouteHelper.dll', '\\Windows\\SysWOW64\\msvcp60.dll', '\\Windows\\SysWOW64\\winhttp.dll', '\\Windows\\SysWOW64\\mswsock.dll', '\\Windows\\SysWOW64\\sspicli.dll', '\\Windows\\SysWOW64\\iertutil.dll', '\\Windows\\SysWOW64\\IPHLPAPI.DLL', '\\Windows\\SysWOW64\\wininet.dll', '\\Windows\\SysWOW64\\netutils.dll', '\\Windows\\SysWOW64\\wldp.dll', '\\Windows\\SysWOW64\\kernel.appcore.dll', '\\Windows\\SysWOW64\\winnsi.dll', '\\Windows\\SysWOW64\\profapi.dll', '\\Windows\\SysWOW64\\cryptsp.dll', '\\Windows\\SysWOW64\\combase.dll', '\\Windows\\SysWOW64\\windows.storage.dll', '\\Windows\\SysWOW64\\advapi32.dll', '\\Windows\\SysWOW64\\win32u.dll', '\\Windows\\SysWOW64\\gdi32full.dll', '\\Windows\\SysWOW64\\nsi.dll', '\\Windows\\SysWOW64\\ntdll.dll', '\\Windows\\SysWOW64\\KernelBase.dll', '\\Windows\\SysWOW64\\ws2_32.dll', '\\Windows\\SysWOW64\\rpcrt4.dll', '\\Windows\\SysWOW64\\user32.dll', '\\Windows\\SysWOW64\\shlwapi.dll', '\\Windows\\SysWOW64\\oleaut32.dll', '\\Windows\\SysWOW64\\bcryptprimitives.dll', '\\Windows\\SysWOW64\\sechost.dll', '\\Windows\\SysWOW64\\gdi32.dll', '\\Windows\\SysWOW64\\msvcp_win.dll', '\\Windows\\SysWOW64\\kernel32.dll', '\\Windows\\SysWOW64\\bcrypt.dll', '\\Windows\\SysWOW64\\ucrtbase.dll', '\\Windows\\SysWOW64\\SHCore.dll', '\\Windows\\System32\\wow64cpu.dll', '\\Windows\\System32\\wow64.dll', '\\Windows\\System32\\ntdll.dll', '\\Windows\\System32\\wow64win.dll']
                }
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
    elif malware == "wannacryv2":
        t = malzclass.WannaCryV2(filepath=filePath, outputpath="./outputtest")
        autoDict = t.run()
        with open('templates/generateReportAutoWanncryV2.html', 'r') as template_file:
            template_content = template_file.read()
        
        pid_content = ''
        for value in autoDict['pid']:
            pid_row = '<tr>'
            pid_row += f'<td>{value}</td>'
            pid_row += '</tr>'
            pid_content += pid_row
        html_content = template_content.replace('{SUSPID_CONTENT}', pid_content)

        html_content = html_content.replace('{SMB_PORT}', str(autoDict['smb_port']))
        html_content = html_content.replace('{SMB_PID}', str(autoDict['smb_pid']))

        index = 0
        pidall_content = ''
        for value in autoDict['pid']:
            pidall_row = '<tr>'
            pidall_row += f'<td>{value}</td>'
            pidall_row += f'<td>{autoDict["process_name"][index]}</td>'
            pidall_row += '</tr>'
            pidall_content += pidall_row
            index+=1
            if index >= len(autoDict["process_name"]):
                index = 0
        html_content = html_content.replace('{PID_CONTENT}', pidall_content)

        if len(autoDict['hidden_pid']) == 0:
            html_content = html_content.replace('{HIDPID}', "kosong")
        else:
            hidpid_content = ''
            for value in autoDict['hidden_pid']:
                hidpid_row = '<tr>'
                hidpid_row += f'<td>{value}</td>'
                hidpid_row += '</tr>'
                hidpid_content += hidpid_row
            html_content = html_content.replace('{HIDPID}', hidpid_content)

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
        for value in filescan_autoDict['Hive Offset']:
                filescan_row = '<tr>'
                filescan_row += f'<td>{filescan_autoDict["Last Write Time"][index]}</td>'
                filescan_row += f'<td>{value}</td>'
                filescan_row += f'<td>{filescan_autoDict["Type"][index]}</td>'
                filescan_row += f'<td>{filescan_autoDict["Key"][index]}</td>'
                filescan_row += f'<td>{filescan_autoDict["Name"][index]}</td>'
                filescan_row += f'<td>{filescan_autoDict["Data"][index]}</td>'
                filescan_row += f'<td>{filescan_autoDict["Volatile"][index]}</td>'
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

        mutexioc_autoDict = autoDict.get('iocs', {})
        if len(mutexioc_autoDict['mutex']) == 0:
            html_content = html_content.replace('{MUTEX_CONTENT}', "kosong")
        else:
            index = 0
            mutexioc_content = ''
            for value in mutexioc_autoDict['mutex']:
                mutexioc_row = '<tr>'
                mutexioc_row += f'<td>{value}</td>'
                mutexioc_row += '</tr>'
                mutexioc_content += mutexioc_row
                index+=1
            html_content = html_content.replace('{MUTEX_CONTENT}', mutexioc_content)
# wanna_path
        if len(mutexioc_autoDict['wanna_path']) == 0:
            html_content = html_content.replace('{WANNAPATH_CONTENT}', "kosong")
        else:
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
            summary_row += f'<td>{value}</td>'
            summary_row += f'<td>{autoDict["process_name"][index]}</td>'
            summary_row += f'<td>{autoDict["malware_types"][index]}</td>'
            summary_row += '</tr>'
            summary_content += summary_row
            index+=1
            if index >= len(autoDict["process_name"]):
                index = 0
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

    print(argsForm)
    data_dict = vol3.run(command,filePath,"./outputtest",argsForm)
    return jsonify(data_dict)


@app.route("/<cmd>")
def commandtest(cmd):
    return f"<h1>{cmd}</h1>"


if __name__ == "__main__":
    app.run(debug=True)
