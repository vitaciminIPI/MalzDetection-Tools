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
        session["fileNameOri"] = file_name
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
        'info': {'header21': 'Value 21', 'header2': 'Value 2'},
        'ipv4': ['83.212.99.68', '131.188.40.189', '204.11.50.131', '94.130.200.167'],
        'dict_cmdline': {'PID': [2340, 2464, 1340, 1588, 2664, 2752, 2092], 
                         'Process': ['@WanaDecryptor', 'WannaCry.EXE', 'explorer.exe', 'vmtoolsd.exe', 'taskmgr.exe', '@WanaDecryptor', 'taskhsvc.exe'], 
                         'Args': ['@WanaDecryptor@.exe co', '"C:\\Users\\labib\\Desktop\\WannaCry.EXE" ', 'C:\\Windows\\Explorer.EXE', '"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr', '"C:\\Windows\\system32\\taskmgr.exe" /4', '@WanaDecryptor@.exe', 'TaskData\\Tor\\taskhsvc.exe']},
        'hidden_pid': [1340, 2464, 2340],
        'sus_pid': [2340, 2464, 1340, 1588, 2664, 2752, 2092],
        'dict_dlllist':{'PID': [2340, 2340, 2340, 2340, 2340, 2464, 1340, 1588, 2664, 2752, 2092],
                        'Process': ['@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', 'WannaCry.EXE', 'explorer.exe', 'vmtoolsd.exe', 'taskmgr.exe', '@WanaDecryptor', 'taskhsvc.exe'], 
                        'Base': ['0x400000', '0x77200000', '0x74e90000', '0x74070000', '0x74ee0000', '0x400000', '0xfff90000', '0x13fda0000', '0xff0c0000', '0x400000', '0xaf0000'], 
                        'Size': ['0x3d000', '0x1a9000', '0x3f000', '0x5c000', '0x8000', '0x35a000', '0x2c0000', '0x18000', '0x45000', '0x3d000', '0x2fe000'], 
                        'Name': ['@WanaDecryptor@.exe', 'ntdll.dll', 'wow64.dll', 'wow64win.dll', 'wow64cpu.dll', 'WannaCry.EXE', 'Explorer.EXE', 'vmtoolsd.exe', 'taskmgr.exe', '@WanaDecryptor@.exe', 'taskhsvc.exe'], 
                        'Path': ['C:\\Users\\labib\\Desktop\\@WanaDecryptor@.exe', 'C:\\Windows\\SYSTEM32\\ntdll.dll', 'C:\\Windows\\SYSTEM32\\wow64.dll', 'C:\\Windows\\SYSTEM32\\wow64win.dll', 'C:\\Windows\\SYSTEM32\\wow64cpu.dll', 'C:\\Users\\labib\\Desktop\\WannaCry.EXE', 'C:\\Windows\\Explorer.EXE', 'C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe', 'C:\\Windows\\system32\\taskmgr.exe', 'C:\\Users\\labib\\Desktop\\@WanaDecryptor@.exe', 'C:\\Users\\labib\\Desktop\\TaskData\\Tor\\taskhsvc.exe'], 
                        'LoadTime': ['N/A', 'N/A', 'datetime.datetime(2021, 2, 22, 17, 52, 25)', 'datetime.datetime(2021, 2, 22, 17, 52, 25)', 'datetime.datetime(2021, 2, 22, 17, 52, 25)', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'], 
                        'File output': ['Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled', 'Disabled']},
        'dict_handles': 
                        {'PID': [2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2340, 2464, 1340, 1588, 2664, 2752, 2092],
                         'Process': ['@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', '@WanaDecryptor', 'WannaCry.EXE', 'explorer.exe', 'vmtoolsd.exe', 'taskmgr.exe', '@WanaDecryptor', 'taskhsvc.exe'], 
                         'Offset': ['0xf8a002477f60', '0xf8a000325790', '0xf8a003683eb0', '0xfa8001f63d10', '0xf8a001744630', '0xf8a003683eb0', '0xfa8001b88b20', '0xfa80020ff750', '0xf8a0023dd250', '0xfa8001f69e60', '0xf8a002003060', '0xfa8001f5c990', '0xfa8002076dc0', '0xfa8001ebc630', '0xf8a002443a10', '0xfa8001b2d360', '0xfa8001dd2fb0', '0xfa8001fad490', '0xfa80019e0600', '0xfa8001a32d30', '0xfa80019e0600', '0xf8a001fa7e00', '0xfa8001e098d0', '0xfa80006f4cd0', '0xfa8001df4fe0', '0xfa8001e7d260', '0xfa8000b77c80', '0xfa8001adee90', '0xfa8000718270', '0xf8a001547eb0', '0xfa8001b8de20', '0xf8a001f6fb00', '0xfa8001dbbaf0', '0xfa8001b415b0', '0xfa80020f1640', '0xfa8001dbafb0', '0xfa8001bb99b0', '0xfa8000ffa4e0', '0xfa80020efeb0', '0xfa8001b3de50', '0xfa8001afa7c0', '0xfa8001bca8b0', '0xfa8001f9cbb0', '0xfa8000a4c960', '0xfa8000f91ca0', '0xf8a0017e1b90', '0xf8a00284ade0', '0xf8a001892750', '0xf8a002439680', '0xfa8000c57d50', '0xfa8001dfa4d0', '0xfa80019aa7d0', '0xf8a001d9d5a0', '0xfa8001e7d2f0', '0xf8a001589330', '0xfa800105a060', '0xfa8001ae0cb0', '0xf8a0026375a0', '0xfa8001ebf390', '0xf8a0026306f0', '0xfa8000fef5c0', '0xfa8001b56730', '0xfa80017ee830', '0xfa8002176140', '0xfa8002023e80', '0xfa80019a0a10', '0xf8a001d95ae0', '0xf8a001d28650', '0xf8a001dde4c0', '0xf8a001fc2500', '0xf8a0025536e0', '0xf8a00259da30'], 
                         'HandleValue': ['0x4', '0x8', '0xc', '0x10', '0x14', '0x18', '0x1c', '0x20', '0x24', '0x28', '0x2c', '0x30', '0x34', '0x38', '0x3c', '0x40', '0x44', '0x48', '0x4c', '0x50', '0x54', '0x58', '0x5c', '0x60', '0x64', '0x68', '0x6c', '0x70', '0x74', '0x78', '0x7c', '0x80', '0x84', '0x88', '0x8c', '0x90', '0x94', '0x98', '0x9c', '0xa0', '0xa4', '0xa8', '0xac', '0xb0', '0xb4', '0xb8', '0xbc', '0xc0', '0xc4', '0xc8', '0xcc', '0xd0', '0xd4', '0xd8', '0xdc', '0xe0', '0xe4', '0xe8', '0xec', '0xf0', '0xf4', '0xf8', '0xfc', '0x100', '0x104', '0x108', '0x4', '0x4', '0x4', '0x4', '0x4', '0x4'], 
                         'Type': ['Key', 'Directory', 'Directory', 'File', 'Key', 'Directory', 'File', 'File', 'Key', 'ALPC Port', 'Key', 'Semaphore', 'Semaphore', 'Mutant', 'Key', 'Event', 'EtwRegistration', 'Event', 'WindowStation', 'Desktop', 'WindowStation', 'Key', 'EtwRegistration', 'Event', 'Event', 'Event', 'Event', 'Event', 'Event', 'Directory', 'File', 'Key', 'File', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'EtwRegistration', 'ALPC Port', 'Section', 'Key', 'Key', 'Key', 'EtwRegistration', 'EtwRegistration', 'File', 'Section', 'File', 'Section', 'Thread', 'Event', 'Key', 'Event', 'Key', 'Event', 'File', 'File', 'IoCompletion', 'Event', 'Event', 'Key', 'Key', 'Key', 'Key', 'Key', 'Key'], 
                         'GrantedAccess': ['0x9', '0x3', '0x3', '0x100020', '0x9', '0x3', '0x100020', '0x100020', '0x20019', '0x1f0001', '0x1', '0x100003', '0x100003', '0x1f0001', '0x20019', '0x1f0003', '0x804', '0x21f0003', '0xf037f', '0xf01ff', '0xf037f', '0x1', '0x804', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0x1f0003', '0xf', '0x120089', '0xf003f', '0x120089', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x804', '0x1f0001', '0x4', '0x20019', '0x20019', '0x20019', '0x804', '0x804', '0x100020', '0x6', '0x120089', '0xf0005', '0x1fffff', '0x1f0003', '0x20019', '0x1f0003', '0x20019', '0x1f0003', '0x16019f', '0x212019f', '0x21f0003', '0x1f0003', '0x100003', '0x9', '0x9', '0x9', '0x9', '0x9', '0x9'], 
                         'Name': ['MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', 'KnownDlls', 'KnownDlls32', '\\Device\\HarddiskVolume1\\Windows', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', 'KnownDlls32', '\\Device\\HarddiskVolume1\\Users\\labib\\Desktop', '\\Device\\HarddiskVolume1\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\SORTING\\VERSIONS', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\SESSION MANAGER', '', '', '', 'MACHINE', '', '', '', 'WinSta0', 'Default', 'WinSta0', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\CUSTOMLOCALE', '', '', '', '', '', '', '', 'BaseNamedObjects', '\\Device\\HarddiskVolume1\\Windows\\SysWOW64\\en-US\\odbcint.dll.mui', 'USER\\S-1-5-21-2222247560-3146130292-765576430-1000', '\\Device\\HarddiskVolume1\\Windows\\SysWOW64\\en-US\\MFC42.dll.mui', '', '', '', '', '', '', '', '', '', '', '', '', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\LOCALE', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\LOCALE\\ALTERNATE SORTS', 'MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\NLS\\LANGUAGE GROUPS', '', '', '\\Device\\HarddiskVolume1\\Windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2', 'windows_shell_global_counters', '\\Device\\HarddiskVolume1\\Windows\\Fonts\\StaticCache.dat', '', 'Tid 2280 Pid 2340', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\WINSOCK2\\PARAMETERS\\PROTOCOL_CATALOG9', '', 'MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\WINSOCK2\\PARAMETERS\\NAMESPACE_CATALOG5', '', '\\Device\\Afd\\Endpoint', '\\Device\\Afd\\AsyncConnectHlp', '', '', '', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS', 'MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS']},
        'registry': 
                        [['datetime.datetime(2021, 2, 16, 10, 6, 38)', '0xf8a0012f1010', 'REG_SZ',  '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'VMware VM3DService Process', '"C:\\Windows\\system32\\vm3dservice.exe" -u', False], ['datetime.datetime(2021, 2, 16, 10, 6, 38)', '0xf8a0012f1010', 'REG_SZ', '\\SystemRoot\\System32\\Config\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'VMware User Process', '"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr', False]],
        'pid': [2340, 2464, 2752],
        'process_name': ['@WanaDecryptor', 'WannaCry.EXE', '@WanaDecryptor'],
        'malware_types': ['ransomware.wanna/wannacryptor', 'trojan.wannacry/wannacryptor', 'trojan.wannacry/wannacryptor']
    }
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
    # print(autoDict)
    with open('templates/generateReportAuto.html', 'r') as template_file:
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
    # print(filePath)
    fileNameOri = session.get('fileNameOri')
    print(fileNameOri)
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
