from volatility3.framework import contexts
from volatility3.framework import automagic
from volatility3 import framework
from volatility3.framework import interfaces
from volatility3.cli import MuteProgress
from volatility3.framework import plugins
from volatility3.cli import CommandLine as cmd
import volatility3
from volatility3.cli import text_renderer, volargparse
from volatility3.framework import interfaces
import os
import volatility3.framework.constants
from urllib import request
# from volatility3.framework.configuration import requirements
from volatility3.cli import text_renderer
# from tabulate import tabulate

VOLDATA = {}

"""
{'windows.statistics.Statistics': <class 'volatility3.plugins.windows.statistics.Statistics'>, 
'timeliner.Timeliner': <class 'volatility3.plugins.timeliner.Timeliner'>, 
'windows.pslist.PsList': <class 'volatility3.plugins.windows.pslist.PsList'>, 
'windows.handles.Handles': <class 'volatility3.plugins.windows.handles.Handles'>, 
'windows.poolscanner.PoolScanner': <class 'volatility3.plugins.windows.poolscanner.PoolScanner'>, 
'windows.bigpools.BigPools': <class 'volatility3.plugins.windows.bigpools.BigPools'>, 
'windows.registry.hivescan.HiveScan': <class 'volatility3.plugins.windows.registry.hivescan.HiveScan'>, 
'windows.registry.hivelist.HiveList': <class 'volatility3.plugins.windows.registry.hivelist.HiveList'>, 
'windows.registry.printkey.PrintKey': <class 'volatility3.plugins.windows.registry.printkey.PrintKey'>, 
'windows.registry.certificates.Certificates': <class 'volatility3.plugins.windows.registry.certificates.Certificates'>, 
'layerwriter.LayerWriter': <class 'volatility3.plugins.layerwriter.LayerWriter'>, 
'banners.Banners': <class 'volatility3.plugins.banners.Banners'>,
'isfinfo.IsfInfo': <class 'volatility3.plugins.isfinfo.IsfInfo'>, 
'configwriter.ConfigWriter': <class 'volatility3.plugins.configwriter.ConfigWriter'>, 
'frameworkinfo.FrameworkInfo': <class 'volatility3.plugins.frameworkinfo.FrameworkInfo'>, 
'windows.vadinfo.VadInfo': <class 'volatility3.plugins.windows.vadinfo.VadInfo'>,
'windows.skeleton_key_check.Skeleton_Key_Check': <class 'volatility3.plugins.windows.skeleton_key_check.Skeleton_Key_Check'>, 
'windows.virtmap.VirtMap': <class 'volatility3.plugins.windows.virtmap.VirtMap'>, 
'windows.info.Info': <class 'volatility3.plugins.windows.info.Info'>, 
'windows.psscan.PsScan': <class 'volatility3.plugins.windows.psscan.PsScan'>, 
'windows.dlllist.DllList': <class 'volatility3.plugins.windows.dlllist.DllList'>, 
'windows.modscan.ModScan': <class 'volatility3.plugins.windows.modscan.ModScan'>, 
'windows.sessions.Sessions': <class 'volatility3.plugins.windows.sessions.Sessions'>, 
'windows.dumpfiles.DumpFiles': <class 'volatility3.plugins.windows.dumpfiles.DumpFiles'>, 
'windows.envars.Envars': <class 'volatility3.plugins.windows.envars.Envars'>,
'windows.symlinkscan.SymlinkScan': <class 'volatility3.plugins.windows.symlinkscan.SymlinkScan'>, 
'windows.joblinks.JobLinks': <class 'volatility3.plugins.windows.joblinks.JobLinks'>, 
'windows.cmdline.CmdLine': <class 'volatility3.plugins.windows.cmdline.CmdLine'>, 
'windows.memmap.Memmap': <class 'volatility3.plugins.windows.memmap.Memmap'>, 
'windows.getsids.GetSIDs': <class 'volatility3.plugins.windows.getsids.GetSIDs'>, 
'windows.modules.Modules': <class 'volatility3.plugins.windows.modules.Modules'>, 
'windows.verinfo.VerInfo': <class 'volatility3.plugins.windows.verinfo.VerInfo'>, 
'windows.netscan.NetScan': <class 'volatility3.plugins.windows.netscan.NetScan'>, 
'windows.driverscan.DriverScan': <class 'volatility3.plugins.windows.driverscan.DriverScan'>, 
'windows.filescan.FileScan': <class 'volatility3.plugins.windows.filescan.FileScan'>, 
'windows.ldrmodules.LdrModules': <class 'volatility3.plugins.windows.ldrmodules.LdrModules'>, 
'windows.netstat.NetStat': <class 'volatility3.plugins.windows.netstat.NetStat'>, 
'windows.getservicesids.GetServiceSIDs': <class 'volatility3.plugins.windows.getservicesids.GetServiceSIDs'>, 
'windows.pstree.PsTree': <class 'volatility3.plugins.windows.pstree.PsTree'>, 
'windows.mutantscan.MutantScan': <class 'volatility3.plugins.windows.mutantscan.MutantScan'>, 
'windows.ssdt.SSDT': <class 'volatility3.plugins.windows.ssdt.SSDT'>, 
'windows.callbacks.Callbacks': <class 'volatility3.plugins.windows.callbacks.Callbacks'>, 
'windows.privileges.Privs': <class 'volatility3.plugins.windows.privileges.Privs'>, 
'windows.driverirp.DriverIrp': <class 'volatility3.plugins.windows.driverirp.DriverIrp'>, 
'windows.crashinfo.Crashinfo': <class 'volatility3.plugins.windows.crashinfo.Crashinfo'>, 
'windows.devicetree.DeviceTree': <class 'volatility3.plugins.windows.devicetree.DeviceTree'>, 
'windows.strings.Strings': <class 'volatility3.plugins.windows.strings.Strings'>, 
'windows.mbrscan.MBRScan': <class 'volatility3.plugins.windows.mbrscan.MBRScan'>, 
'windows.malfind.Malfind': <class 'volatility3.plugins.windows.malfind.Malfind'>, 
'windows.registry.userassist.UserAssist': <class 'volatility3.plugins.windows.registry.userassist.UserAssist'>}
"""

def renderersEx(grid: interfaces.renderers.TreeGrid):
    global VOLDATA

    if VOLDATA:
        VOLDATA.clear()
    
    # get the key
    for column in grid.columns:
        VOLDATA[column.name] = []
    
    # visit node 
    def visitor(node: interfaces.renderers.TreeGrid, accumulator):
        objecttest = grid.values(node)
        index = 0
        for key in VOLDATA.keys():
            if objecttest[index].__class__.__name__ == "NotApplicableValue":
                VOLDATA[key].append("N/A")
            elif objecttest[index].__class__.__name__ == "UnreadableValue" or objecttest[index].__class__.__name__ == "UnparsableValue" :
                VOLDATA[key].append("-")
            else:
                VOLDATA[key].append(objecttest[index])
            index+=1
        return None

    grid.populate(visitor)

def byteToString(listOfData):
     lenOfData = len(listOfData)

     for idx in range(lenOfData):
          data = listOfData[idx]
          if isinstance(data, bytes):
               strbyte = text_renderer.multitypedata_as_text(data)
               listOfData[idx] = strbyte

def intToHex(listOfData):
     lenOfData = len(listOfData)

     for idx in range(lenOfData):
        numb = listOfData[idx]
        if isinstance(numb, int):
            listOfData[idx] = hex(listOfData[idx])
        else:
             listOfData[idx] = "N/A"

def disasmToHex(dictOfData, key):
    disasm = dictOfData["Disasm"]
    data = []

    for dis in disasm:
        try:
            strdis = text_renderer.display_disassembly(dis)
            data.append(strdis)
        except:
            continue
    
    dictOfData[key] = data

def hexDumpBytes(dictOfData, key):
    hexaData = dictOfData['Hexdump']
    
    readableChar = []

    for h in hexaData:
        strtemp = ""
        try:
            strdata = text_renderer.hex_bytes_as_text(h)
            strtemp += strdata
            readableChar.append(strtemp)
        except:
            strtemp += ""
    dictOfData[key] = readableChar

def run(pluginName, filePath, outputPath, argument):
    volatility3.framework.require_interface_version(2, 0, 0)
    renderers = dict(
                [
                    (x.name.lower(), x)
                    for x in framework.class_subclasses(text_renderer.CLIRenderer)
                ]
            )
    # render_mode = "quick"
    parser = volargparse.HelpfulArgParser(add_help = False, prog = "volatility", description = "An open-source memory forensics framework")
    context = contexts.Context()
    failures = framework.import_files(
                volatility3.plugins, True
            )
    automagics = automagic.available(context)
    cmds = cmd()
    # plugin list harus setelah automagic supaya ada list pluginnya
    plugin_list = framework.list_plugins()
    seen_automagics = set()
    chosen_configurables_list = {}
    for amagic in automagics:
                chosen_configurables_list[amagic.__class__.__name__] = amagic
    for amagic in automagics:
                if amagic in seen_automagics:
                    continue
                seen_automagics.add(amagic)
                if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
                    cmd.populate_requirements_argparse(cmds, parser, amagic.__class__)

    subparser = parser.add_subparsers(title = "Plugins",
                                            dest = "plugin",
                                            description = "For plugin specific options, run '{} <plugin> --help'".format(
                                                "volatility"),
                                            action = volargparse.HelpfulSubparserAction)
    for plugin in sorted(plugin_list):
                plugin_parser = subparser.add_parser(plugin, help = plugin_list[plugin].__doc__)
                cmd.populate_requirements_argparse(cmds, plugin_parser, plugin_list[plugin])
    
    args = parser.parse_args()
    
    # "windows.malfind.Malfind"
    args.plugin = pluginName
    # set output dir
    args.output_dir = outputPath
    # "wanncry.vmem"
    args.file = filePath
    if pluginName == "windows.netscan.NetScan":
        # [1340]
        if argument:
            args.pid = [argument[0]]
    elif pluginName == "windows.modules.Modules":
         if argument:
              args.dump = argument[0]
    elif pluginName == "windows.pslist.PsList":
        if argument:
            args.physical = argument[0]
            args.pid = [argument[1]]
            args.dump = argument[2]
    elif pluginName == "windows.pstree.PsTree":
        if argument:
            args.physical = argument[0]
            args.pid = argument[1]
    elif pluginName == "windows.psscan.PsScan":
        if argument:
            args.physical = argument[0]
            args.pid = [argument[1]]
            args.dump = argument[2]
    elif pluginName == "windows.dlllist.DllList":
        if argument:
            # harus dalam list
            args.pid = [argument[0]]
            args.dump = argument[1]
    elif pluginName == "windows.handles.Handles":
        if argument:
            args.pid = [argument[0]]
    elif pluginName == "windows.registry.printkey.PrintKey":
        if argument:
            # args.offset = argument[0]
            args.key = argument[0]
            # args.recurse = argument[2]
    elif pluginName == "windows.malfind.Malfind":
        if argument:
            args.pid = [argument[0]]
            args.dump = argument[1]
    elif pluginName == "windows.cmdline.CmdLine":
        if argument:
            args.pid = [argument[0]]
    elif pluginName == "windows.netstat.NetStat":
         if argument:
            args.include_corrupt = argument[0]

    plugin = plugin_list[args.plugin]
    chosen_configurables_list[args.plugin] = plugin

    # config_path = automagic.choose_automagic(automagics, plugin)

    base_config_path = "plugins"
    plugin_config_path = interfaces.configuration.path_join(
                base_config_path, plugin.__name__
            )

    # set output dir
    cmds.output_dir = args.output_dir
 
    file_name = os.path.abspath(args.file)
    if not os.path.exists(file_name):
                    print("File does not exist")
    else:
        single_location = "file:" + request.pathname2url(file_name)
        context.config['automagic.LayerStacker.single_location'] = single_location

    for amagic in automagics:
        chosen_configurables_list[amagic.__class__.__name__] = amagic

    cmd.populate_config(cmds, context, chosen_configurables_list, args, plugin_config_path)
    progress_callback = MuteProgress()
    constructed = plugins.construct_plugin(context, automagics, plugin, base_config_path, progress_callback, cmds.file_handler_class_factory())
    treegrid = constructed.run()
    
    renderersEx(grid=treegrid)

    for key in VOLDATA.keys():
        if key == "Size" or key == "Base" or key == "Offset" or key == "HandleValue" or key == "GrantedAccess" or key == "Hive Offset" or key == "Offset(V)" or key == "Start VPN" or key == "End VPN":
            intToHex(VOLDATA[key])
        elif key == "Data":
            byteToString(VOLDATA[key])
        elif key == "Hexdump":
             hexDumpBytes(VOLDATA, key)
        elif key == "Disasm":
             disasmToHex(VOLDATA, key)
        else:
             continue

    return VOLDATA

if __name__ == '__main__':
     run()