from volatility3.framework import contexts
from volatility3.framework import automagic
from volatility3 import framework
from volatility3.framework import interfaces
from volatility3.cli import PrintedProgress, MuteProgress
from volatility3.framework import plugins
from volatility3.cli import CommandLine as cmd
import volatility3
from volatility3.cli import text_renderer, volargparse
from volatility3.framework import interfaces
import os
import volatility3.framework.constants
import argparse, inspect
import binascii
from typing import Dict, Type, Union, Any
from urllib import parse, request
from volatility3.framework.configuration import requirements
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

def populate_requirements_argparse(parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup],
                                       configurable: Type[interfaces.configuration.ConfigurableInterface]):
        """Adds the plugin's simple requirements to the provided parser.

        Args:
            parser: The parser to add the plugin's (simple) requirements to
            configurable: The plugin object to pull the requirements from
        """
        if not issubclass(configurable, interfaces.configuration.ConfigurableInterface):
            raise TypeError("Expected ConfigurableInterface type, not: {}".format(type(configurable)))

        # Construct an argparse group

        for requirement in configurable.get_requirements():
            additional = {}  # type: Dict[str, Any]
            if not isinstance(requirement, interfaces.configuration.RequirementInterface):
                raise TypeError("Plugin contains requirements that are not RequirementInterfaces: {}".format(
                    configurable.__name__))
            if isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
                additional["type"] = requirement.instance_type
                if isinstance(requirement, requirements.IntRequirement):
                    additional["type"] = lambda x: int(x, 0)
                if isinstance(requirement, requirements.BooleanRequirement):
                    additional["action"] = "store_true"
                    if "type" in additional:
                        del additional["type"]
            elif isinstance(requirement, volatility3.framework.configuration.requirements.ListRequirement):
                additional["type"] = requirement.element_type
                nargs = '*' if requirement.optional else '+'
                additional["nargs"] = nargs
            elif isinstance(requirement, volatility3.framework.configuration.requirements.ChoiceRequirement):
                additional["type"] = str
                additional["choices"] = requirement.choices
            else:
                continue
            parser.add_argument("--" + requirement.name.replace('_', '-'),
                                help = requirement.description,
                                default = requirement.default,
                                dest = requirement.name,
                                required = not requirement.optional,
                                **additional)

def populate_config(context: interfaces.context.ContextInterface,
                        configurables_list: Dict[str, Type[interfaces.configuration.ConfigurableInterface]],
                        args: argparse.Namespace, plugin_config_path: str) -> None:
        """Populate the context config based on the returned args.

        We have already determined these elements must be descended from ConfigurableInterface

        Args:
            context: The volatility3 context to operate on
            configurables_list: A dictionary of configurable items that can be configured on the plugin
            args: An object containing the arguments necessary
            plugin_config_path: The path within the context's config containing the plugin's configuration
        """
        vargs = vars(args)
        for configurable in configurables_list:
            for requirement in configurables_list[configurable].get_requirements():
                value = vargs.get(requirement.name, None)
                if value is not None:
                    if isinstance(requirement, requirements.URIRequirement):
                        if isinstance(value, str):
                            scheme = parse.urlparse(value).scheme
                            if not scheme or len(scheme) <= 1:
                                if not os.path.exists(value):
                                    raise FileNotFoundError(
                                        "Non-existant file {} passed to URIRequirement".format(value))
                                value = "file://" + request.pathname2url(os.path.abspath(value))
                    if isinstance(requirement, requirements.ListRequirement):
                        if not isinstance(value, list):
                            raise TypeError("Configuration for ListRequirement was not a list: {}".format(
                                requirement.name))
                        value = [requirement.element_type(x) for x in value]
                    if not inspect.isclass(configurables_list[configurable]):
                        config_path = configurables_list[configurable].config_path
                    else:
                        # We must be the plugin, so name it appropriately:
                        config_path = plugin_config_path
                    extended_path = interfaces.configuration.path_join(config_path, requirement.name)
                    context.config[extended_path] = value

def renderersEx(grid: interfaces.renderers.TreeGrid, pluginName):
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
            elif objecttest[index].__class__.__name__ == "UnreadableValue" :
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
               strbyte = data.decode('utf-16')
               listOfData[idx] = strbyte

def intToHex(listOfData):
     lenOfData = len(listOfData)

     for idx in range(lenOfData):
        listOfData[idx] = hex(listOfData[idx])

def hexToAscii(dictOfData, key):
    hex = dictOfData["Hexdump"]
    strList = []

    for h in hex:
        bytes_data = bytes.fromhex(h)
        strdata = ""
        for byte in bytes_data:
            if byte >= 32 and byte <= 126:
                strdata += chr(byte)
            else:
                strdata += "."
        
        strList.append(strdata)

    dictOfData[key] = strList

def disasmToHex(dictOfData, key):
    disasm = dictOfData["Disasm"]
    data = []

    for dis in disasm:
        strdis = text_renderer.display_disassembly(dis)
        data.append(strdis)
    
    dictOfData[key] = data

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
                    populate_requirements_argparse(parser, amagic.__class__)

    subparser = parser.add_subparsers(title = "Plugins",
                                            dest = "plugin",
                                            description = "For plugin specific options, run '{} <plugin> --help'".format(
                                                "volatility"),
                                            action = volargparse.HelpfulSubparserAction)
    for plugin in sorted(plugin_list):
                plugin_parser = subparser.add_parser(plugin, help = plugin_list[plugin].__doc__)
                populate_requirements_argparse(plugin_parser, plugin_list[plugin])
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
            args.pid = argument[0]
            args.dump = argument[1]
    elif pluginName == "windows.cmdline.CmdLine":
        if argument:
            args.pid = [argument[0]]

    plugin = plugin_list[args.plugin]
    chosen_configurables_list[args.plugin] = plugin

    # config_path = automagic.choose_automagic(automagics, plugin)

    base_config_path = "plugins"
    plugin_config_path = interfaces.configuration.path_join(
                base_config_path, plugin.__name__
            )
    
    cmds = cmd()

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

    populate_config(context, chosen_configurables_list, args, plugin_config_path)
    progress_callback = MuteProgress()
    constructed = plugins.construct_plugin(context, automagics, plugin, base_config_path, progress_callback, cmds.file_handler_class_factory())
    treegrid = constructed.run()
    
    renderersEx(grid=treegrid, pluginName=pluginName)

    for key in VOLDATA.keys():
        if key == "Size" or key == "Base" or key == "Offset" or key == "HandleValue" or key == "GrantedAccess" or key == "Hive Offset" or key == "Offset(V)":
            intToHex(VOLDATA[key])
        elif key == "Data":
            byteToString(VOLDATA[key])
        elif key == "Hexdump":
             disasmToHex(VOLDATA, key)
        elif key == "Disasm":
             hexToAscii(VOLDATA, key)
        else:
             continue
    
    return VOLDATA

if __name__ == '__main__':
     run()