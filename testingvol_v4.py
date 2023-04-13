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
import sys, os, json
import volatility3.framework.constants
import argparse, inspect
from typing import Dict, Type, Union, Any
from urllib import parse, request
from volatility3.framework.configuration import requirements
# from tabulate import tabulate
 
dictlist = {
    "PID" : [],
    "PPID" : [],
    "Image": [],
    "Offset": [],
    "Threads": [],
    "Handles": [],
    "SessionId": [],
    "Wow64": [],
    "CreateTime": [],
    "ExitTime": [],
    "FileOutPut": [],
}

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

def renderersEx(grid: interfaces.renderers.TreeGrid):
    line = []
    outfd = sys.stdout
    # for column in grid.columns:
        # line.append(f"{column.name}")
        # print(column.name, end= "\t")
        # print(column.name)
    
    def visitor(node: interfaces.renderers.TreeGrid, accumulator):
        # line = []
        # print("*" * max(0, node.path_depth - 1), end = " ")
        # grid.values(node) --> buat ngeprint smua isi node 
        # print(f"{grid.values(node)[0]} \t {grid.values(node)[1]}")
        # myDict = {
        #     "PID" : grid.values(node)[0]
        # }
        objecttest = grid.values(node)
        print(objecttest)
        # index = 0
        # for key in dictlist.keys():
        #     if objecttest[index].__class__.__name__ == "NotApplicableValue":
        #         dictlist[key].append("N/A")
        #     else:
        #         dictlist[key].append(objecttest[index])
        #     index+=1
        # exitstr = {

        # }
        # print(str(objecttest))
        
        # exitstr.append(objecttest)
        # x = grid.values(node)
        # print(type(x))
        # for column_index in range(len(grid.columns)):
            # column = grid.columns[column_index]
            # print(x)
            # print(repr(grid.values[column_index]), end= "\t")
            # print(repr(grid.values[]))
            # print(column_index)
            # print(grid.values[column_index])
        return None
    grid.populate(visitor, None)

volatility3.framework.require_interface_version(1, 0, 0)
renderers = dict(
            [
                (x.name.lower(), x)
                for x in framework.class_subclasses(text_renderer.CLIRenderer)
            ]
        )
render_mode = "quick"
parser = volargparse.HelpfulArgParser(add_help = False, prog = "volatility", description = "An open-source memory forensics framework")
# known_args = ['vol.py', '-f', 'wanncry.vmem', 'windows.malfind', '--pid', '1340']
# print(renderers)
context = contexts.Context()
failures = framework.import_files(
            volatility3.plugins, True
        )
automagics = automagic.available(context)
# plugin list harus setelah automagic supaya ada list pluginnya
plugin_list = framework.list_plugins()
# print(plugin_list)
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
args.plugin = "windows.malfind.Malfind"
args.pid = [1340]
args.dump = False
args.file = "wanncry.vmem"
# args.config = "None"
# args.extend = "None"
# args.output_dir = os.path.abspath(args.file)
plugin = plugin_list[args.plugin]
chosen_configurables_list[args.plugin] = plugin
# print(plugin)
config_path = automagic.choose_automagic(automagics, plugin)

base_config_path = "plugins"
plugin_config_path = interfaces.configuration.path_join(
            base_config_path, plugin.__name__
        )
cmds = cmd()

# TESTING SUBPARSE
# parser = volargparse.HelpfulArgParser(
#             add_help=False,
#             prog="asdfa",
#             description="An open-source memory forensics framework",
#         )
# subparser = parser.add_subparsers(
#             title="Plugins",
#             dest="plugin",
#             description="For plugin specific options, run '{} <plugin> --help'",
#             action=volargparse.HelpfulSubparserAction,
#         )

# for plugin in sorted(plugin_list):
#     plugin_parser = subparser.add_parser(
#         plugin, help=plugin_list[plugin].__doc__
#     )
    # print(plugin_parser)
    # cmds.populate_requirements_argparse(plugin_parser, plugin_list[plugin])
file_name = os.path.abspath(args.file)
if not os.path.exists(file_name):
                print("File does not exist")
else:
    single_location = "file:" + request.pathname2url(file_name)
    context.config['automagic.LayerStacker.single_location'] = single_location

for amagic in automagics:
    chosen_configurables_list[amagic.__class__.__name__] = amagic
# if args.config:
#     with open(args.config, "r") as f:
#         json_val = json.load(f)
#         context.config.splice(plugin_config_path, interfaces.configuration.HierarchicalDict(json_val))
populate_config(context, chosen_configurables_list, args, plugin_config_path)
progress_callback = MuteProgress()
constructed = plugins.construct_plugin(context, automagics, plugin, base_config_path, progress_callback, cmds.file_handler_class_factory())
# print(dir(constructed))
# renderers["pretty"]().render(constructed.run)
treegrid = constructed.run()
# print(treegrid.values())
# print(dir(treegrid))
# print(treegrid.__dict__)

# Jalan buat default print
# renderers[render_mode]().render(treegrid)

# Jalan buat nangkep hasil dalam list
renderersEx(grid=treegrid)

# print()

# print(tabulate(dictlist, headers=dictlist.keys(), tablefmt='fancy_grid'))