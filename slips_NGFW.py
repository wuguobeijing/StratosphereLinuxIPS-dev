#!/usr/bin/env python3
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz

import configparser
import sys
import redis
import os
import time
import shutil
from datetime import datetime
import socket
import warnings
from modules.UpdateManager.update_file_manager import UpdateFileManager
import json
import pkgutil
import inspect
import modules
import importlib
from slips_files.common.abstracts import Module
from slips_files.core.database import __database__
import errno
import subprocess
import re
from collections import OrderedDict
from distutils.dir_util import copy_tree
import asyncio


class Slips:
    def __init__(self):
        self.version = '0.1.1'
        # Ignore warnings on CPU from tensorflow
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
        # Ignore warnings in general
        warnings.filterwarnings('ignore')
        self.filepath = None
        self.interface = None
        self.gui = None
        self.blocking = None
        self.clearblocking = None
        self.output = None
        self.config = None
        self.db = __database__

    def read_configuration(self, section, name):
        """ Read the configuration file for what slips.py needs. Other processes also access the configuration """
        try:
            return self.config.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            return False

    def recognize_host_ip(self):
        """
        Recognize the IP address of the machine
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            ipaddr_check = s.getsockname()[0]
            s.close()
        except (socket.error):
            # not connected to the internet
            return None
        return ipaddr_check

    def create_folder_for_logs(self):
        """
        Create a folder for logs if logs are enabled
        """
        logs_folder = datetime.now().strftime('%Y-%m-%d--%H-%M-%S')
        try:
            os.makedirs(logs_folder)
        except OSError as e:
            if e.errno != errno.EEXIST:
                # doesn't exist and can't create
                return False
        return logs_folder

    async def update_ti_files(self, outputqueue, config):
        """
        Update malicious files and store them in database before slips start
        """
        update_manager = UpdateFileManager(outputqueue, config)
        # create_task is used to run update() function concurrently instead of serially
        update_finished = asyncio.create_task(update_manager.update())
        # wait for UpdateFileManager to finish before starting all the modules
        await update_finished

    def check_redis_database(self, redis_host='localhost', redis_port=6379) -> bool:
        """
        Check if we have redis-server running
        """
        try:
            r = redis.StrictRedis(host=redis_host, port=redis_port, db=1, charset="utf-8",
                                  decode_responses=True)
            r.ping()
        except Exception as ex:
            print('[DB] Error: Is redis database running? You can run it as: "redis-server --daemonize yes"')
            return False
        return True

    def clear_redis_cache_database(self, redis_host='localhost', redis_port=6379) -> bool:
        """
        Clear cache database
        """
        rcache = redis.StrictRedis(host=redis_host, port=redis_port, db=2, charset="utf-8",
                                   decode_responses=True)
        rcache.flushdb()
        return True

    def check_zeek_or_bro(self):
        """
        Check if we have zeek or bro
        """
        if shutil.which('zeek'):
            return 'zeek'
        elif shutil.which('bro'):
            return 'bro'
        return False

    def terminate_slips(self):
        """
        Do all necessary stuff to stop process any clear any files.
        """
        sys.exit(-1)

    def load_modules(self):
        """
        Import modules and loads the modules from the 'modules' folder. Is very relative to the starting position of slips
        """

        plugins = {}
        failed_to_load_modules = 0
        # Walk recursively through all modules and packages found on the . folder.
        # __path__ is the current path of this python program
        for loader, module_name, ispkg in pkgutil.walk_packages(modules.__path__, modules.__name__ + '.'):
            if any(module_name.__contains__(mod) for mod in self.to_ignore):
                continue
            # If current item is a package, skip.
            if ispkg:
                continue

            # Try to import the module, otherwise skip.
            try:
                # "level specifies whether to use absolute or relative imports. The default is -1 which
                # indicates both absolute and relative imports will be attempted. 0 means only perform
                # absolute imports. Positive values for level indicate the number of parent
                # directories to search relative to the directory of the module calling __import__()."
                module = importlib.import_module(module_name)
            except ImportError as e:
                print("Something wrong happened while importing the module {0}: {1}".format(module_name, e))
                continue

            # Walk through all members of currently imported modules.
            for member_name, member_object in inspect.getmembers(module):
                # Check if current member is a class.
                if inspect.isclass(member_object):
                    if issubclass(member_object, Module) and member_object is not Module:
                        plugins[member_object.name] = dict(obj=member_object, description=member_object.description)

        # Change the order of the blocking module(load it first) so it can receive msgs sent from other modules
        if 'Blocking' in plugins:
            plugins = OrderedDict(plugins)
            # last=False to move to the beginning of the dict
            plugins.move_to_end('Blocking', last=False)

        return plugins, failed_to_load_modules

    def get_cwd(self):
        # Can't use os.getcwd() because slips directory name won't always be Slips plus this way requires less parsing
        for arg in sys.argv:
            if 'slips.py' in arg:
                # get the path preceeding slips.py
                # (may be ../ or  ../../ or '' if slips.py is in the cwd),
                # this path is where slips.conf will be
                cwd = arg[:arg.index('slips.py')]
                return cwd

    def prepare_zeek_scripts(self):
        """
        Adds local network to slips-conf.zeek
        """
        # get home network from slips.conf
        try:
            home_network = self.config.get('parameters', 'home_network')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            from slips_files.common.slips_utils import utils
            home_network = utils.home_network_ranges

        zeek_scripts_dir = os.getcwd() + '/zeek-scripts'
        # add local sites if not there
        is_local_nets_defined = False
        with open(zeek_scripts_dir + '/slips-conf.zeek', 'r') as slips_conf:
            if 'local_nets' in slips_conf.read():
                is_local_nets_defined = True

        if not is_local_nets_defined:
            with open(zeek_scripts_dir + '/slips-conf.zeek', 'a') as slips_conf:
                # update home network
                slips_conf.write('\nredef Site::local_nets += { ' + home_network + ' };\n')

        # # load all scripts in zeek-script dir
        # with open(zeek_scripts_dir + '/__load__.zeek','r') as f:
        #     loaded_scripts = f.read()
        # with open(zeek_scripts_dir + '/__load__.zeek','a') as f:
        #     for file_name in os.listdir(zeek_scripts_dir):
        #         # ignore the load file
        #         if file_name == '__load__.zeek':
        #             continue
        #         if file_name not in loaded_scripts:
        #             # found a file in the dir that isn't in __load__.zeek, add it
        #             f.write(f'\n@load ./{file_name}')

    def add_metadata(self):
        """
        Create a metadata dir output/metadata/ that has a copy of slips.conf, whitelist.conf, current commit and date
        """
        metadata_dir = os.path.join(self.output, 'metadata')
        try:
            os.mkdir(metadata_dir)
        except FileExistsError:
            # if the file exists it will be overwritten
            pass

        # Add a copy of slips.conf
        config_file = 'slips.conf'
        shutil.copy(config_file, metadata_dir)
        # Add a copy of whitelist.conf
        whitelist = self.config.get('parameters', 'whitelist_path')
        shutil.copy(whitelist, metadata_dir)

        from git import Repo
        repo = Repo('.')
        branch = repo.active_branch.name
        commit = repo.active_branch.commit.hexsha
        now = datetime.now()

        info_path = os.path.join(metadata_dir, 'info.txt')
        with open(info_path, 'w') as f:
            f.write(f'Slips version: {self.version}\n')
            f.write(f'Branch: {branch}\n')
            f.write(f'Commit: {commit}\n')
            f.write(f'Date: {now}\n')

        print(f'[Main] Metadata added to {metadata_dir}')

    def shutdown_gracefully(self):
        try:
            print('\n' + '-' * 27)
            print('Stopping Slips')
            # is slips currently exporting alerts?
            self.send_to_warden = self.config.get('CESNET', 'send_alerts').lower()
            # Stop the modules that are subscribed to channels
            self.db.publish_stop()
            # Here we should Wait for any channel if it has still
            # data to receive in its channel
            finished_modules = []
            try:
                loaded_modules = self.modules_to_call.keys()
            except NameError:
                # this is the case of -d <rdb file> we don't have loaded_modules
                loaded_modules = []

            # get dict of PIDs spawned by slips
            self.PIDs = self.db.get_PIDs()
            # timeout variable so we don't loop forever
            max_loops = 130
            # loop until all loaded modules are finished
            while len(finished_modules) < len(loaded_modules) and max_loops != 0:
                # print(f"Modules not finished yet {set(loaded_modules) - set(finished_modules)}")
                try:
                    message = self.c1.get_message(timeout=0.01)
                except NameError:
                    # Sometimes the c1 variable does not exist yet. So just force the shutdown
                    message = {
                        'data': 'dummy_value_not_stopprocess',
                        'channel': 'finished_modules'}

                if message and message['data'] == 'stop_process':
                    continue
                if message and message['channel'] == 'finished_modules' and type(message['data']) == str:
                    # all modules must reply with their names in this channel after
                    # receiving the stop_process msg
                    # to confirm that all processing is done and we can safely exit now
                    module_name = message['data']

                    if module_name not in finished_modules:
                        finished_modules.append(module_name)
                        try:
                            # remove module from the list of opened pids
                            self.PIDs.pop(module_name)
                        except KeyError:
                            continue
                        modules_left = len(list(self.PIDs.keys()))
                        # to vertically align them when printing
                        module_name = module_name + ' ' * (20 - len(module_name))
                        print(
                            f"\t\033[1;32;40m{module_name}\033[00m \tStopped. \033[1;32;40m{modules_left}\033[00m left.")
                max_loops -= 1

                # before killing the modules that aren't finished
                # make sure we're not in the middle of exporting alerts
                # if the PID of CESNET module is there in PIDs dict,
                # it means the module hasn't stopped yet
                if 'yes' in self.send_to_warden and 'CESNET' in self.PIDs:
                    # we're in the middle of sending alerts to warden server
                    # delay killing unstopped modules
                    max_loops += 1

            # modules that aren't subscribed to any channel will always be killed and not stopped
            # some modules continue on sigint, but recieve
            # other msgs (other than stop_message) in the queue before stop_process
            # they will always be killed
            # kill processes that didn't stop after timeout
            for unstopped_proc, pid in self.PIDs.items():
                unstopped_proc = unstopped_proc + ' ' * (20 - len(unstopped_proc))
                try:
                    os.kill(int(pid), 9)
                    print(f'\t\033[1;32;40m{unstopped_proc}\033[00m \tKilled.')
                except ProcessLookupError:
                    print(f'\t\033[1;32;40m{unstopped_proc}\033[00m \tAlready stopped.')
            # Send manual stops to the process not using channels
            try:
                self.logsProcessQueue.put('stop_process')
            except NameError:
                # The logsProcessQueue is not there because we
                # didnt started the logs files (used -l)
                pass
            try:
                self.outputProcessQueue.put('stop_process')
            except NameError:
                pass
            try:
                self.profilerProcessQueue.put('stop_process')
            except NameError:
                pass
            try:
                self.inputProcess.terminate()
            except NameError:
                pass

            # if store_a_copy_of_zeek_files is set to yes in slips.conf, copy the whole zeek_files dir to the output dir
            try:
                store_a_copy_of_zeek_files = self.config.get('parameters', 'store_a_copy_of_zeek_files')
                store_a_copy_of_zeek_files = False if 'no' in store_a_copy_of_zeek_files.lower() else True
            except (configparser.NoOptionError, configparser.NoSectionError, NameError):
                # There is a conf, but there is no option, or no section or no configuration file specified
                store_a_copy_of_zeek_files = False

            os._exit(-1)
            return True
        except KeyboardInterrupt:
            # display a warning if the user's trying to stop
            # slips while we're still exporting
            if 'yes' in self.send_to_warden and 'CESNET' in self.PIDs:
                print("[Main] Exporting alerts to warden server was cancelled.")
            return False

    def is_debugger_active(self) -> bool:
        """Return if the debugger is currently active"""
        gettrace = getattr(sys, 'gettrace', lambda: None)
        return gettrace() is not None

    ####################
    # Main
    ####################

    def main(self, filepath, interface, gui, blocking, clearblocking, output):
        try:
            # Before the argparse, we need to set up the default path fr alerts.log
            # and alerts.json. In our case, it is output folder.
            self.alerts_default_path = 'output/'
            self.filepath = filepath
            self.interface = interface
            self.gui = gui
            self.blocking = blocking
            self.clearblocking = clearblocking
            self.output = output
            print('wuguo_buaa')
            print('-' * 27)

            # Parse the parameters
            slips_conf_path = 'slips.conf'

            # Read the config file name given from the parameters
            # don't use '%' for interpolation.
            # comment_prefixes are the characters that if found at the beginning
            # of the line, the line is completely ignored by configparses, by default they are # and ;
            # set them to # only to support removing commented ti files from the cache db
            self.config = configparser.ConfigParser(interpolation=None, comment_prefixes="#")
            try:
                with open(slips_conf_path) as source:
                    self.config.read_file(source)
            except IOError:
                pass
            except TypeError:
                # No conf file provided
                pass

            # Check if redis server running
            if self.check_redis_database() is False:
                print("Redis database is not running. Stopping Slips")
                self.terminate_slips()

            if self.clearblocking:
                if os.geteuid() != 0:
                    print("Slips needs to be run as root to clear the slipsBlocking chain. Stopping.")
                    self.terminate_slips()
                else:
                    # start only the blocking module process and the db
                    from multiprocessing import Queue
                    from modules.blocking.blocking import Module
                    blocking = Module(Queue(), self.config)
                    blocking.start()
                    blocking.delete_slipsBlocking_chain()
                    # Tell the blocking module to clear the slips chain
                    self.shutdown_gracefully()
            self.db.start(self.config)

            # Check the type of input
            if self.interface is not None:
                self.input_information = self.interface
                self.input_type = 'interface'
            elif filepath is not None:
                # get the input_type
                self.input_information = filepath
                # check invalid file path
                if not os.path.exists(self.input_information):
                    print(f'[Main] Invalid file path {self.input_information}. Stopping.')
                    os._exit(-1)

                # default value
                self.input_type = 'file'
                # Get the type of file
                cmd_result = subprocess.run(['file', self.input_information], stdout=subprocess.PIPE)
                # Get command output
                cmd_result = cmd_result.stdout.decode('utf-8')

                if 'pcap' in cmd_result:
                    self.input_type = 'pcap'
                elif 'dBase' in cmd_result:
                    self.input_type = 'nfdump'
                elif 'CSV' in cmd_result:
                    self.input_type = 'binetflow'
                elif 'directory' in cmd_result:
                    self.input_type = 'zeek_folder'
                else:
                    # is it a zeek log file or suricata, binetflow tabs , or binetflow comma separated file?
                    # use first line to determine
                    with open(self.input_information, 'r') as f:
                        while True:
                            # get the first line that isn't a comment
                            first_line = f.readline().replace('\n', '')
                            if not first_line.startswith('#'):
                                break
                    if 'flow_id' in first_line:
                        self.input_type = 'suricata'
                    else:
                        # this is a text file , it can be binetflow or zeek_log_file
                        try:
                            # is it a json log file
                            json.loads(first_line)
                            self.input_type = 'zeek_log_file'
                        except json.decoder.JSONDecodeError:
                            # this is a tab separated file
                            # is it zeek log file or binetflow file?
                            # line = re.split(r'\s{2,}', first_line)[0]
                            tabs_found = re.search('\s{1,}-\s{1,}', first_line)
                            if '->' in first_line or 'StartTime' in first_line:
                                # tab separated files are usually binetflow tab files
                                self.input_type = 'binetflow-tabs'
                            elif tabs_found:
                                self.input_type = 'zeek_log_file'

            # If we need zeek (bro), test if we can run it.
            # Need to be assign to something because we pass it to inputProcess later
            zeek_bro = None
            if self.input_type == 'pcap' or self.interface is not None or 'zeek' in self.input_type:
                zeek_bro = self.check_zeek_or_bro()
                if zeek_bro is False:
                    # If we do not have bro or zeek, terminate Slips.
                    print('Error. No zeek or bro binary found.')
                    self.terminate_slips()
                else:
                    # run in this mode
                    self.prepare_zeek_scripts()

            # See if we have the nfdump, if we need it according to the input type
            if self.input_type == 'nfdump' and shutil.which('nfdump') is None:
                # If we do not have nfdump, terminate Slips.
                self.terminate_slips()

            # Remove default folder for alerts, if exists
            if os.path.exists(self.output):
                try:
                    os.remove(self.output + 'alerts.log')
                    os.remove(self.output + 'alerts.json')
                except OSError:
                    # Directory not empty (may contain hidden non-deletable files), don't delete dir
                    pass

            # Create output folder for alerts.txt and alerts.json if they do not exist
            if not self.output.endswith('/'):
                self.output = self.output + '/'
            if not os.path.exists(self.output):
                os.makedirs(self.output)

            # Also check if the user blocks on interface, does not make sense to block on files
            if self.interface and self.blocking and os.geteuid() != 0:
                # If the user wants to blocks,we need permission to modify iptables
                print('Run slips with sudo to enable the blocking module.')
                self.shutdown_gracefully()

            """
            Import modules here because if user wants to run "./slips.py --help" it should never throw error. 
            """
            from multiprocessing import Queue
            from inputProcess import InputProcess
            from outputProcess import OutputProcess
            from profilerProcess import ProfilerProcess
            from guiProcess import GuiProcess
            from logsProcess import LogsProcess
            from evidenceProcess import EvidenceProcess

            self.verbose = int(self.config.get('parameters', 'verbose'))

            try:
                self.debug = int(self.config.get('parameters', 'debug'))
            except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError):
                # There is a conf, but there is no option, or no section or no configuration file specified
                # By default, 0
                self.debug = 0

            ##########################
            # Creation of the threads
            ##########################
            # Output thread. This thread should be created first because it handles
            # the output of the rest of the threads.
            # Create the queue
            self.outputProcessQueue = Queue()
            # if stdout it redirected to a file, tell outputProcess.py to redirect it's output as well
            # lsof will provide a list of all open fds belonging to slips
            command = f'lsof -p {os.getpid()}'
            result = subprocess.run(command.split(), capture_output=True)
            # Get command output
            self.output = result.stdout.decode('utf-8')
            # if stdout is being redirected we'll find '1w' in one of the lines 1 means stdout, w means write mode
            for line in self.output.splitlines():
                if '1w' in line:
                    # stdout is redirected, get the file
                    current_stdout = line.split(' ')[-1]
                    break
            else:
                # stdout is not redirected
                current_stdout = ''

            # Create the output thread and start it
            self.outputProcessThread = OutputProcess(self.outputProcessQueue, self.verbose, self.debug, self.config,
                                                     stdout=current_stdout)
            # this process starts the db
            self.outputProcessThread.start()

            # Before starting update malicious file
            # create an event loop and allow it to run the update_file_manager asynchronously
            # asyncio.run(update_ti_files(outputProcessQueue, config))

            # Print the PID of the main slips process. We do it here because we needed the queue to the output process
            self.outputProcessQueue.put('10|main|Started main program [PID {}]'.format(os.getpid()))
            # Output pid
            self.db.store_process_PID('OutputProcess', int(self.outputProcessThread.pid))

            self.outputProcessQueue.put('10|main|Started output thread [PID {}]'.format(self.outputProcessThread.pid))

            # Start each module in the folder modules
            self.outputProcessQueue.put('01|main|Starting modules')
            self.to_ignore = self.read_configuration('modules', 'disable')

            # This plugins import will automatically load the modules and put them in the __modules__ variable
            # if slips is given a .rdb file, don't load the modules as we don't need them
            if self.to_ignore and not self.db:
                # Convert string to list
                self.to_ignore = self.to_ignore.replace("[", "").replace("]", "").replace(" ", "").split(",")
                # Ignore exporting alerts module if export_to is empty
                export_to = self.config.get('ExportingAlerts', 'export_to').rstrip("][").replace(" ", "").lower()
                if 'stix' not in export_to and 'slack' not in export_to and 'json' not in export_to:
                    self.to_ignore.append('ExportingAlerts')
                # ignore CESNET sharing module if send and receive are are disabled in slips.conf
                self.send_to_warden = self.config.get('CESNET', 'send_alerts').lower()
                receive_from_warden = self.config.get('CESNET', 'receive_alerts').lower()
                if 'no' in self.send_to_warden and 'no' in receive_from_warden:
                    self.to_ignore.append('CESNET')
                # don't run blocking module unless specified
                if not self.clearblocking and not self.blocking \
                        or (self.blocking and not self.interface):  # ignore module if not using interface
                    self.to_ignore.append('blocking')

                # leak detector only works on pcap files
                if self.input_type != 'pcap':
                    self.to_ignore.append('leak_detector')
                try:
                    # This 'imports' all the modules somehow, but then we ignore some
                    self.modules_to_call = self.load_modules()[0]
                    for module_name in self.modules_to_call:
                        if module_name not in self.to_ignore:
                            module_class = self.modules_to_call[module_name]['obj']
                            ModuleProcess = module_class(self.outputProcessQueue, self.config)
                            ModuleProcess.start()
                            self.db.store_process_PID(module_name, int(ModuleProcess.pid))
                            description = self.modules_to_call[module_name]['description']
                            self.outputProcessQueue.put(
                                f'10|main|\t\tStarting the module {module_name} '
                                f'({description}) '
                                f'[PID {ModuleProcess.pid}]')
                except TypeError:
                    # There are not modules in the configuration to ignore?
                    print('No modules are ignored')

            # Get the type of output from the parameters
            # Several combinations of outputs should be able to be used
            if self.gui:
                # Create the curses thread
                self.guiProcessQueue = Queue()
                self.guiProcessThread = GuiProcess(self.guiProcessQueue, self.outputProcessQueue, self.verbose,
                                                   self.debug, self.config)
                self.guiProcessThread.start()
                self.outputProcessQueue.put('quiet')

            do_logs = self.read_configuration('parameters', 'create_log_files')
            # if -l is provided or create_log_files is yes then we will create log files
            if do_logs == 'yes':
                # Create a folder for logs
                logs_folder = self.create_folder_for_logs()
                # Create the logsfile thread if by parameter we were told, or if it is specified in the configuration
                self.logsProcessQueue = Queue()
                self.logsProcessThread = LogsProcess(self.logsProcessQueue, self.outputProcessQueue,
                                                     self.verbose, self.debug, self.config, logs_folder)
                self.logsProcessThread.start()
                self.outputProcessQueue.put(
                    '10|main|Started logsfiles thread [PID {}]'.format(self.logsProcessThread.pid))
                self.db.store_process_PID('logsProcess', int(self.logsProcessThread.pid))
            else:
                logs_folder = False

            # Evidence thread
            # Create the queue for the evidence thread
            self.evidenceProcessQueue = Queue()
            # Create the thread and start it
            self.evidenceProcessThread = EvidenceProcess(self.evidenceProcessQueue, self.outputProcessQueue,
                                                         self.config, self.output, logs_folder)
            self.evidenceProcessThread.start()
            self.outputProcessQueue.put(
                '10|main|Started Evidence thread [PID {}]'.format(self.evidenceProcessThread.pid))
            self.db.store_process_PID('EvidenceProcess', int(self.evidenceProcessThread.pid))

            # Profile thread
            # Create the queue for the profile thread
            self.profilerProcessQueue = Queue()
            # Create the profile thread and start it
            self.profilerProcessThread = ProfilerProcess(self.profilerProcessQueue,
                                                         self.outputProcessQueue, self.verbose, self.debug, self.config)
            self.profilerProcessThread.start()
            self.outputProcessQueue.put(
                '10|main|Started Profiler thread [PID {}]'.format(self.profilerProcessThread.pid))
            self.db.store_process_PID('ProfilerProcess', int(self.profilerProcessThread.pid))

            self.c1 = self.db.subscribe('finished_modules')

            # Input process
            # Create the input process and start it
            self.inputProcess = InputProcess(self.outputProcessQueue, self.profilerProcessQueue,
                                             self.input_type, self.input_information, self.config, False, zeek_bro)
            self.inputProcess.start()
            self.outputProcessQueue.put('10|main|Started input thread [PID {}]'.format(self.inputProcess.pid))
            time.sleep(0.5)
            print()
            self.db.store_process_PID('inputProcess', int(self.inputProcess.pid))

            enable_metadata = self.read_configuration('parameters', 'metadata_dir')
            if 'yes' in enable_metadata.lower():
                self.add_metadata()

            # Store the host IP address if input type is interface
            if self.input_type == 'interface':
                hostIP = self.recognize_host_ip()
                while True:
                    try:
                        self.db.set_host_ip(hostIP)
                        break
                    except redis.exceptions.DataError:
                        print("Not Connected to the internet. Reconnecting in 10s.")
                        time.sleep(10)
                        hostIP = self.recognize_host_ip()

            # As the main program, keep checking if we should stop slips or not
            # This is not easy since we need to be sure all the modules are stopped
            # Each interval of checking is every 5 seconds
            check_time_sleep = 5
            # In each interval we check if there has been any modifications to the database by any module.
            # If not, wait this amount of intervals and then stop slips.
            # We choose 6 to wait 30 seconds.
            limit_minimum_intervals_to_wait = 4
            minimum_intervals_to_wait = limit_minimum_intervals_to_wait
            fieldseparator = self.db.getFieldSeparator()
            slips_internal_time = 0
            try:
                while True:
                    # Sleep some time to do rutine checks
                    time.sleep(check_time_sleep)
                    slips_internal_time = float(self.db.getSlipsInternalTime()) + 1
                    # Get the amount of modified profiles since we last checked
                    modified_profiles, last_modified_tw_time = self.db.getModifiedProfilesSince(slips_internal_time)
                    amount_of_modified = len(modified_profiles)
                    # Get the time of last modified timewindow and set it as a new
                    if last_modified_tw_time != 0:
                        self.db.setSlipsInternalTime(last_modified_tw_time)
                    # How many profiles we have?
                    profilesLen = str(self.db.getProfilesLen())
                    print(f'Total Number of Profiles in DB so far: {profilesLen}. '
                          f'Modified Profiles in the last TW: {amount_of_modified}. '
                          f'({datetime.now().strftime("%Y-%m-%d--%H:%M:%S")})', end='\r')

                    # Check if we need to close some TW
                    self.db.check_TW_to_close()

                    # In interface we keep track of the host IP. If there was no
                    # modified TWs in the host NotIP, we check if the network was changed.
                    # Dont try to stop slips if its catpurting from an interface
                    if self.interface:
                        # To check of there was a modified TW in the host IP. If not,
                        # count down.
                        modifiedTW_hostIP = False
                        for profileIP in modified_profiles:
                            # True if there was a modified TW in the host IP
                            if hostIP == profileIP:
                                modifiedTW_hostIP = True

                        # If there was no modified TW in the host IP
                        # then start counting down
                        # After count down we update the host IP, to check if the
                        # network was changed
                        if not modifiedTW_hostIP and self.interface:
                            if minimum_intervals_to_wait == 0:
                                hostIP = self.recognize_host_ip()
                                if hostIP:
                                    self.db.set_host_ip(hostIP)
                                minimum_intervals_to_wait = limit_minimum_intervals_to_wait
                            minimum_intervals_to_wait -= 1
                        else:
                            minimum_intervals_to_wait = limit_minimum_intervals_to_wait

                    # ---------------------------------------- Stopping slips

                    # When running Slips in the file.
                    # If there were no modified TW in the last timewindow time,
                    # then start counting down
                    else:
                        # don't shutdown slips if it's being debugged
                        if amount_of_modified == 0 and not self.is_debugger_active():
                            # print('Counter to stop Slips. Amount of modified
                            # timewindows: {}. Stop counter: {}'.format(amount_of_modified, minimum_intervals_to_wait))
                            if minimum_intervals_to_wait == 0:
                                # If the user specified -s, save the database before stopping
                                self.shutdown_gracefully()
                                break
                            minimum_intervals_to_wait -= 1
                        else:
                            minimum_intervals_to_wait = limit_minimum_intervals_to_wait

                    self.db.pubsub.check_health()

            except KeyboardInterrupt:
                self.shutdown_gracefully()

        except KeyboardInterrupt:
            self.shutdown_gracefully()


if __name__ == '__main__':
    slips = Slips()
    slips.main(filepath=None, interface=None, gui=True, blocking=False, clearblocking=False, output=None)
