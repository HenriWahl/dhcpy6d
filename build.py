# -*- coding: utf-8 -*-

"""

Experimental script for automated Debian build
Taken from Nagstamon

"""

from optparse import OptionParser
import platform
import os
import sys
import shutil

INSTALLER_DIR = 'installer%s' % os.path.sep

def execute_script_lines(script_lines, opt_dict):
    for line in script_lines:
        command = line % opt_dict
        print 'Running: %s' % command 
        os.system(command)

def get_opt_dict(options):
    opt_dict = vars(options)
    opt_dict.update({ 'installer': INSTALLER_DIR, 'default_location': DEFAULT_LOCATION })
    return opt_dict

def get_required_files(location, required_file_list):
    all_files = []
    for dir_path, dir_list, file_list in os.walk(location):
        for file_name in required_file_list:
            if file_name in file_list:
                all_files.append(os.path.join(dir_path, file_name))
    return all_files

def get_all_files(location):
    for dir_path, dir_list, file_list in os.walk(location):
        for file_name in file_list:
            yield os.path.join(dir_path, file_name)

def debmain():
    parser = OptionParser()
    parser.add_option('-t', '--target', dest='target', help='Target application directory', default='')
    parser.add_option('-d', '--debian', dest='debian', help='"debian" directory location', default='')
    options, args = parser.parse_args()
    if not options.debian:
        options.debian = '%s/%sdebian' % (options.target, INSTALLER_DIR)
    else:
        options.debian = '%s/debian' % options.debian
    options.debian = os.path.abspath(options.debian)
    if not os.path.isfile('%s/rules' % (options.debian)):
        print 'Missing required "rules" file in "%s" directory' % options.debian
        return
    execute_script_lines(['cd %(target)s; ln -s %(debian)s; chmod 755 %(debian)s/rules; fakeroot debian/rules build; \
fakeroot debian/rules binary; fakeroot debian/rules clean; rm debian'],
                         get_opt_dict(options))

DISTS = {
    'debian': debmain, 
    'Ubuntu': debmain
}

if __name__ == '__main__':
    dist = platform.dist()[0]
    if dist in DISTS:
        DISTS[dist]()
    else:
        print 'Your system is not supported for automated build yet'
