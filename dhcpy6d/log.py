# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2020 Henri Wahl <h.wahl@ifw-dresden.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

from grp import getgrnam
import logging
from logging import (Formatter,
                     getLogger,
                     StreamHandler)
from logging.handlers import (SysLogHandler,
                              WatchedFileHandler)
from os import chown
from pwd import getpwnam
from socket import gethostname

from .config import cfg

# globally available logging instace
log = getLogger('dhcpy6d')

if cfg.LOG:
    formatter = Formatter('{asctime} {name} {levelname} {message}', style='{')
    log.setLevel(logging.__dict__[cfg.LOG_LEVEL])
    if cfg.LOG_FILE != '':
        chown(cfg.LOG_FILE, getpwnam(cfg.USER).pw_uid, getgrnam(cfg.GROUP).gr_gid)
        log_handler = WatchedFileHandler(cfg.LOG_FILE)
        log_handler.setFormatter(formatter)
        log.addHandler(log_handler)
    # std err console output
    if cfg.LOG_CONSOLE:
        log_handler = StreamHandler()
        log_handler.setFormatter(formatter)
        log.addHandler(log_handler)
    if cfg.LOG_SYSLOG:
        # time should be added by syslog daemon
        hostname = gethostname().split('.')[0]
        formatter = Formatter(hostname + ' {name} {levelname} {message}', style='{')
        # if /socket/file is given use this as address
        if cfg.LOG_SYSLOG_DESTINATION.startswith('/'):
            destination = cfg.LOG_SYSLOG_DESTINATION
        # if host and port are defined use them...
        elif cfg.LOG_SYSLOG_DESTINATION.count(':') == 1:
            destination = tuple(cfg.LOG_SYSLOG_DESTINATION.split(':'))
        # ...otherwise add port 514 to given host address
        else:
            destination = (cfg.LOG_SYSLOG_DESTINATION, 514)
        log_handler = SysLogHandler(address=destination,
                                    facility=SysLogHandler.__dict__['LOG_' + cfg.LOG_SYSLOG_FACILITY])
        log_handler.setFormatter(formatter)
        log.addHandler(log_handler)
