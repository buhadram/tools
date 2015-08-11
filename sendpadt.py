#!/usr/bin/python

# This script sends PADT (PPPoED termination packet) to PPPoE server
# (c) Lutfi Shihab, 2015

import os
import sys
import re
import csv
import getopt
import logging
import logging.handlers
# silence most of scappy msgs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#import syslog
from datetime import datetime, date, time
#import xml.etrea.cElementTree as ET
#libary lxml harus sudah diinstall di Python!!
from lxml import etree as ET
from scapy import all as scp

global mylog
global myiface
verbose=0
_debug=0

def usage():
    print "%s [opts] < --src>| -r> <src-mac> < --dst >| -t> <dst-mac> <--session>| -s] <session-number>" % (sys.argv[0])
    print """
    where opts can be one or more of these:
        --help | -h

        --verbose | -v
        
        --debug | -d

        --iface | -i <physical interface>, default to eth1 if not specified 

    The session Id is 10-base
    """


def config_syslog(aptname):
    global verbose, _debug

    if _debug: 
        print "%s: aptname=%s" % (sys._getframe().f_code.co_name, aptname)
    logger = logging.getLogger(aptname)
    logger.setLevel(logging.DEBUG)
    #handler = logging.handlers.SysLogHandler(address = '/dev/log')
    handler = logging.handlers.SysLogHandler(address = ('127.0.0.1',514), facility=logging.handlers.SysLogHandler.LOG_USER)
    
    #formatter = logging.Formatter("%(name)s: %(levelname)s %(message)s")
    formatter = logging.Formatter('%(asctime)s %(name)-15s: %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.info('**** %s has just started **** ' % aptname)
    return logger



def send_padt(mysrc, mydst, sid):
    global _debug, verbose, mylog, myiface

    if _debug:
        mylog.debug("mysrc=%s" % mysrc)
        mylog.debug("mydst=%s" % mydst)
        mylog.debug("session-id=%s" % sid)


    # from RFC-2516:
    # This packet may be sent anytime after a session is established to
    # indicate that a PPPoE session has been terminated.  It may be sent by
    # either the Host or the Access Concentrator.  The DESTINATION_ADDR
    # field is a unicast Ethernet address, the CODE field is set to 0xa7
    # and the SESSION_ID MUST be set to indicate which session is to be
    # terminated.  No TAGs are required.

    # When a PADT is received, no further PPP traffic is allowed to be sent
    # using that session.  Even normal PPP termination packets MUST NOT be
    # sent after sending or receiving a PADT.  A PPP peer SHOULD use the
    # PPP protocol itself to bring down a PPPoE session, but the PADT MAY
    # be used when PPP can not be used.

    try:
        sesid = int(sid)

    except:
        print "Session-id must be 10-base integer"
        return

    eth_frame = scp.Ether(dst=mydst, src=mysrc)
    padt_pkt = eth_frame/scp.PPPoED(code=0xa7,sessionid=sesid)
    if verbose:
        scp.ls(padt_pkt)
    #scp.ls(padt_pkt)
    mylog.info("sending PADT (sed=%d) pkt from %s (this PC) to %s" % (sesid, mysrc, mydst))
    scp.sendp(padt_pkt, iface=myiface, verbose=1)



def main(argv):
    global verbose, _debug, myiface

    # default to ML's eth1
    src='68:05:ca:1b:52:cd'
    #default to my 552n WAN port
    dst='00:23:6a:5d:80:d1'
    sid=''
    myiface='eth1'

    try:
        opts, args = getopt.getopt(argv, 'hvdr:t:s:i:', 
            ["help", "verbose", "debug",  "src=", "dst=", "session=", "iface="])

    except getopt.GetoptError:
        print "Option error"
        usage()
        sys.exit(2)
    # end try

# set colors
    scp.conf.verb=1
    #scp.conf.color_theme=RastaTheme()
    scp.conf.color_theme=scp.ColorOnBlackTheme()

    # get the MACS
    #scp.sendrecv.sniff(iface="eth1", filter='pppoed', prn=lambda x: x.show() )

    for opt, arg in opts:
        if _debug:
            print "opt=", opt, ", arg=",arg
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-d", "--debug"):
            _debug = 1
        elif opt in ('-v', "--verbose"):
            verbose = 1
        elif opt in ("-r", "--src"):
            src = arg
        elif opt in ("-t", "--dst"):
            dst = arg
        elif opt in ("-s", "--session"):
            sid = arg
        elif opt in ("-i", "--iface"):
            myiface = arg
        else:
            print "unknown option"
            usage()
            sys.exit()
        # end if
    # end for

    if _debug:
        print "HOI!!! opts=", opts, ", args=", args

    if (len(src) > 0) and (len(dst) > 0) and (len(sid) > 0):
        if _debug:
            if (len(src) == 0):
                print "src parameter is empty"
            if (len(dst) == 0):
                print "dst parameter is empty"
            if (len(sid) == 0):
                print "session-id is not specified"
    if (len(src) > 0) and (len(dst) > 0) and (len(sid) > 0):
        send_padt(src, dst, sid)
    else:
        usage()



# ===== MAIN ENTRY ============
if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print "No parameters specified"
        usage()
        sys.exit(1)
    # end if

    #use syslog
    _debug=1
    mylog = config_syslog(os.path.splitext(os.path.basename(sys.argv[0]))[0])
    _debug=0
    mylog = config_syslog(sys.argv[0])

    main(sys.argv[1:])
    mylog.info('**** %s has stopped **** ' % sys.argv[0])
# end if


