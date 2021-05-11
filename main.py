#!/bin/sh
"""true"
exec python -u "$0" "$@"
"""

import os
import sys
import time
import subprocess
from subprocess import TimeoutExpired
import shlex
import argparse
import re

ip_regex = re.compile('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')


_parser = argparse.ArgumentParser(prog='autosint',description='automate osint activity')

_parser.add_argument('--modules',type=str,dest='modules',help='domain, ip, debug')
_parser.add_argument('--timeout',type=int,default=0,help='time to wait before terminating subprocess (default=0)')
_parser.add_argument('--input',type=str,help='comma seperated list of domains and/or ip addresses')
_parser.add_argument('--infile',type=str,help='file containing newline seperated list of domains and/or ip addresses')

#wrapper around subprocess.Popen
def runcmd_rt(cmd,input=b'',timeout=0):
    t1 = time.perf_counter()
    proc = subprocess.Popen(shlex.split(cmd),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    #no limit
    if timeout==0:
        t2 = time.perf_counter()
        #sys.stderr.write('elapsed: '+'{:.1f}'.format(t2-t1)+'\n')
        return proc.communicate(input=input)[0]
    else:
        while proc.poll() == None:
            t2 = time.perf_counter()
            sys.stderr.write('{:.1f}'.format(t2-t1))
            sys.stderr.write('\b'*10)
            if (t2-t1) >= timeout:
                proc.terminate()
                sys.stderr.write('elapsed: '+'{:.1f}'.format(t2-t1)+'\n')
                return proc.communicate(input=input)[0]
        t2 = time.perf_counter()
        sys.stderr.write('elapsed: '+'{:.1f}'.format(t2-t1)+'\n')
        return proc.communicate(input=input)[0]

#debug
def debug():
    print('debug')

def tbd():
    print('to be implemented')

args = _parser.parse_args()

module_table = {'debug':debug,'domain':tbd,'ip':tbd}

if __name__=='__main__':

    #print(args)
    args_valid = True

    # check if args are valid

    #inputs
    if (args.input == None and args.infile == None):
        sys.stderr.write('provide at least one input via --infile or --input!\n')
        args_valid = False

    elif (args.input != None and args.infile != None):
        sys.stderr.write('--input and --infile cannot be used together!\n')
        args_valid = False

    else:
        #get inputs
        if args.input:
            input_data = args.input.split(',')
        elif args.infile:
            if os.path.isfile(args.infile):
                input_data = open(args.infile,'r').read().split('\n')
            else:
                sys.stderr.write('input file does not exist!\n')
                args_valid = False

    #modules
    if args.modules == None:
        sys.stderr.write('select at least one module!\n')
        args_valid = False

    #if args not valid then quit
    if not args_valid:
        sys.stderr.write('quitting...\n\n')
        _parser.print_help()
        sys.exit(1)
    else:
        input_data = list(filter(None,input_data))
        input_ip = []
        input_domain = []

        for i in input_data:
            if ip_regex.match(i):
                input_ip.append(i)
            else:
                input_domain.append(i)

        print(input_ip,input_domain)

        for module in args.modules.split(','):
            if module not in module_table.keys():
                sys.stderr.write('the module {} specified is invalid!\nignoring...\n'.format(module))
                pass
            else:
                module_table[module]()
