#!/usr/bin/env python3

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
_parser.add_argument('--stdout',action='store_true',help='write output to stdout')
_parser.add_argument('-o',dest='output_dir',default='.',help='output directory. by default writes output to current directory')

#wrapper around subprocess.Popen
def runcmd_rt(cmd,input=b'',timeout=0):
    t1 = time.perf_counter()
    proc = subprocess.Popen(shlex.split(cmd),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    #no limit
    if timeout==0:
        t2 = time.perf_counter()
        stdout,stderr = proc.communicate(input=input)
        #sys.stderr.write(stderr.decode())
        return stdout
    else:
        while proc.poll() == None:
            t2 = time.perf_counter()
            sys.stderr.write('{:.1f}'.format(t2-t1))
            sys.stderr.write('\b'*10)
            if (t2-t1) >= timeout:
                sys.stderr.write('timeout expired!\n')
                proc.terminate()
                sys.stderr.write('elapsed: '+'{:.1f}'.format(t2-t1)+'\n')
                stdout,stderr = proc.communicate(input=input)
                #sys.stderr.write(stderr.decode())
                return stdout
        t2 = time.perf_counter()
        sys.stderr.write('elapsed: '+'{:.1f}'.format(t2-t1)+'\n')
        stdout,stderr = proc.communicate(input=input)
        #sys.stderr.write(stderr.decode())
        return stdout

#domain enumeration
def domain(input_data,timeout,output_dir,stdout,errlog_file):
    outpath = output_dir+'/auto_osint_output/domain/'
    try:
        os.makedirs(output_dir+'/auto_osint_output'+'/domain',exist_ok=True)
    except OSError:
        sys.stderr.write('unable to create domain directory!\nquitting...\n')
        sys.exit(1)
    domain_ip_file = open(outpath+'domain-ip.list','w')
    input_domain = input_data[0]
    if len(input_domain) == 0:
        sys.stderr.write('domain module specified without any input domains!\nskipping module...\n')
        return (None,'domain')
    big_domain_list = []
    domain_ip_table = {}
    failed_lookups = []
    for d in input_domain:
        sys.stderr.write('gathering subdomains for '+d+'\n')
        tmp = runcmd_rt('subfinder -d '+d,timeout=timeout).decode().split('\n')
        for line in tmp:
            big_domain_list.append(line)
    big_domain_list = list(filter(None,big_domain_list))
    big_domain_list = list(set(big_domain_list))
    for domain in big_domain_list:
        sys.stderr.write('running host lookup on {}...\n'.format(domain))
        if domain not in domain_ip_table.keys():
            tmp = runcmd_rt('cut -d" " -f4',input=runcmd_rt('grep "has address"',input=runcmd_rt('host '+domain))).decode().strip().split('\n')
            if tmp == ['']:
                failed_lookups.append(domain)
            else:
                domain_ip_table[domain] = tmp
        else:
            pass
    if len(failed_lookups) != 0:
        sys.stderr.write('\nhost lookup failed for the following domains:\n')
        errlog_file.write('\nhost lookup failed for the following domains:\n')
        for i in failed_lookups:
            sys.stderr.write('\t'+str(i)+'\n')
            errlog_file.write('\t'+str(i)+'\n')
        sys.stderr.write('try increasing the timeout option or running a manual scan\n\n')
    for item in domain_ip_table.items():
        record = item[0]+':'+','.join(item[1])
        domain_ip_file.write(record+'\n')
        if stdout:
            sys.stdout.write(record+'\n')
    return (domain_ip_table,'domain')

def ip(input_data,timeout,output_dir,stdout,errlog_file):
    global previous_input
    input_ip = input_data[1]
    failed_scans = []
    if len(input_ip) == 0:
        sys.stderr.write('ip module specified without any input IP addresses!\nskipping...\n')
        return (None,'ip')
    big_ip_list = []
    if previous_input != None:
        if previous_input[1] == 'domain':
            tmp_ip_data = previous_input[0].values()
            for i in tmp_ip_data:
                for j in i:
                    big_ip_list.append(j)
            big_ip_list = list(set(big_ip_list))
            input_ip = input_ip + big_ip_list
    try:
        os.makedirs(output_dir+'/auto_osint_output'+'/ip/nmap',exist_ok=True)
    except OSError:
        sys.stderr.write('unable to create nmap directory!\nquitting...\n')
        sys.exit(1)
    ip_port_table = {}
    for ip in input_ip:
        sys.stderr.write('running nmap on '+ip+'\n')
        runcmd_rt('nmap -p- -sV -sT -nvv '+ip+' -oA '+output_dir+'/auto_osint_output'+'/ip/nmap/'+ip,timeout=timeout)
    for ip in input_ip:
        tmp = list(filter(None,runcmd_rt('cut -d"/" -f1',input=runcmd_rt('grep open',input=runcmd_rt('cat auto_osint_output/ip/nmap/'+ip+'.nmap'))).decode().split('\n')))
        if tmp == []:
            failed_scans.append(ip)
        else:
            ip_port_table[ip] = tmp
    try:
        os.makedirs(output_dir+'/auto_osint_output'+'/ip/port_scans',exist_ok=True)
    except OSError:
        sys.stderr.write('unable to create port_scans directory!\nquitting...\n')
        sys.exit(1)
    for item in ip_port_table.items():
        record = item[0]+':'+','.join(item[1])+'\n'
        open(output_dir+'/auto_osint_output/ip/port_scans/'+str(item[0])+'_open.ports','w').write(record)
        if stdout:
            sys.stdout.write(record)
    if len(failed_scans) != 0:
        sys.stderr.write('nmap scans failed to find open ports on the following IP addresses:\n\n')
        errlog_file.write('nmap scans failed to find open ports on the following IP addresses:\n\n')
        for i in failed_scans:
            sys.stderr.write('\t'+str(i)+'\n')
            errlog_file.write('\t'+str(i)+'\n')
        sys.stderr.write('try increasing the timeout option or running a manual scan\n\n')
        errlog_file.write('try increasing the timeout option or running a manual scan\n\n')
    return (ip_port_table,'ip')


def web(input_data,timeout,output_dir,stdout,errlog_file):
    global previous_input
    input_ip = input_data[0]
    input_domain = input_data[1]
    webserver_list = []
    try:
        os.makedirs(output_dir+'/auto_osint_output'+'/web',exist_ok=True)
    except OSError:
        sys.stderr.write('unable to create web directory!\nquitting...\n')
        return (None,'web')
    if previous_input == (None,None):
        sys.stderr.write('web module must be run with ip module!\nquitting...\n')
        sys.exit(1)
    elif previous_input[1] == 'ip':
        ip_port_table = previous_input[0]
        if ip_port_table == {}:
            sys.stderr.write('web module was unable to detect any webservers!\n')
            return (None,'web')
        else:
            for ip in ip_port_table.keys():
                for line in open(output_dir+'/auto_osint_output/ip/nmap/'+str(ip)+'.nmap').read().split('\n'):
                    for port in ip_port_table[ip]:
                        if port in line:
                            if 'open' in line:
                                if 'ssl/http' in line:
                                    webserver_list.append({'ip':ip,'port':port,'ssl':True,'backend':'unknown'})
                                elif 'http' in line:
                                    webserver_list.append({'ip':ip,'port':port,'ssl':False,'backend':'unknown'})
            if len(webserver_list) == 0:
                sys.stderr.write('web module was unable to detect any webservers!\n')
            else:
                sys.stderr.write('webservers found!\n')
                for webserv in webserver_list:
                    sys.stderr.write('running whatweb on {}'.format(webserv['ip']+':'+webserv['port']+'...\n'))
                    backend = runcmd_rt('whatweb --color=never '+webserv['ip']+':'+webserv['port'],timeout=timeout)
                    webserv['backend'] = backend.decode().strip('\n')
                    try:
                        os.makedirs(output_dir+'/auto_osint_output'+'/web/whatweb',exist_ok=True)
                    except OSError:
                        sys.stderr.write('unable to create whatweb directory!\nquitting...\n')
                        return (None,'web')
                    open(output_dir+'/auto_osint_output/web/whatweb/'+webserv['ip']+'.txt','w').write(str(webserv+'\n'))
                    if stdout:
                        sys.stdout.write(str(webserv+'\n'))
                    sys.stderr.write('running gobuster on {}'.format(webserv['ip']+':'+webserv['port']+'...\n'))
                    try:
                        os.makedirs(output_dir+'/auto_osint_output'+'/web/gobuster',exist_ok=True)
                    except OSError:
                        sys.stderr.write('unable to create subdirectory for gobuster!\n')
                        return (None,'web')
                    try:
                        os.makedirs(output_dir+'/auto_osint_output'+'/web/ssl',exist_ok=True)
                    except OSError:
                        sys.stderr.write('unable to create subdirectory for sslscan!\n')
                        return (None,'web')
                    if webserv['ssl']:
                        sys.stderr.write('running sslscan on {}'.format(webserv['ip']+':'+webserv['port']+'...\n'))
                        runcmd_rt('sslscan --xml='+output_dir+'/auto_osint_output/web/ssl/'+webserv['ip']+'.xml'+webserv['ip']+':'+webserv['port'],timeout=timeout)
                        runcmd_rt('gobuster dir -u https://'+webserv['ip']+':'+webserv['port']+' -w wordlists/bustlist.txt -o '+output_dir+'/auto_osint_output/web/gobuster/'+webserv['ip']+'.out',timeout=timeout)
                    else:
                        runcmd_rt('gobuster dir -u http://'+webserv['ip']+':'+webserv['port']+' -w wordlists/bustlist.txt -o '+output_dir+'/auto_osint_output/web/gobuster/'+webserv['ip']+'.out',timeout=timeout)
                    return (webserver_list,'web')
    else:
        sys.stderr.write('web module dependency error!\nquitting...\n')
        sys.exit(1)

#debug
def debug(*anyargs):
    print('debug')

def tbd(*anyargs):
    print('to be implemented')

args = _parser.parse_args()

module_table = {'debug':debug,'domain':domain,'ip':ip, 'web':web}

global previous_input

if __name__=='__main__':

    global previous_input
    previous_input = (None,None)
    #print(args)
    args_valid = True

    #check if args are valid

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

    #outputs
    if not os.path.isdir(args.output_dir):
        sys.stderr.write('output directory path is invalid!\n')
        args_valid = False
    else:
        try:
            os.makedirs(args.output_dir+'/auto_osint_output',exist_ok=True)
        except OSError as err:
            sys.stderr.write('cannot create subdirectory!\n')
            args_valid = False
        errlog_file = open(args.output_dir+'/auto_osint_output/error.log','w')

    #modules
    if args.modules == None:
        sys.stderr.write('select at least one module!\n')
        args_valid = False

    #if args not valid then quit
    if not args_valid:
        sys.stderr.write('quitting...\n\n')
        _parser.print_help()
        sys.exit(1)
    else: #fix inputs
        input_data = list(filter(None,input_data))
        input_ip = []
        input_domain = []

        for i in input_data:
            if ip_regex.match(i):
                input_ip.append(i)
            else:
                input_domain.append(i)

        input_data = (input_domain,input_ip)

        if 'all' not in args.modules.split(','):
            for module in module_table.keys():
                if module in args.modules.split(','):
                    previous_input = module_table[module](input_data,args.timeout,args.output_dir,args.stdout,errlog_file)
        else:
            all_mods = 'domain,ip,web'
            for module in module_table.keys():
                if module in all_mods.split(','):
                    previous_input = module_table[module](input_data,args.timeout,args.output_dir,args.stdout,errlog_file)
