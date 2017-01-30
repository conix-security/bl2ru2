#!/usr/bin/python3
# Copyright 2013, 2014, 2017 Conix Cybersécurité
# Copyright 2013 Adrien Chevalier
# Copyright 2013, 2014 Alexandre Deloup
# Copyright 2017 Robin Marsollier
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import argparse
import re

#TODO:
#   - add -s --sid option to let user specify the starting sid
#   - add rule for md5
#   - manage uri like example.com/stuff_here
#   - make the prints to tsdout conditionnals to args.output
#   - add exception PermissionError if .sid and output file can't be written
#   - add baserule for domain in ssl cert (if possible)
#   - add rules examples along the baserules
#   - smb/netbios etc ?

# To add a rule class while keeping the code clean, add the baserule here
IP_UDP_BASERULE = 'alert udp $HOME_NET any -> %s any (msg:"%s - %s - UDP traffic to %s"; classtype:trojan-activity; reference:url,%s; sid:%d; rev:1;)'
IP_TCP_BASERULE = 'alert tcp $HOME_NET any -> %s any (msg:"%s - %s - TCP traffic to %s"; classtype:trojan-activity; reference:url,%s; sid:%d; rev:1;)'
IP_BASERULE = 'alert ip $HOME_NET any -> %s any (msg:"%s - %s - IP traffic to %s"; classtype:trojan-activity; reference:url,%s; sid:%d; rev:1;)'
DNS_BASERULE = 'alert udp $HOME_NET any -> any 53 (msg:%s - %s - DNS request for %s"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:20; offset: 2; content:"%s"; fast_pattern:only; nocase; classtype:trojan-activity; reference:url,%s; sid: %d; rev:1 )'
URL_BASERULE = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"%s - %s - Related URL (%s)"; content:"%s"; http_uri;%s classtype:trojan-activity; reference:url,%s; sid:%d; rev:1;)'

def main(args):
    global ORG
    ORG = args.emitter

    #############################
    #       Latest SID
    print("[+] Getting SID")
    try:
        with open(".sid_log_file", "r") as f_sid_log_file:
            line = f_sid_log_file.readline()
            sid = int(line)
    except FileNotFoundError:
        sid = 5100000
        print("[-] .sid_log_file not found, starting SID from %s"%str(sid))

    #############################
    #       Generating rules
    print("[+] Generating rules")
    with open(args.file, "r") as f_input:
        rules = []
        for line in f_input:
            line = line.strip()
            (name, ioc, url) = split_line(line)
            sid += 1
            if ioc.startswith("/"):
                # URL it is
                rules.append(gen_url_rule(name, ioc, url, sid))
            elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ioc):
                # IP it is
                #rules.append(gen_ip_rule_udp(name, ioc, url, sid))
                #sid += 1
                #rules.append(gen_ip_rule_tcp(name, ioc, url, sid))
                #sid += 1
                rules.append(gen_ip_rule(name, ioc, url, sid))
            else:
                # Well, by lack of other option, let's say it is a domain name
                rules.append(gen_dns_rule(name, ioc, url, sid))
                sid += 1
                rules.append(gen_url_rule(name, ioc, url, sid))

    #############################
    #       Writing rules to file
    if args.output:
        print("[+] Writing Rule file")
        with open(args.output, "a") as f_out:
            for rule in rules:
                f_out.write("%s \n"%(rule))
    else:
        for rule in rules:
            print("%s"%rule)

    #############################
    #       Logging max sid
    print("[+] Writing Last SID")
    with open(".sid_log_file", "w") as f_sid:
        f_sid.write("%d"%(sid))

    return True

def gen_dns_rule(name, domain, ref, sid):
    '''
    Generate suricata rule for a domain
    '''
    members = domain.split(".")
    dns_request = ""
    for member in members:
        dns_request += "|%0.2X|%s"%(len(member), member)
    rule = (DNS_BASERULE%(ORG, name, domain, dns_request, ref, sid))

    return rule

def gen_url_rule(name, url, ref, sid):
    '''
    Generate suricata rule for an url
    '''
    #TODO: check this thing against real url
    uri = url.split("?")[0]
    #If there are many "?" in the complete url, colapse them
    uri_params = "?".join(url.split("?")[1:])
    rule_content = ""
    if uri_params:
        params = uri_params.split("&")
        rule_content = ' content:"?%s=";'%(params[0].split("=")[0])
        for param in params[1:]:
            rule_content += ' content:"&%s=";'%(param.split("=")[0])
    rule = (URL_BASERULE%(ORG, name, uri, uri, rule_content, ref, sid))
    return rule

def gen_ip_rule_udp(name, ip_addr, ref, sid):
    '''
    Generate suricata rule for an IP, traffic over udp
    '''
    rule = (IP_UDP_BASERULE%(ORG, ip_addr, name, ip_addr, ref, sid))
    return rule

def gen_ip_rule_tcp(name, ip_addr, ref, sid):
    '''
    Generate suricata rule for an IP, traffic over tcp
    '''
    rule = (IP_TCP_BASERULE%(ORG, ip_addr, name, ip_addr, ref, sid))
    return rule

def gen_ip_rule(name, ip_addr, ref, sid):
    '''
    Generate suricata rule for an IP
    '''
    rule = (IP_BASERULE%(ORG, ip_addr, name, ip_addr, ref, sid))
    return rule

def split_line(line):
    '''
    Cut the line to extract the different fields
    '''
    (name, value, ref_url) = line.split(';', 3)
    name = name.strip()
    ioc = value.strip()
    ref_url = ref_url.strip()
    return name, ioc, ref_url

if __name__ == '__main__':
    __parser__ = argparse.ArgumentParser()
    __parser__.add_argument("file", help="Input file")
    __parser__.add_argument("--output", "-o", help="Output file")
    __parser__.add_argument("--emitter", "-e", \
            help="Emitter of the rules, default: bl2ru2", default="bl2ru2")
    __args__ = __parser__.parse_args()
    main(__args__)
