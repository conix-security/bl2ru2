# bl2ru2
This tool is aimed to be the successor of bl2ru.

This tools creates suricata rules for the following IOC types:
- domain: DNS request rule, HTTP request rule and TLS SNI rule
- IP: IP rule
- URL: HTTP/URL request rule (not yet fully tested)

While the original bl2ru performed dns requests to retrieve ip adresses associated with each domain of the domain list given (and thus sometimes duplicating rules), this tool takes another approach and let your TI determine this and only create rules for given input, without trying any enrichment of the data.

To ensure maximum efficiency ofthis tool, your upstream Threat Intelligence should take care of:
- duplicates elimination
- data enrichment
- data splitting (i.e. split conix.fr/nos-expertises/ssi/ in conix.fr and /nos_expertises/ssi)
# Installation
```
pip3 install bl2ru2
```

# Usage
```
$  python3 bl2ru2.py --help
usage: bl2ru2.py [-h] [--output OUTPUT] [--ssid SSID] [--emitter EMITTER] file

positional arguments:
  file                  Input file

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output file (default is stdou)
  --ssid SSID, -s SSID  Starting sid of the generated rules
  --emitter EMITTER, -e EMITTER
                        Emitter of the rules, default: bl2ru2

```
The input file must be a csv-like file (delimiter is a space) containing the following information, 3 rows :
- first row : Threat name
- second row : Link to a reference
- third row : IOC

Like:
```
LuminosityLink http://www.conix.fr 030092056f0368639145711a615d3b7f.co.cc
```

# Example
```
$  cat blacklist.txt
LuminosityLink https://www.conix.fr 030092056f0368639145711a615d3b7f.co.cc
LuminosityLink https://www.conix.fr 70.30.5.3
$
$
$  python3 bl2ru2.py blacklist.txt -o cert-conix.rules -e CERT-Conix
[+] Getting SID
[+] Generating rules
[+] Writing Rule file
[+] Writing Last SID
$
$
$  cat cert-conix.rules
alert udp $HOME_NET any -> any 53 (msg:CERT-Conix - LuminosityLink - DNS request for 030092056f0368639145711a615d3b7f.co.cc"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:20; offset: 2; content:"|20|030092056f0368639145711a615d3b7f|02|co|02|cc"; fast_pattern:only; nocase; classtype:trojan-activity; reference:url,https://conix.fr; sid: 5100004; rev:1 )
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"CERT-Conix - LuminosityLink - Related URL (030092056f0368639145711a615d3b7f.co.cc)"; content:"030092056f0368639145711a615d3b7f.co.cc"; http_uri; classtype:trojan-activity; reference:url,https://conix.fr; sid:5100005;rev:1;)
alert ip $HOME_NET any -> 70.30.5.3 any (msg:"CERT-Conix - LuminosityLink - IP traffic to 70.30.5.3"; classtype:trojan-activity; reference:url,https://conix.fr; sid:5100006; rev:1;)
```

# Adding your own rule generator
If you find yourself in the need of another rule type not generated yet by bl2ru2, follow the following procedure:
- add the base rule on the top of the bl2ru2.py file
- create the gen_SMTHG_rule() function that is going to generate the rules using the baserule defined before
- modify the generate_rules() function to call your new generator
- Pull request your changes

# TODO
- smb/netbios rules?

# Authors
- Robin Marsollier
