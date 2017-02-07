# bl2ru2
This tool is aimed to be the succesor of bl2ru.

This tools creates suricate rules for the following IOC types :
- domain
- IP
- URL

While the original bl2ru performed dns requests to retrieve ip adresses associated with each domain of the domain list given (and thus sometimes duplicating rules), this tool takes another approach and let your TI determine this and only create rules for given input, without trying any enrichment of the data.


# Usage
```
$  python3 bl2ru2.py --help
usage: bl2ru2.py [-h] [--output OUTPUT] [--emitter EMITTER] file

positional arguments:
  file                  Input file

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output file
  --emitter EMITTER, -e EMITTER
                        Emitter of the rules, default: bl2ru2
```
The input file must be a csv-like file (delimiter is a space) containing the following information, 3 rows :
- first row : Threat name
- second row : Link to a reference
- third row : IOC

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

# TODO
- add baserule for domain in ssl cert (if possible)
- smb/netbios etc ?
