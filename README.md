bl2ru2
=====

This tool is aimed to be the succesor of bl2ru.

This tools creates suricate rules for the following IOC types :
- domain 
- IP
- URL 

While the original bl2ru performed dns requests to retrieve ip adresses associated with each domain of the domain list given (and thus sometimes duplicating rules), this tool takes another approach and let your TI determine this and only create rules for given input, without trying any enrichment of the data.
