#!/bin/bash

kramdown-rfc2629 oauth-browser-based-apps.md > build/oauth-browser-based-apps.xml

./replacements.php

curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-browser-based-apps.xml -F 'modeAsFormat=txt/ascii' -F type=ascii > build/oauth-browser-based-apps.txt
curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-browser-based-apps.xml -F 'modeAsFormat=html/ascii' -F type=ascii > build/oauth-browser-based-apps.html

# https://datatracker.ietf.org/submit/

