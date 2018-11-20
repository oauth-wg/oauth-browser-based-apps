#!/bin/bash

kramdown-rfc2629 oauth-browser-based-apps.md > build/oauth-browser-based-apps.xml

curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-browser-based-apps.xml -F 'modeAsFormat=txt/ascii' -F type=ascii > build/oauth-browser-based-apps.txt
curl https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi -F input=@build/oauth-browser-based-apps.xml -F 'modeAsFormat=html/ascii' -F type=ascii > build/oauth-browser-based-apps.html

sed -i .bak 's/, \.//' build/oauth-browser-based-apps.txt
rm build/oauth-browser-based-apps.txt.bak

sed -i .bak 's/, \.//' build/oauth-browser-based-apps.html
rm build/oauth-browser-based-apps.html.bak
