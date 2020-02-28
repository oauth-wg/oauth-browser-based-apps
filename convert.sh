#!/bin/bash

kramdown-rfc2629 oauth-browser-based-apps.md > build/oauth-browser-based-apps.xml

./replacements.php

xml2rfc build/oauth-browser-based-apps.xml
xml2rfc --html build/oauth-browser-based-apps.xml

# https://datatracker.ietf.org/submit/

