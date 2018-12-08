#!/usr/local/bin/php
<?php

$xml = file_get_contents('build/oauth-browser-based-apps.xml');

$xml = str_replace('<area>OAuth</area>', "<area>Security Area</area>\n    <workgroup>Open Authentication Protocol</workgroup>", $xml);
$xml = str_replace('<author initials="." surname="whatwg" fullname="whatwg">
      <organization></organization>
    </author>',
 '<author>
      <organization>whatwg</organization>
    </author>', $xml);

file_put_contents('build/oauth-browser-based-apps.xml', $xml);

