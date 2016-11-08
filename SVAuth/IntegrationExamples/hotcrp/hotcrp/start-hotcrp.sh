#!/bin/bash
sleep 10 && cd /app && ./lib/createdb.sh --batch --replace hotcrp && chmod 0755 conf/options.php
