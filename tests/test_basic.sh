#!/bin/bash

# TERMINAL COLOR CONSTANTS
RED='\033[0;31m'
GREEN='\033[0;32m'
NOCOLOR='\033[0m'

function print_step () { echo ""; echo "===[ TEST $1 ]=========================="; }
function passed () { printf "${GREEN}test passed  ✅${NOCOLOR}\n"; }
function failed () { printf "${RED}test failed with rc $? ❌${NOCOLOR}\n"; }

function run_test() {
    time eval $1
    if [ $? == 0 ]
    then
        passed
    else
        failed
    fi
}

print_step "URL basic"
run_test "./feedreader https://api-web.novinky.cz/v1/timelines/section_5ad5a5fcc25e64000bd6e7ab?xml=rss >> /dev/null"

print_step "feedile with redirect (expect no XML found error for theregister.co.uk)"
run_test "./feedreader -f tests/test_feedfile.txt >> /dev/null"

print_step "option flags"
run_test "./feedreader https://api-web.novinky.cz/v1/timelines/section_5ad5a5fcc25e64000bd6e7ab?xml=rss  -Tau >> /dev/null"

print_step "http only"
run_test "./feedreader -f tests/http_feedfile.txt  >> /dev/null"

print_step "RSS1.0 support (expect not supported)"
run_test "./feedreader https://web.resource.org/rss/1.0/schema.rdf >> /dev/null"

print_step "wrong link (expect invalid format)"
run_test "./feedreader random.link.com >> /dev/null"