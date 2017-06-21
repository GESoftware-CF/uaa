#!/bin/bash

set -e -x -v

uaac target ${PROTOCOL}://$PUBLISHED_DOMAIN
uaac token client get admin -s ${ADMIN_CLIENT_SECRET}

uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.none"],
  "client_id" : "c1",
  "authorized_grant_types" : [ "urn:ietf:params:oauth:grant-type:jwt-bearer" ],
  "authorities" : [ "machine.m1.admin" ],
  "allowed_device_id" : "d10"
}'
