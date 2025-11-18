#!/bin/bash
set -e
set -x
set -v

####Set up the degraded tests...
uaac target ${PROTOCOL}://$PUBLISHED_DOMAIN
uaac token client get admin -s ${ADMIN_CLIENT_SECRET}

uaac client get admin
uaac client update admin --authorities "zones.test-app-zone.admin zones.test-platform-zone.admin zones.write zones.read zones.uaa.admin clients.read clients.secret clients.write clients.admin uaa.admin password.write scim.write scim.read idps.read idps.write sps.read sps.write"

#Create test-app-zone (Application UAA) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-app-zone", "subdomain":"test-app-zone", "name":"test-app-zone"}'
uaac curl -t -H "X-Identity-Zone-Id:test-app-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "'"$ZONE_ADMIN_SECRET"'", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-app-zone.admin", "idps.read", "idps.write", "uaa.resource"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Create test-platform-zone (Platform UAA) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-platform-zone", "subdomain":"test-platform-zone", "name":"test-platform-zone", "config": {"idpDiscoveryEnabled" : true, "prompts" : [ {"name" : "username","type" : "text","text" : "username"}, {"name" : "password","type" : "password","text" : "password"}], "links" : {"selfService" : {"selfServiceLinksEnabled" : false}} }}'
uaac curl -t -H "X-Identity-Zone-Id:test-platform-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "'"$ZONE_ADMIN_SECRET"'", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-platform-zone.admin", "idps.read", "idps.write"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Create test-saml-zone (SAML IDP) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-saml-zone", "subdomain":"test-saml-zone", "name":"test-saml-zone"}'
uaac curl -t -H "X-Identity-Zone-Id:test-saml-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "'"$ZONE_ADMIN_SECRET"'",  "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-saml-zone.admin", "idps.read", "idps.write"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients


#Login to test-saml-zone
uaac target ${PROTOCOL}://test-saml-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET

#Create some saml users
uaac user add samluser1 -p SamlUser10@ --email samluser1@ge.com || true

uaac user add samluser2 -p SamlUser20@ --email samluser2@ge.com || true

uaac user add 1234 -p UserGE30@ --email user3@ge.com || true

#Login to test-platform-zone
uaac target ${PROTOCOL}://test-platform-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET

#Create migrated saml users
uaac curl '/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
  "externalId" : "1234",
  "meta" : {
    "version" : 0,
    "created" : "2016-09-09T00:34:22.087Z"
  },
  "userName" : "1234",
  "name" : {
    "formatted" : "given name family name",
    "familyName" : "family name",
    "givenName" : "given name"
  },
  "emails" : [ {
    "value" : "user3@ge.com",
    "primary" : true
  } ],
  "active" : true,
  "verified" : true,
  "origin" : "test-saml-zone-idp",
  "schemas" : [ "urn:scim:schemas:core:1.0" ]
}'

#Login to test-saml-zone
uaac target ${PROTOCOL}://test-saml-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET

#Login to test-app-zone
uaac target ${PROTOCOL}://test-app-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET


#Create a client for implicit flow
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.resource","openid" ],
  "client_id" : "cf",
  "authorized_grant_types" : [ "implicit" ],
  "authorities" : [ "uaa.resource", "openid" ],
  "redirect_uri" : "'"${PROTOCOL}"'://*.example.com/**",
  "autoapprove" : [ "uaa.resource","openid" ],
  "allowedproviders" : ["uaa"]
}'

#Create a client to check token.
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "openid" ],
  "client_id" : "app",
  "client_secret" : "'"$BASIC_AUTH_CLIENT_SECRET"'",
  "authorized_grant_types" : [ "client_credentials" , "password" ],
  "authorities" : [ "uaa.resource" ]
}'

uaac user add marissa -p KOala12@ --email marissa@ge.com || true

uaac group add zones.test-app-zone.admin || true

uaac group add sps.read || true

uaac group add sps.write || true