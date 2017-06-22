# domino-nginx-auth
Nginx auth_http servlet for IBM Domino Servers

This project contains an OSGi servlet that implements the [NGINX auth protocol](http://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html)
to validate SMTP credentials when using nginx as a mail proxy in front of Domino.

## Installation
Create and register an Eclipse Update Site database on your Domino server ([detailed description from IBM](https://www-10.lotus.com/ldd/ddwiki.nsf/xpAPIViewer.xsp?lookupName=XPages+Extensibility+API#action=openDocument&res_title=XPages_Extension_Library_Deployment&content=apicontent)).

Next import the binary release of this project (or build your own from source code) and restart the http server task with `restart task http`.

## Configuration
The servlet expects a set of Notes.ini variables on the server to configure its behavior:

```
# REQUIRED: comma separated list of mail domains that are considered as local (used when receiving data via SMTP from external hosts)
$NGINXAUTH_LOCALDOMAINS=mymaildomain.com,mymaildomain.de
# OPTIONAL: the UO address that nginx should use to connect to Domino's SMTP task (if missing we pick the first local IP we can find)
$NGINXAUTH_PUBLICIP=1.2.3.4
# OPTIONAL: writes debug messages for each SMTP connection to the server console (false by default)
$NGINXAUTH_DEBUG=true
# OPTIONAL: switch to disable the servlet (true by default)
$NGINXAUTH_ENABLED=true
# OPTIONAL: name of HTTP header with secret value to send back; use nginx switch auth_http_header to validate
$NGINXAUTH_AUTHKEY_HEADER=X-NGX-Auth-Key
# OPTIONAL: secret value of HTTP header with secret value to send back; use nginx switch auth_http_header to validate
$NGINXAUTH_AUTHKEY_VALUE=81jbdvdl
# OPTIONAL: number of seconds to wait when receiving wrong SMTP credentials
$NGINXAUTH_WAITONERROR=3
```

## Licence
The code is available under Apache 2.0 license.

Copyright by [Mindoo GmbH](http://www.mindoo.com)


 