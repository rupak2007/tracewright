# Tracewright Zeek site policy (architecture §5).
# Loads only the analyzers P1 needs and keeps password capture OFF (SEC-08).
# Do not load local.zeek, packages, or anything that executes capture-derived content.

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/ssl
@load base/files/x509

redef LogAscii::use_json = T;

# Passwords must never be written to logs.
redef FTP::default_capture_password = F;
redef HTTP::default_capture_password = F;
