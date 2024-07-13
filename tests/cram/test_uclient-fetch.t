check uclient-fetch usage:

  $ [ -n "$BUILD_BIN_DIR" ] && export PATH="$BUILD_BIN_DIR:$PATH"
  $ alias uc='valgrind --quiet --leak-check=full uclient-fetch'

  $ uc
  Usage: uclient-fetch [options] <URL>
  Options:
  \t-4\t\t\t\tUse IPv4 only (esc)
  \t-6\t\t\t\tUse IPv6 only (esc)
  \t-O <file>\t\t\tRedirect output to file (use "-" for stdout) (esc)
  \t-P <dir>\t\t\tSet directory for output files (esc)
  \t--quiet | -q\t\t\tTurn off status messages (esc)
  \t--continue | -c\t\t\tContinue a partially-downloaded file (esc)
  \t--header='Header: value'\tAdd HTTP header. Multiple allowed (esc)
  \t--user=<user>\t\t\tHTTP authentication username (esc)
  \t--password=<password>\t\tHTTP authentication password (esc)
  \t--user-agent | -U <str>\t\tSet HTTP user agent (esc)
  \t--post-data=STRING\t\tuse the POST method; send STRING as the data (esc)
  \t--post-file=FILE\t\tuse the POST method; send FILE as the data (esc)
  \t--method=METHOD\t\tuse the HTTP method e.g. PUT (esc)
  \t--body-data=STRING\t\twith --method send the STRING in body (esc)
  \t--body-file=FILE\t\twith --method send the FILE content in body (esc)
  \t--spider | -s\t\t\tSpider mode - only check file existence (esc)
  \t--timeout=N | -T N\t\tSet connect/request timeout to N seconds (esc)
  \t--proxy=on | -Y on\t\tEnable interpretation of proxy env vars (default) (esc)
  \t--proxy=off | -Y off | (esc)
  \t--no-proxy           \t\tDisable interpretation of proxy env vars (esc)
  
  HTTPS options:
  \t--ca-certificate=<cert>\t\tLoad CA certificates from file <cert> (esc)
  \t--no-check-certificate\t\tdon't validate the server's certificate (esc)
  \t--ciphers=<cipherlist>\t\tSet the cipher list string (esc)
  
  [1]

download lorem ipsum verbose:

  $ uc -O lorem http://127.0.0.1:1922/lorem
  Downloading 'http://127.0.0.1:1922/lorem'
  Connecting to 127.0.0.1:1922
  Writing to 'lorem'
  \r (no-eol) (esc)
  lorem                100% |*******************************|  4111   0:00:00 ETA
  Download completed (4111 bytes)

  $ md5sum lorem
  887943f7c25bd6cec4570c405241b425  lorem

download lorem ipsum quiet:

  $ uc -q -O lorem http://127.0.0.1:1922/lorem

  $ md5sum lorem
  887943f7c25bd6cec4570c405241b425  lorem

check that HTTP 404 errors are handled properly:

  $ uc http://127.0.0.1:1922/does-not-exist
  Downloading 'http://127.0.0.1:1922/does-not-exist'
  Connecting to 127.0.0.1:1922
  HTTP error 404
  [8]

  $ uc -q http://127.0.0.1:1922/does-not-exist
  [8]

check that SSL works:

  $ uc -q -O /dev/null 'https://www.openwrt.org'

  $ uc -q -O /dev/null 'https://letsencrypt.org'

  $ uc -O /dev/null 'https://downloads.openwrt.org/does-not-exist' 2>&1 | grep error
  HTTP error 404

check handling of certificate issues:

  $ uc -O /dev/null 'https://self-signed.badssl.com/' 2>&1 | grep error
  Connection error: Invalid SSL certificate

  $ uc -O /dev/null 'https://untrusted-root.badssl.com/' 2>&1 | grep error
  Connection error: Invalid SSL certificate

  $ uc -O /dev/null 'https://expired.badssl.com/' 2>&1 | grep error
  Connection error: Invalid SSL certificate

  $ uc --ca-certificate=/dev/null -O /dev/null 'https://www.openwrt.org/' 2>&1 | grep error
  Connection error: Invalid SSL certificate

check that certificate issues can be disabled:

  $ uc --no-check-certificate -q -O /dev/null 'https://self-signed.badssl.com/'

  $ uc --no-check-certificate -q -O /dev/null 'https://untrusted-root.badssl.com/'

  $ uc --no-check-certificate -q -O /dev/null 'https://expired.badssl.com/'
