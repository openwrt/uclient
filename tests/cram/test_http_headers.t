Response header lines may span the default stream buffer, including a folded
header or a redirect followed by a response body:

  $ python3 "$TESTDIR/http_headers.py"
  /boundary: OK
  /long: OK
  /folded: OK
  /redirect: OK
  /lf: OK
