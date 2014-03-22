#ifndef __UCLIENT_UTILS_H
#define __UCLIENT_UTILS_H

#include <stdbool.h>

struct http_digest_data {
	const char *uri;
	const char *method;

	const char *auth_hash; /* H(A1) */
	const char *qop;
	const char *nc;
	const char *nonce;
	const char *cnonce;
};

static inline int base64_len(int len)
{
	return ((len + 2) / 3) * 4;
}

void base64_encode(const void *inbuf, unsigned int len, void *out);
void bin_to_hex(char *dest, const void *buf, int len);

int uclient_urldecode(const char *in, char *out, bool decode_plus);

void http_digest_calculate_auth_hash(char *dest, const char *user, const char *realm, const char *password);
void http_digest_calculate_response(char *dest, const struct http_digest_data *data);

#endif
