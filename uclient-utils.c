/*
 * uclient - ustream based protocol client library
 *
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libubox/md5.h>
#include <libubox/utils.h>

#include "uclient-utils.h"

static const char *b64 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const void *inbuf, unsigned int len, void *outbuf)
{
	unsigned char *out = outbuf;
	const uint8_t *in = inbuf;
	unsigned int i;
	int pad = len % 3;

	for (i = 0; i < len - pad; i += 3) {
		uint32_t in3 = (in[0] << 16) | (in[1] << 8) | in[2];
		int k;

		for (k = 3; k >= 0; k--) {
			out[k] = b64[in3 & 0x3f];
			in3 >>= 6;
		}
		in += 3;
		out += 4;
	}

	if (pad) {
		uint32_t in2 = in[0] << (16 - 6);

		out[3] = '=';

		if (pad > 1) {
			in2 |= in[1] << (8 - 6);
			out[2] = b64[in2 & 0x3f];
		} else {
			out[2] = '=';
		}

		in2 >>= 6;
		out[1] = b64[in2 & 0x3f];
		in2 >>= 6;
		out[0] = b64[in2 & 0x3f];

		out += 4;
	}

	*out = '\0';
}

int uclient_urldecode(const char *in, char *out, bool decode_plus)
{
	static char dec[3];
	int ret = 0;
	char c;

	while ((c = *(in++))) {
		if (c == '%') {
			if (!isxdigit(in[0]) || !isxdigit(in[1]))
				return -1;

			dec[0] = in[0];
			dec[1] = in[1];
			c = strtol(dec, NULL, 16);
			in += 2;
		} else if (decode_plus && c == '+') {
			c = ' ';
		}

		*(out++) = c;
		ret++;
	}

	*out = 0;
	return ret;
}

static char hex_digit(char val)
{
	val += val > 9 ? 'a' - 10 : '0';
	return val;
}

void bin_to_hex(char *dest, const void *buf, int len)
{
	const uint8_t *data = buf;
	int i;

	for (i = 0; i < len; i++) {
		*(dest++) = hex_digit(data[i] >> 4);
		*(dest++) = hex_digit(data[i] & 0xf);
	}
	*dest = 0;
}

static void http_create_hash(char *dest, const char * const * str, int n_str)
{
	uint32_t hash[4];
	md5_ctx_t md5;
	int i;

	md5_begin(&md5);
	for (i = 0; i < n_str; i++) {
		if (i)
			md5_hash(":", 1, &md5);
		md5_hash(str[i], strlen(str[i]), &md5);
	}
	md5_end(hash, &md5);
	bin_to_hex(dest, &hash, sizeof(hash));
}

void http_digest_calculate_auth_hash(char *dest, const char *user, const char *realm, const char *password)
{
	const char *hash_str[] = {
		user,
		realm,
		password
	};

	http_create_hash(dest, hash_str, ARRAY_SIZE(hash_str));
}

void http_digest_calculate_response(char *dest, const struct http_digest_data *data)
{
	const char *h_a2_strings[] = {
		data->method,
		data->uri,
	};
	const char *resp_strings[] = {
		data->auth_hash,
		data->nonce,
		data->nc,
		data->cnonce,
		data->qop,
		dest, /* initialized to H(A2) first */
	};

	http_create_hash(dest, h_a2_strings, ARRAY_SIZE(h_a2_strings));
	http_create_hash(dest, resp_strings, ARRAY_SIZE(resp_strings));
}
