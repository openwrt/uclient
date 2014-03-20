#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

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
