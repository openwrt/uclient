#ifndef __UCLIENT_UTILS_H
#define __UCLIENT_UTILS_H

#include <stdbool.h>

static inline int base64_len(int len)
{
	return ((len + 2) / 3) * 4;
}

void base64_encode(const void *inbuf, unsigned int len, void *out);

int uclient_urldecode(const char *in, char *out, bool decode_plus);


#endif
