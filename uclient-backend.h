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
#ifndef __UCLIENT_INTERNAL_H
#define __UCLIENT_INTERNAL_H

struct uclient_url;

struct uclient_backend {
	const char * const * prefix;

	struct uclient *(*alloc)(void);
	void (*free)(struct uclient *cl);
	void (*update_url)(struct uclient *cl);

	int (*connect)(struct uclient *cl);
	int (*request)(struct uclient *cl);
	void (*disconnect)(struct uclient *cl);

	int (*read)(struct uclient *cl, char *buf, unsigned int len);
	int (*write)(struct uclient *cl, char *buf, unsigned int len);
};

void uclient_backend_set_error(struct uclient *cl, int code);
void uclient_backend_set_eof(struct uclient *cl);
void uclient_backend_reset_state(struct uclient *cl);
struct uclient_url *uclient_get_url(const char *url_str, const char *auth_str);

#endif
