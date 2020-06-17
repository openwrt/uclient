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
#ifndef __LIBUBOX_UCLIENT_H
#define __LIBUBOX_UCLIENT_H

#include <netinet/in.h>

#include <libubox/blob.h>
#include <libubox/ustream.h>
#include <libubox/ustream-ssl.h>

#define UCLIENT_DEFAULT_TIMEOUT_MS			30000

struct uclient_cb;
struct uclient_backend;

enum uclient_error_code {
	UCLIENT_ERROR_UNKNOWN,
	UCLIENT_ERROR_CONNECT,
	UCLIENT_ERROR_TIMEDOUT,
	UCLIENT_ERROR_SSL_INVALID_CERT,
	UCLIENT_ERROR_SSL_CN_MISMATCH,
	UCLIENT_ERROR_MISSING_SSL_CONTEXT,
	__UCLIENT_ERROR_MAX
};

union uclient_addr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

struct uclient_url {
	const struct uclient_backend *backend;
	int prefix;

	const char *host;
	const char *port;
	const char *location;

	const char *auth;
};

struct uclient {
	const struct uclient_backend *backend;
	const struct uclient_cb *cb;

	union uclient_addr local_addr, remote_addr;

	struct uclient_url *proxy_url;
	struct uclient_url *url;
	int timeout_msecs;
	void *priv;

	bool eof;
	bool data_eof;
	int error_code;
	int status_code;
	int seq;
	struct blob_attr *meta;

	struct uloop_timeout connection_timeout;
	struct uloop_timeout timeout;
};

struct uclient_cb {
	void (*data_read)(struct uclient *cl);
	void (*data_sent)(struct uclient *cl);
	void (*data_eof)(struct uclient *cl);
	void (*header_done)(struct uclient *cl);
	void (*error)(struct uclient *cl, int code);
};

struct uclient *uclient_new(const char *url, const char *auth_str, const struct uclient_cb *cb);
void uclient_free(struct uclient *cl);

int uclient_set_url(struct uclient *cl, const char *url, const char *auth);
int uclient_set_proxy_url(struct uclient *cl, const char *url_str, const char *auth_str);


/**
 * Sets connection timeout.
 *
 * Provided timeout value will be used for:
 * 1) Receiving HTTP response
 * 2) Receiving data
 *
 * In case of timeout uclient will use error callback with
 * UCLIENT_ERROR_TIMEDOUT code.
 *
 * @param msecs timeout in milliseconds
 */
int uclient_set_timeout(struct uclient *cl, int msecs);

int uclient_connect(struct uclient *cl);
void uclient_disconnect(struct uclient *cl);

int uclient_read(struct uclient *cl, char *buf, int len);
int uclient_write(struct uclient *cl, const char *buf, int len);
int uclient_request(struct uclient *cl);

char *uclient_get_addr(char *dest, int *port, union uclient_addr *a);

/* HTTP */
extern const struct uclient_backend uclient_backend_http;

int uclient_http_reset_headers(struct uclient *cl);
int uclient_http_set_header(struct uclient *cl, const char *name, const char *value);
int uclient_http_set_request_type(struct uclient *cl, const char *type);
int uclient_http_redirect(struct uclient *cl);

int uclient_http_set_ssl_ctx(struct uclient *cl, const struct ustream_ssl_ops *ops,
			     struct ustream_ssl_ctx *ctx, bool require_validation);
int uclient_http_set_address_family(struct uclient *cl, int af);
const char *uclient_strerror(unsigned err);

#endif
