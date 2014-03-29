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
#include <libubox/ustream-ssl.h>
#include "uclient.h"
#include "uclient-utils.h"
#include "uclient-backend.h"

struct uclient_url __hidden *
uclient_get_url(const char *url_str, const char *auth_str)
{
	static const struct uclient_backend *backends[] = {
		&uclient_backend_http,
	};

	const struct uclient_backend *backend;
	const char * const *prefix = NULL;
	struct uclient_url *url;
	const char *location;
	char *host_buf, *uri_buf, *auth_buf, *next;
	int i, host_len;

	for (i = 0; i < ARRAY_SIZE(backends); i++) {
		int prefix_len = 0;

		for (prefix = backends[i]->prefix; *prefix; prefix++) {
			prefix_len = strlen(*prefix);

			if (!strncmp(url_str, *prefix, prefix_len))
				break;
		}

		if (!*prefix)
			continue;

		url_str += prefix_len;
		backend = backends[i];
		break;
	}

	if (!*prefix)
		return NULL;

	next = strchr(url_str, '/');
	if (next) {
		location = next;
		host_len = next - url_str;
	} else {
		location = "/";
		host_len = strlen(url_str);
	}

	url = calloc_a(sizeof(*url),
		&host_buf, host_len + 1,
		&uri_buf, strlen(location) + 1,
		&auth_buf, auth_str ? strlen(auth_str) + 1 : 0);

	url->backend = backend;
	url->location = strcpy(uri_buf, location);
	url->prefix = prefix - backend->prefix;

	url->host = strncpy(host_buf, url_str, host_len);

	next = strchr(host_buf, '@');
	if (next) {
		*next = 0;
		url->host = next + 1;

		if (uclient_urldecode(host_buf, host_buf, false) < 0)
			goto free;

		url->auth = host_buf;
	}

	if (!url->auth && auth_str)
		url->auth = strcpy(auth_buf, auth_str);

	/* Literal IPv6 address */
	if (*url->host == '[') {
		url->host++;
		next = strrchr(url->host, ']');
		if (!next)
			goto free;

		*(next++) = 0;
		if (*next == ':')
			url->port = next + 1;
	} else {
		next = strrchr(url->host, ':');
		if (next) {
			*next = 0;
			url->port = next + 1;
		}
	}

	return url;

free:
	free(url);
	return NULL;
}

struct uclient *uclient_new(const char *url_str, const char *auth_str, const struct uclient_cb *cb)
{
	struct uclient *cl;
	struct uclient_url *url;

	url = uclient_get_url(url_str, auth_str);
	if (!url)
		return NULL;

	cl = url->backend->alloc();
	if (!cl)
		return NULL;

	cl->backend = url->backend;
	cl->cb = cb;
	cl->url = url;

	return cl;
}

int uclient_set_url(struct uclient *cl, const char *url_str, const char *auth_str)
{
	const struct uclient_backend *backend = cl->backend;
	struct uclient_url *url = cl->url;

	url = uclient_get_url(url_str, auth_str);
	if (!url)
		return -1;

	if (url->backend != cl->backend)
		return -1;

	free(cl->url);
	cl->url = url;

	if (backend->update_url)
		backend->update_url(cl);

	return 0;
}

int uclient_connect(struct uclient *cl)
{
	return cl->backend->connect(cl);
}

void uclient_free(struct uclient *cl)
{
	struct uclient_url *url = cl->url;

	if (cl->backend->free)
		cl->backend->free(cl);
	else
		free(cl);

	free(url);
}

int uclient_write(struct uclient *cl, char *buf, int len)
{
	if (!cl->backend->write)
		return -1;

	return cl->backend->write(cl, buf, len);
}

int uclient_request(struct uclient *cl)
{
	if (!cl->backend->request)
		return -1;

	return cl->backend->request(cl);
}

int uclient_read(struct uclient *cl, char *buf, int len)
{
	if (!cl->backend->read)
		return -1;

	return cl->backend->read(cl, buf, len);
}

static void __uclient_backend_change_state(struct uloop_timeout *timeout)
{
	struct uclient *cl = container_of(timeout, struct uclient, timeout);

	if (cl->error_code && cl->cb->error)
		cl->cb->error(cl, cl->error_code);
	else if (cl->eof && cl->cb->data_eof)
		cl->cb->data_eof(cl);
}

static void uclient_backend_change_state(struct uclient *cl)
{
	cl->timeout.cb = __uclient_backend_change_state;
	uloop_timeout_set(&cl->timeout, 1);
}

void __hidden uclient_backend_set_error(struct uclient *cl, int code)
{
	if (cl->error_code)
		return;

	cl->error_code = code;
	uclient_backend_change_state(cl);
}

void __hidden uclient_backend_set_eof(struct uclient *cl)
{
	if (cl->eof || cl->error_code)
		return;

	cl->eof = true;
	uclient_backend_change_state(cl);
}

void __hidden uclient_backend_reset_state(struct uclient *cl)
{
	cl->eof = false;
	cl->error_code = 0;
	uloop_timeout_cancel(&cl->timeout);
}
