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
#include <arpa/inet.h>
#include <libubox/ustream-ssl.h>
#include "uclient.h"
#include "uclient-utils.h"
#include "uclient-backend.h"

char *uclient_get_addr(char *dest, int *port, union uclient_addr *a)
{
	int portval;
	void *ptr;

	switch(a->sa.sa_family) {
	case AF_INET:
		ptr = &a->sin.sin_addr;
		portval = a->sin.sin_port;
		break;
	case AF_INET6:
		ptr = &a->sin6.sin6_addr;
		portval = a->sin6.sin6_port;
		break;
	default:
		return strcpy(dest, "Unknown");
	}

	inet_ntop(a->sa.sa_family, ptr, dest, INET6_ADDRSTRLEN);
	if (port)
		*port = ntohs(portval);

	return dest;
}

static struct uclient_url *
__uclient_get_url(const struct uclient_backend *backend,
		  const char *host, int host_len,
		  const char *location, const char *auth_str)
{
	struct uclient_url *url;
	char *host_buf, *uri_buf, *auth_buf, *next;

	url = calloc_a(sizeof(*url),
		&host_buf, host_len + 1,
		&uri_buf, strlen(location) + 1,
		&auth_buf, auth_str ? strlen(auth_str) + 1 : 0);

	if (!url)
		return NULL;

	url->backend = backend;
	url->location = strcpy(uri_buf, location);
	if (host)
		url->host = strncpy(host_buf, host, host_len);

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

static const char *
uclient_split_host(const char *base, int *host_len)
{
	char *next, *location;

	next = strchr(base, '/');
	if (next) {
		location = next;
		*host_len = next - base;
	} else {
		location = "/";
		*host_len = strlen(base);
	}

	return location;
}

struct uclient_url __hidden *
uclient_get_url_location(struct uclient_url *url, const char *location)
{
	struct uclient_url *new_url;
	char *host_buf, *uri_buf, *auth_buf, *port_buf;
	int host_len = strlen(url->host) + 1;
	int auth_len = url->auth ? strlen(url->auth) + 1 : 0;
	int port_len = url->port ? strlen(url->port) + 1 : 0;
	int uri_len;

	if (strstr(location, "://"))
		return uclient_get_url(location, url->auth);

	if (location[0] == '/')
		uri_len = strlen(location) + 1;
	else
		uri_len = strlen(url->location) + strlen(location) + 2;

	new_url = calloc_a(sizeof(*url),
		&host_buf, host_len,
		&port_buf, port_len,
		&uri_buf, uri_len,
		&auth_buf, auth_len);

	if (!new_url)
		return NULL;

	new_url->backend = url->backend;
	new_url->prefix = url->prefix;
	new_url->host = strcpy(host_buf, url->host);
	if (url->port)
		new_url->port = strcpy(port_buf, url->port);
	if (url->auth)
		new_url->auth = strcpy(auth_buf, url->auth);

	new_url->location = uri_buf;
	if (location[0] == '/')
		strcpy(uri_buf, location);
	else {
		int len = strcspn(url->location, "?#");
		char *buf = uri_buf;

		memcpy(buf, url->location, len);
		if (buf[len - 1] != '/') {
			buf[len] = '/';
			len++;
		}

		buf += len;
		strcpy(buf, location);
	}

	return new_url;
}

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
	int host_len;
	unsigned int i;

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

	location = uclient_split_host(url_str, &host_len);
	url = __uclient_get_url(backend, url_str, host_len, location, auth_str);
	if (!url)
		return NULL;

	url->prefix = prefix - backend->prefix;
	return url;
}

static void uclient_connection_timeout(struct uloop_timeout *timeout)
{
	struct uclient *cl = container_of(timeout, struct uclient, connection_timeout);

	if (cl->backend->disconnect)
		cl->backend->disconnect(cl);

	uclient_backend_set_error(cl, UCLIENT_ERROR_TIMEDOUT);
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
	cl->timeout_msecs = UCLIENT_DEFAULT_TIMEOUT_MS;
	cl->connection_timeout.cb = uclient_connection_timeout;

	return cl;
}

int uclient_set_proxy_url(struct uclient *cl, const char *url_str, const char *auth_str)
{
	const struct uclient_backend *backend = cl->backend;
	struct uclient_url *url;
	int host_len;
	char *next, *host;

	if (!backend->update_proxy_url)
		return -1;

	next = strstr(url_str, "://");
	if (!next)
		return -1;

	host = next + 3;
	uclient_split_host(host, &host_len);

	url = __uclient_get_url(NULL, host, host_len, url_str, auth_str);
	if (!url)
		return -1;

	free(cl->proxy_url);
	cl->proxy_url = url;

	if (backend->update_proxy_url)
		backend->update_proxy_url(cl);

	return 0;
}

int uclient_set_url(struct uclient *cl, const char *url_str, const char *auth_str)
{
	const struct uclient_backend *backend = cl->backend;
	struct uclient_url *url = cl->url;

	url = uclient_get_url(url_str, auth_str);
	if (!url)
		return -1;

	if (url->backend != cl->backend) {
		free(url);
		return -1;
	}

	free(cl->proxy_url);
	cl->proxy_url = NULL;

	free(cl->url);
	cl->url = url;

	if (backend->update_url)
		backend->update_url(cl);

	return 0;
}

int uclient_set_timeout(struct uclient *cl, int msecs)
{
	if (msecs <= 0)
		return -EINVAL;

	cl->timeout_msecs = msecs;

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

int uclient_write(struct uclient *cl, const char *buf, int len)
{
	if (!cl->backend->write)
		return -1;

	return cl->backend->write(cl, buf, len);
}

int uclient_request(struct uclient *cl)
{
	int err;

	if (!cl->backend->request)
		return -1;

	err = cl->backend->request(cl);
	if (err)
		return err;

	uloop_timeout_set(&cl->connection_timeout, cl->timeout_msecs);

	return 0;
}

int uclient_read(struct uclient *cl, char *buf, int len)
{
	if (!cl->backend->read)
		return -1;

	return cl->backend->read(cl, buf, len);
}

void uclient_disconnect(struct uclient *cl)
{
	uloop_timeout_cancel(&cl->connection_timeout);

	if (!cl->backend->disconnect)
		return;

	cl->backend->disconnect(cl);
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

	uloop_timeout_cancel(&cl->connection_timeout);
	cl->error_code = code;
	uclient_backend_change_state(cl);
}

void __hidden uclient_backend_set_eof(struct uclient *cl)
{
	if (cl->eof || cl->error_code)
		return;

	uloop_timeout_cancel(&cl->connection_timeout);
	cl->eof = true;
	uclient_backend_change_state(cl);
}

void __hidden uclient_backend_reset_state(struct uclient *cl)
{
	cl->data_eof = false;
	cl->eof = false;
	cl->error_code = 0;
	uloop_timeout_cancel(&cl->timeout);
}

const char * uclient_strerror(unsigned err)
{
	switch (err) {
	case UCLIENT_ERROR_UNKNOWN:
		return "unknown error";
	case UCLIENT_ERROR_CONNECT:
		return "connect failed";
	case UCLIENT_ERROR_TIMEDOUT:
		return "timeout";
	case UCLIENT_ERROR_SSL_INVALID_CERT:
		return "ssl invalid cert";
	case UCLIENT_ERROR_SSL_CN_MISMATCH:
		return "ssl cn mismatch";
	case UCLIENT_ERROR_MISSING_SSL_CONTEXT:
		return "missing ssl context";
	default:
		return "invalid error code";
	}
}
