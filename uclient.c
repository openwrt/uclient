#include <libubox/ustream-ssl.h>
#include "uclient.h"
#include "uclient-utils.h"
#include "uclient-backend.h"

static struct uclient_url *uclient_get_url(const char *url_str)
{
	static const struct uclient_backend *backends[] = {
		&uclient_backend_http,
	};

	const struct uclient_backend *backend;
	const char * const *prefix = NULL;
	struct uclient_url *url;
	const char *location;
	char *host_buf, *uri_buf, *next;
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
		&uri_buf, strlen(location) + 1);

	url->backend = backend;
	url->location = strcpy(uri_buf, location);

	url->host = strncpy(host_buf, url_str, host_len);

	next = strchr(host_buf, '@');
	if (next) {
		*next = 0;
		url->host = next + 1;

		if (uclient_urldecode(host_buf, host_buf, false) < 0)
			goto free;

		url->auth = host_buf;
	}

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
		if (next)
			url->port = next + 1;
	}

	return url;

free:
	free(url);
	return NULL;
}

struct uclient *uclient_new(const char *url_str, const struct uclient_cb *cb)
{
	struct uclient *cl;
	struct uclient_url *url;

	url = uclient_get_url(url_str);
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

int uclient_connect_url(struct uclient *cl, const char *url_str)
{
	struct uclient_url *url = cl->url;
	const struct uclient_backend *backend = cl->backend;

	if (url_str) {
		url = uclient_get_url(url_str);
		if (!url)
			return -1;

		if (url->backend != cl->backend)
			return -1;

		free(cl->url);
		cl->url = url;

		if (backend->update_url)
			backend->update_url(cl);
	}

	return backend->connect(cl);
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

	if (cl->error && cl->cb->error)
		cl->cb->error(cl);
	else if (cl->eof && cl->cb->data_eof)
		cl->cb->data_eof(cl);
}

static void uclient_backend_change_state(struct uclient *cl)
{
	cl->timeout.cb = __uclient_backend_change_state;
	uloop_timeout_set(&cl->timeout, 1);
}

void __hidden uclient_backend_set_error(struct uclient *cl)
{
	if (cl->error)
		return;

	cl->error = true;
	uclient_backend_change_state(cl);
}

void __hidden uclient_backend_set_eof(struct uclient *cl)
{
	if (cl->eof || cl->error)
		return;

	cl->eof = true;
	uclient_backend_change_state(cl);
}

void __hidden uclient_backend_reset_state(struct uclient *cl)
{
	cl->error = false;
	cl->eof = false;
	uloop_timeout_cancel(&cl->timeout);
}
