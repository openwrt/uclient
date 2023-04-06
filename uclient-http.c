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
#include <sys/socket.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

#include <libubox/ustream.h>
#include <libubox/ustream-ssl.h>
#include <libubox/usock.h>
#include <libubox/blobmsg.h>

#include "uclient.h"
#include "uclient-utils.h"
#include "uclient-backend.h"

enum auth_type {
	AUTH_TYPE_UNKNOWN,
	AUTH_TYPE_NONE,
	AUTH_TYPE_BASIC,
	AUTH_TYPE_DIGEST,
};

enum request_type {
	REQ_DELETE,
	REQ_GET,
	REQ_HEAD,
	REQ_OPTIONS,
	REQ_POST,
	REQ_PUT,
	__REQ_MAX
};

enum http_state {
	HTTP_STATE_INIT,
	HTTP_STATE_HEADERS_SENT,
	HTTP_STATE_REQUEST_DONE,
	HTTP_STATE_RECV_HEADERS,
	HTTP_STATE_RECV_DATA,
	HTTP_STATE_ERROR,
};

// Must be sorted alphabetically
static const char * const request_types[__REQ_MAX] = {
	[REQ_DELETE] = "DELETE",
	[REQ_GET] = "GET",
	[REQ_HEAD] = "HEAD",
	[REQ_OPTIONS] = "OPTIONS",
	[REQ_POST] = "POST",
	[REQ_PUT] = "PUT",
};

struct uclient_http {
	struct uclient uc;

	const struct ustream_ssl_ops *ssl_ops;
	struct ustream_ssl_ctx *ssl_ctx;
	struct ustream *us;

	union {
		struct ustream_fd ufd;
		struct ustream_ssl ussl;
	};

	struct uloop_timeout disconnect_t;
	unsigned int seq;
	int fd;

	bool ssl_require_validation;
	bool ssl;
	bool eof;
	bool connection_close;
	bool disconnect;
	enum request_type req_type;
	enum http_state state;

	enum auth_type auth_type;
	char *auth_str;

	long read_chunked;
	long content_length;

	int usock_flags;

	uint32_t nc;

	struct blob_buf headers;
	struct blob_buf meta;
};

enum {
	PREFIX_HTTP,
	PREFIX_HTTPS,
	__PREFIX_MAX,
};

static const char * const uclient_http_prefix[] = {
	[PREFIX_HTTP] = "http://",
	[PREFIX_HTTPS] = "https://",
	[__PREFIX_MAX] = NULL
};

static int uclient_http_connect(struct uclient *cl);

static int uclient_do_connect(struct uclient_http *uh, const char *port)
{
	socklen_t sl;
	int fd;

	if (uh->uc.url->port)
		port = uh->uc.url->port;

	memset(&uh->uc.remote_addr, 0, sizeof(uh->uc.remote_addr));

	fd = usock_inet_timeout(USOCK_TCP | USOCK_NONBLOCK | uh->usock_flags,
				uh->uc.url->host, port, &uh->uc.remote_addr,
				uh->uc.timeout_msecs);
	if (fd < 0)
		return -1;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	uh->fd = fd;

	sl = sizeof(uh->uc.local_addr);
	memset(&uh->uc.local_addr, 0, sl);
	getsockname(fd, &uh->uc.local_addr.sa, &sl);

	return 0;
}

static void uclient_http_disconnect(struct uclient_http *uh)
{
	uloop_timeout_cancel(&uh->disconnect_t);
	if (!uh->us)
		return;

	if (uh->ssl)
		ustream_free(&uh->ussl.stream);
	else
		ustream_free(&uh->ufd.stream);
	if(uh->fd >= 0)
		close(uh->fd >= 0);
	uh->us = NULL;
}

static void uclient_http_free_url_state(struct uclient *cl)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	uh->auth_type = AUTH_TYPE_UNKNOWN;
	free(uh->auth_str);
	uh->auth_str = NULL;
	uclient_http_disconnect(uh);
}

static void uclient_http_error(struct uclient_http *uh, int code)
{
	uh->state = HTTP_STATE_ERROR;
	uh->us->eof = true;
	ustream_state_change(uh->us);
	uclient_backend_set_error(&uh->uc, code);
}

static void uclient_http_request_disconnect(struct uclient *cl)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	if (!uh->us)
		return;

	uh->eof = true;
	uh->disconnect = true;
	uloop_timeout_set(&uh->disconnect_t, 1);
}

static void uclient_notify_eof(struct uclient_http *uh)
{
	struct ustream *us = uh->us;

	if (uh->disconnect)
		return;

	if (!uh->eof) {
		if (!us->eof && !us->write_error)
			return;

		if (ustream_pending_data(us, false))
			return;
	}

	if ((uh->content_length < 0 && uh->read_chunked >= 0) ||
			uh->content_length == 0)
		uh->uc.data_eof = true;

	uclient_backend_set_eof(&uh->uc);

	if (uh->connection_close)
		uclient_http_request_disconnect(&uh->uc);
}

static void uclient_http_reset_state(struct uclient_http *uh)
{
	uh->seq++;
	uclient_backend_reset_state(&uh->uc);
	uh->read_chunked = -1;
	uh->content_length = -1;
	uh->eof = false;
	uh->disconnect = false;
	uh->connection_close = false;
	uh->state = HTTP_STATE_INIT;

	if (uh->auth_type == AUTH_TYPE_UNKNOWN && !uh->uc.url->auth)
		uh->auth_type = AUTH_TYPE_NONE;
}

static void uclient_http_init_request(struct uclient_http *uh)
{
	uh->seq++;
	uclient_http_reset_state(uh);
	blob_buf_init(&uh->meta, 0);
}

static enum auth_type
uclient_http_update_auth_type(struct uclient_http *uh)
{
	if (!uh->auth_str)
		return AUTH_TYPE_NONE;

	if (!strncasecmp(uh->auth_str, "basic", 5))
		return AUTH_TYPE_BASIC;

	if (!strncasecmp(uh->auth_str, "digest", 6))
		return AUTH_TYPE_DIGEST;

	return AUTH_TYPE_NONE;
}

static void uclient_http_process_headers(struct uclient_http *uh)
{
	enum {
		HTTP_HDR_TRANSFER_ENCODING,
		HTTP_HDR_CONNECTION,
		HTTP_HDR_CONTENT_LENGTH,
		HTTP_HDR_AUTH,
		__HTTP_HDR_MAX,
	};
	static const struct blobmsg_policy hdr_policy[__HTTP_HDR_MAX] = {
#define hdr(_name) { .name = _name, .type = BLOBMSG_TYPE_STRING }
		[HTTP_HDR_TRANSFER_ENCODING] = hdr("transfer-encoding"),
		[HTTP_HDR_CONNECTION] = hdr("connection"),
		[HTTP_HDR_CONTENT_LENGTH] = hdr("content-length"),
		[HTTP_HDR_AUTH] = hdr("www-authenticate"),
#undef hdr
	};
	struct blob_attr *tb[__HTTP_HDR_MAX];
	struct blob_attr *cur;

	blobmsg_parse(hdr_policy, __HTTP_HDR_MAX, tb, blob_data(uh->meta.head), blob_len(uh->meta.head));

	cur = tb[HTTP_HDR_TRANSFER_ENCODING];
	if (cur && strstr(blobmsg_data(cur), "chunked"))
		uh->read_chunked = 0;

	cur = tb[HTTP_HDR_CONNECTION];
	if (cur && strstr(blobmsg_data(cur), "close"))
		uh->connection_close = true;

	cur = tb[HTTP_HDR_CONTENT_LENGTH];
	if (cur)
		uh->content_length = strtoul(blobmsg_data(cur), NULL, 10);

	cur = tb[HTTP_HDR_AUTH];
	if (cur) {
		free(uh->auth_str);
		uh->auth_str = strdup(blobmsg_data(cur));
	}

	uh->auth_type = uclient_http_update_auth_type(uh);
}

static bool uclient_request_supports_body(enum request_type req_type)
{
	switch (req_type) {
	case REQ_GET:
	case REQ_HEAD:
	case REQ_OPTIONS:
		return false;
	default:
		return true;
	}
}

static int
uclient_http_add_auth_basic(struct uclient_http *uh)
{
	struct uclient_url *url = uh->uc.url;
	int auth_len = strlen(url->auth);
	char *auth_buf;

	if (auth_len > 512)
		return -EINVAL;

	auth_buf = alloca(base64_len(auth_len) + 1);
	if (!auth_buf)
		return -ENOMEM;

	base64_encode(url->auth, auth_len, auth_buf);
	ustream_printf(uh->us, "Authorization: Basic %s\r\n", auth_buf);

	return 0;
}

static char *digest_unquote_sep(char **str)
{
	char *cur = *str + 1;
	char *start = cur;
	char *out;

	if (**str != '"')
		return NULL;

	out = cur;
	while (1) {
		if (!*cur)
			return NULL;

		if (*cur == '"') {
			cur++;
			break;
		}

		if (*cur == '\\')
			cur++;

		*(out++) = *(cur++);
	}

	if (*cur == ',')
		cur++;

	*out = 0;
	*str = cur;

	return start;
}

static char *digest_sep(char **str)
{
	char *cur, *next;

	cur = *str;
	next = strchr(*str, ',');
	if (next) {
	    *str = next + 1;
	    *next = 0;
	} else {
	    *str += strlen(*str);
	}

	return cur;
}

static bool strmatch(char **str, const char *prefix)
{
	int len = strlen(prefix);

	if (strncmp(*str, prefix, len) != 0 || (*str)[len] != '=')
		return false;

	*str += len + 1;
	return true;
}

static void
get_cnonce(char *dest)
{
	uint32_t val = 0;
	FILE *f;
	size_t n;

	f = fopen("/dev/urandom", "r");
	if (f) {
		n = fread(&val, sizeof(val), 1, f);
		fclose(f);
		if (n != 1)
			return;
	}

	bin_to_hex(dest, &val, sizeof(val));
}

static void add_field(char **buf, int *ofs, int *len, const char *name, const char *val)
{
	int available = *len - *ofs;
	int required;
	const char *next;
	char *cur;

	if (*len && !*buf)
		return;

	required = strlen(name) + 4 + strlen(val) * 2;
	if (required > available)
		*len += required - available + 64;

	*buf = realloc(*buf, *len);
	if (!*buf)
		return;

	cur = *buf + *ofs;
	cur += sprintf(cur, ", %s=\"", name);

	while ((next = strchr(val, '"'))) {
		if (next > val) {
			memcpy(cur, val, next - val);
			cur += next - val;
		}

		cur += sprintf(cur, "\\\"");
		val = next + 1;
	}

	cur += sprintf(cur, "%s\"", val);
	*ofs = cur - *buf;
}

static int
uclient_http_add_auth_digest(struct uclient_http *uh)
{
	struct uclient_url *url = uh->uc.url;
	const char *realm = NULL, *opaque = NULL;
	const char *user, *password;
	char *buf, *next;
	int len, ofs;
	int err = 0;

	char cnonce_str[9];
	char nc_str[9];
	char ahash[33];
	char hash[33];

	struct http_digest_data data = {
		.nc = nc_str,
		.cnonce = cnonce_str,
		.auth_hash = ahash,
	};

	len = strlen(uh->auth_str) + 1;
	if (len > 512) {
		err = -EINVAL;
		goto fail;
	}

	buf = alloca(len);
	if (!buf) {
		err = -ENOMEM;
		goto fail;
	}

	strcpy(buf, uh->auth_str);

	/* skip auth type */
	strsep(&buf, " ");

	next = buf;
	while (*next) {
		const char **dest = NULL;
		const char *tmp;

		while (*next && isspace(*next))
			next++;

		if (strmatch(&next, "realm"))
			dest = &realm;
		else if (strmatch(&next, "qop"))
			dest = &data.qop;
		else if (strmatch(&next, "nonce"))
			dest = &data.nonce;
		else if (strmatch(&next, "opaque"))
			dest = &opaque;
		else if (strmatch(&next, "stale") ||
			 strmatch(&next, "algorithm") ||
			 strmatch(&next, "auth-param")) {
			digest_sep(&next);
			continue;
		} else if (strmatch(&next, "domain") ||
			 strmatch(&next, "qop-options"))
			dest = &tmp;
		else {
			digest_sep(&next);
			continue;
		}

		*dest = digest_unquote_sep(&next);
	}

	if (!realm || !data.qop || !data.nonce) {
		err = -EINVAL;
		goto fail;
	}

	sprintf(nc_str, "%08x", uh->nc++);
	get_cnonce(cnonce_str);

	data.qop = "auth";
	data.uri = url->location;
	data.method = request_types[uh->req_type];

	password = strchr(url->auth, ':');
	if (password) {
		char *user_buf;

		len = password - url->auth;
		if (len > 256) {
			err = -EINVAL;
			goto fail;
		}

		user_buf = alloca(len + 1);
		if (!user_buf) {
			err = -ENOMEM;
			goto fail;
		}

		strncpy(user_buf, url->auth, len);
		user_buf[len] = 0;
		user = user_buf;
		password++;
	} else {
		user = url->auth;
		password = "";
	}

	http_digest_calculate_auth_hash(ahash, user, realm, password);
	http_digest_calculate_response(hash, &data);

	buf = NULL;
	len = 0;
	ofs = 0;

	add_field(&buf, &ofs, &len, "username", user);
	add_field(&buf, &ofs, &len, "realm", realm);
	add_field(&buf, &ofs, &len, "nonce", data.nonce);
	add_field(&buf, &ofs, &len, "uri", data.uri);
	add_field(&buf, &ofs, &len, "cnonce", data.cnonce);
	add_field(&buf, &ofs, &len, "response", hash);
	if (opaque)
		add_field(&buf, &ofs, &len, "opaque", opaque);

	ustream_printf(uh->us, "Authorization: Digest nc=%s, qop=%s%s\r\n", data.nc, data.qop, buf);

	free(buf);

	return 0;

fail:
	return err;
}

static int
uclient_http_add_auth_header(struct uclient_http *uh)
{
	if (!uh->uc.url->auth)
		return 0;

	switch (uh->auth_type) {
	case AUTH_TYPE_UNKNOWN:
	case AUTH_TYPE_NONE:
		break;
	case AUTH_TYPE_BASIC:
		return uclient_http_add_auth_basic(uh);
	case AUTH_TYPE_DIGEST:
		return uclient_http_add_auth_digest(uh);
	}

	return 0;
}

static int
uclient_http_send_headers(struct uclient_http *uh)
{
	struct uclient_url *url = uh->uc.url;
	struct blob_attr *cur;
	enum request_type req_type = uh->req_type;
	bool literal_ipv6;
	int err;
	size_t rem;

	if (uh->state >= HTTP_STATE_HEADERS_SENT)
		return 0;

	if (uh->uc.proxy_url)
		url = uh->uc.proxy_url;

	literal_ipv6 = strchr(url->host, ':');

	ustream_printf(uh->us,
		"%s %s HTTP/1.1\r\n"
		"Host: %s%s%s%s%s\r\n",
		request_types[req_type], url->location,
		literal_ipv6 ? "[" : "",
		url->host,
		literal_ipv6 ? "]" : "",
		url->port ? ":" : "",
		url->port ? url->port : "");

	blobmsg_for_each_attr(cur, uh->headers.head, rem)
		ustream_printf(uh->us, "%s: %s\r\n", blobmsg_name(cur), (char *) blobmsg_data(cur));

	if (uclient_request_supports_body(uh->req_type))
		ustream_printf(uh->us, "Transfer-Encoding: chunked\r\n");

	err = uclient_http_add_auth_header(uh);
	if (err)
		return err;

	ustream_printf(uh->us, "\r\n");

	uh->state = HTTP_STATE_HEADERS_SENT;

	return 0;
}

static void uclient_http_headers_complete(struct uclient_http *uh)
{
	enum auth_type auth_type = uh->auth_type;
	int seq = uh->uc.seq;

	uh->state = HTTP_STATE_RECV_DATA;
	uh->uc.meta = uh->meta.head;
	uclient_http_process_headers(uh);

	if (auth_type == AUTH_TYPE_UNKNOWN && uh->uc.status_code == 401 &&
	    (uh->req_type == REQ_HEAD || uh->req_type == REQ_GET)) {
		uclient_http_connect(&uh->uc);
		uclient_http_send_headers(uh);
		uh->state = HTTP_STATE_REQUEST_DONE;
		return;
	}

	if (uh->uc.cb->header_done)
		uh->uc.cb->header_done(&uh->uc);

	if (uh->eof || seq != uh->uc.seq)
		return;

	if (uh->req_type == REQ_HEAD || uh->uc.status_code == 204 ||
			uh->content_length == 0) {
		uh->eof = true;
		uclient_notify_eof(uh);
	}
}

static void uclient_parse_http_line(struct uclient_http *uh, char *data)
{
	char *name;
	char *sep;

	if (uh->state == HTTP_STATE_REQUEST_DONE) {
		char *code;

		if (!strlen(data))
			return;

		/* HTTP/1.1 */
		strsep(&data, " ");

		code = strsep(&data, " ");
		if (!code)
			goto error;

		uh->uc.status_code = strtoul(code, &sep, 10);
		if (sep && *sep)
			goto error;

		uh->state = HTTP_STATE_RECV_HEADERS;
		return;
	}

	if (!*data) {
		uclient_http_headers_complete(uh);
		return;
	}

	sep = strchr(data, ':');
	if (!sep)
		return;

	*(sep++) = 0;

	for (name = data; *name; name++)
		*name = tolower(*name);

	name = data;
	while (isspace(*sep))
		sep++;

	blobmsg_add_string(&uh->meta, name, sep);
	return;

error:
	uh->uc.status_code = 400;
	uh->eof = true;
	uclient_notify_eof(uh);
}

static void __uclient_notify_read(struct uclient_http *uh)
{
	struct uclient *uc = &uh->uc;
	unsigned int seq = uh->seq;
	char *data;
	int len;

	if (uh->state < HTTP_STATE_REQUEST_DONE || uh->state == HTTP_STATE_ERROR)
		return;

	data = ustream_get_read_buf(uh->us, &len);
	if (!data || !len)
		return;

	if (uh->state < HTTP_STATE_RECV_DATA) {
		char *sep, *next;
		int cur_len;

		do {
			sep = strchr(data, '\n');
			if (!sep)
				break;

			next = sep + 1;
			if (sep > data && sep[-1] == '\r')
				sep--;

			/* Check for multi-line HTTP headers */
			if (sep > data) {
				if (!*next)
					return;

				if (isspace(*next) && *next != '\r' && *next != '\n') {
					sep[0] = ' ';
					if (sep + 1 < next)
						sep[1] = ' ';
					continue;
				}
			}

			*sep = 0;
			cur_len = next - data;
			uclient_parse_http_line(uh, data);
			if (seq != uh->seq)
				return;

			ustream_consume(uh->us, cur_len);
			len -= cur_len;

			if (uh->eof)
				return;

			data = ustream_get_read_buf(uh->us, &len);
		} while (data && uh->state < HTTP_STATE_RECV_DATA);

		if (!len)
			return;
	}

	if (uh->eof)
		return;

	if (uh->state == HTTP_STATE_RECV_DATA) {
		/* Now it's uclient user turn to read some data */
		uloop_timeout_cancel(&uc->connection_timeout);
		uclient_backend_read_notify(uc);
	}
}

static void __uclient_notify_write(struct uclient_http *uh)
{
	struct uclient *uc = &uh->uc;

	if (uc->cb->data_sent)
		uc->cb->data_sent(uc);
}

static void uclient_notify_read(struct ustream *us, int bytes)
{
	struct uclient_http *uh = container_of(us, struct uclient_http, ufd.stream);

	__uclient_notify_read(uh);
}

static void uclient_notify_write(struct ustream *us, int bytes)
{
	struct uclient_http *uh = container_of(us, struct uclient_http, ufd.stream);

	__uclient_notify_write(uh);
}

static void uclient_notify_state(struct ustream *us)
{
	struct uclient_http *uh = container_of(us, struct uclient_http, ufd.stream);

	if (uh->ufd.stream.write_error) {
		uclient_http_error(uh, UCLIENT_ERROR_CONNECT);
		return;
	}
	uclient_notify_eof(uh);
}

static int uclient_setup_http(struct uclient_http *uh)
{
	struct ustream *us = &uh->ufd.stream;
	int ret;

	memset(&uh->ufd, 0, sizeof(uh->ufd));
	uh->us = us;
	uh->ssl = false;

	us->string_data = true;
	us->notify_state = uclient_notify_state;
	us->notify_read = uclient_notify_read;
	us->notify_write = uclient_notify_write;

	ret = uclient_do_connect(uh, "80");
	if (ret)
		return UCLIENT_ERROR_CONNECT;

	ustream_fd_init(&uh->ufd, uh->fd);

	return 0;
}

static void uclient_ssl_notify_read(struct ustream *us, int bytes)
{
	struct uclient_http *uh = container_of(us, struct uclient_http, ussl.stream);

	__uclient_notify_read(uh);
}

static void uclient_ssl_notify_write(struct ustream *us, int bytes)
{
	struct uclient_http *uh = container_of(us, struct uclient_http, ussl.stream);

	__uclient_notify_write(uh);
}

static void uclient_ssl_notify_state(struct ustream *us)
{
	struct uclient_http *uh = container_of(us, struct uclient_http, ussl.stream);

	uclient_notify_eof(uh);
}

static void uclient_ssl_notify_error(struct ustream_ssl *ssl, int error, const char *str)
{
	struct uclient_http *uh = container_of(ssl, struct uclient_http, ussl);
	struct uclient *uc = &uh->uc;

	if (uc->cb->log_msg)
		uc->cb->log_msg(uc, UCLIENT_LOG_SSL_ERROR, str);
	uclient_http_error(uh, UCLIENT_ERROR_CONNECT);
}

static void uclient_ssl_notify_verify_error(struct ustream_ssl *ssl, int error, const char *str)
{
	struct uclient_http *uh = container_of(ssl, struct uclient_http, ussl);
	struct uclient *uc = &uh->uc;

	if (!uh->ssl_require_validation)
		return;

	if (uc->cb->log_msg)
		uc->cb->log_msg(uc, UCLIENT_LOG_SSL_VERIFY_ERROR, str);
	uclient_http_error(uh, UCLIENT_ERROR_SSL_INVALID_CERT);
}

static void uclient_ssl_notify_connected(struct ustream_ssl *ssl)
{
	struct uclient_http *uh = container_of(ssl, struct uclient_http, ussl);

	if (!uh->ssl_require_validation)
		return;

	if (!uh->ussl.valid_cn)
		uclient_http_error(uh, UCLIENT_ERROR_SSL_CN_MISMATCH);
}

static int uclient_setup_https(struct uclient_http *uh)
{
	struct ustream *us = &uh->ussl.stream;
	int ret;

	memset(&uh->ussl, 0, sizeof(uh->ussl));
	uh->ssl = true;
	uh->us = us;

	if (!uh->ssl_ctx)
		return UCLIENT_ERROR_MISSING_SSL_CONTEXT;

	ret = uclient_do_connect(uh, "443");
	if (ret)
		return UCLIENT_ERROR_CONNECT;

	us->string_data = true;
	us->notify_state = uclient_ssl_notify_state;
	us->notify_read = uclient_ssl_notify_read;
	us->notify_write = uclient_ssl_notify_write;
	uh->ussl.notify_error = uclient_ssl_notify_error;
	uh->ussl.notify_verify_error = uclient_ssl_notify_verify_error;
	uh->ussl.notify_connected = uclient_ssl_notify_connected;
	uh->ussl.server_name = uh->uc.url->host;
	uh->ssl_ops->init_fd(&uh->ussl, uh->fd, uh->ssl_ctx, false);
	uh->ssl_ops->set_peer_cn(&uh->ussl, uh->uc.url->host);

	return 0;
}

static int uclient_http_connect(struct uclient *cl)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);
	int ret;

	if (!cl->eof || uh->disconnect || uh->connection_close)
		uclient_http_disconnect(uh);

	uclient_http_init_request(uh);

	if (uh->us)
		return 0;

	uh->ssl = cl->url->prefix == PREFIX_HTTPS;

	if (uh->ssl)
		ret = uclient_setup_https(uh);
	else
		ret = uclient_setup_http(uh);

	return ret;
}

static void uclient_http_disconnect_cb(struct uloop_timeout *timeout)
{
	struct uclient_http *uh = container_of(timeout, struct uclient_http, disconnect_t);

	uclient_http_disconnect(uh);
}

static struct uclient *uclient_http_alloc(void)
{
	struct uclient_http *uh;

	uh = calloc_a(sizeof(*uh));
	if (!uh)
		return NULL;

	uh->disconnect_t.cb = uclient_http_disconnect_cb;
	blob_buf_init(&uh->headers, 0);

	return &uh->uc;
}

static void uclient_http_free_ssl_ctx(struct uclient_http *uh)
{
	uh->ssl_ops = NULL;
	uh->ssl_ctx = NULL;
}

static void uclient_http_free(struct uclient *cl)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	uclient_http_free_url_state(cl);
	uclient_http_free_ssl_ctx(uh);
	blob_buf_free(&uh->headers);
	blob_buf_free(&uh->meta);
	free(uh);
}

int
uclient_http_set_request_type(struct uclient *cl, const char *type)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);
	unsigned int i;

	if (cl->backend != &uclient_backend_http)
		return -1;

	if (uh->state > HTTP_STATE_INIT)
		return -1;

	for (i = 0; i < ARRAY_SIZE(request_types); i++) {
		int c = strcmp(request_types[i], type);
		if (c < 0) {
			continue;
		} else if (c == 0) {
			uh->req_type = i;
			return 0;
		} else {
			return -1;
		}
	}

	return -1;
}

int
uclient_http_reset_headers(struct uclient *cl)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	blob_buf_init(&uh->headers, 0);

	return 0;
}

int
uclient_http_set_header(struct uclient *cl, const char *name, const char *value)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	if (cl->backend != &uclient_backend_http)
		return -1;

	if (uh->state > HTTP_STATE_INIT)
		return -1;

	blobmsg_add_string(&uh->headers, name, value);
	return 0;
}

static int
uclient_http_send_data(struct uclient *cl, const char *buf, unsigned int len)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);
	int err;

	if (uh->state >= HTTP_STATE_REQUEST_DONE)
		return -1;

	err = uclient_http_send_headers(uh);
	if (err)
		return err;

	if (len > 0) {
		ustream_printf(uh->us, "%X\r\n", len);
		ustream_write(uh->us, buf, len, false);
		ustream_printf(uh->us, "\r\n");
	}

	return len;
}

static int
uclient_http_request_done(struct uclient *cl)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);
	int err;

	if (uh->state >= HTTP_STATE_REQUEST_DONE)
		return -1;

	err = uclient_http_send_headers(uh);
	if (err)
		return err;

	if (uclient_request_supports_body(uh->req_type))
		ustream_printf(uh->us, "0\r\n\r\n");
	uh->state = HTTP_STATE_REQUEST_DONE;

	return 0;
}

static int
uclient_http_read(struct uclient *cl, char *buf, unsigned int len)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);
	int read_len = 0;
	char *data, *data_end;

	if (uh->state < HTTP_STATE_RECV_DATA || !uh->us)
		return 0;

	data = ustream_get_read_buf(uh->us, &read_len);
	if (!data || !read_len) {
		ustream_poll(uh->us);
		data = ustream_get_read_buf(uh->us, &read_len);
		if (!data || !read_len)
			return 0;
	}

	data_end = data + read_len;
	read_len = 0;

	if (uh->read_chunked == 0) {
		char *sep;

		if (data[0] == '\r' && data[1] == '\n') {
			data += 2;
			read_len += 2;
		}

		sep = strstr(data, "\r\n");
		if (!sep)
			return 0;

		*sep = 0;
		uh->read_chunked = strtoul(data, NULL, 16);

		read_len += sep + 2 - data;
		data = sep + 2;

		if (!uh->read_chunked) {
			uh->eof = true;
			uh->uc.data_eof = true;
		}
	}

	unsigned int diff = data_end - data;
	if (len > diff)
		len = diff;

	if (uh->read_chunked >= 0) {
		if (len > (unsigned long) uh->read_chunked)
			len = uh->read_chunked;

		uh->read_chunked -= len;
	} else if (uh->content_length >= 0) {
		if (len > (unsigned long) uh->content_length)
			len = uh->content_length;

		uh->content_length -= len;
		if (!uh->content_length) {
			uh->eof = true;
			uh->uc.data_eof = true;
		}
	}

	if (len > 0) {
		read_len += len;
		memcpy(buf, data, len);
	}

	if (read_len > 0)
		ustream_consume(uh->us, read_len);

	uclient_notify_eof(uh);

	/* Now that we consumed something and if this isn't EOF, start timer again */
	if (!uh->uc.eof && !cl->connection_timeout.pending)
		uloop_timeout_set(&cl->connection_timeout, cl->timeout_msecs);

	return len;
}

int uclient_http_redirect(struct uclient *cl)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);
	struct blobmsg_policy location = {
		.name = "location",
		.type = BLOBMSG_TYPE_STRING,
	};
	struct uclient_url *url = cl->url;
	struct blob_attr *tb;

	if (cl->backend != &uclient_backend_http)
		return false;

	if (!uclient_http_status_redirect(cl))
		return false;

	blobmsg_parse(&location, 1, &tb, blob_data(uh->meta.head), blob_len(uh->meta.head));
	if (!tb)
		return false;

	url = uclient_get_url_location(url, blobmsg_data(tb));
	if (!url)
		return false;

	if (cl->proxy_url) {
		free(cl->proxy_url);
		cl->proxy_url = url;
	}
	else {
		free(cl->url);
		cl->url = url;
	}

	if (uclient_http_connect(cl))
		return -1;

	uclient_http_request_done(cl);

	return true;
}

int uclient_http_set_ssl_ctx(struct uclient *cl, const struct ustream_ssl_ops *ops,
			     struct ustream_ssl_ctx *ctx, bool require_validation)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	if (cl->backend != &uclient_backend_http)
		return -1;

	uclient_http_free_url_state(cl);

	uclient_http_free_ssl_ctx(uh);
	uh->ssl_ops = ops;
	uh->ssl_ctx = ctx;
	uh->ssl_require_validation = !!ctx && require_validation;

	return 0;
}

int uclient_http_set_address_family(struct uclient *cl, int af)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	if (cl->backend != &uclient_backend_http)
		return -1;

	switch (af) {
	case AF_INET:
		uh->usock_flags = USOCK_IPV4ONLY;
		break;
	case AF_INET6:
		uh->usock_flags = USOCK_IPV6ONLY;
		break;
	default:
		uh->usock_flags = 0;
		break;
	}

	return 0;
}

static int
uclient_http_pending_bytes(struct uclient *cl, bool write)
{
	struct uclient_http *uh = container_of(cl, struct uclient_http, uc);

	return ustream_pending_data(uh->us, write);
}

const struct uclient_backend uclient_backend_http = {
	.prefix = uclient_http_prefix,

	.alloc = uclient_http_alloc,
	.free = uclient_http_free,
	.connect = uclient_http_connect,
	.disconnect = uclient_http_request_disconnect,
	.update_url = uclient_http_free_url_state,
	.update_proxy_url = uclient_http_free_url_state,

	.read = uclient_http_read,
	.write = uclient_http_send_data,
	.request = uclient_http_request_done,
	.pending_bytes = uclient_http_pending_bytes,
};
