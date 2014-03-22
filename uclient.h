#ifndef __LIBUBOX_UCLIENT_H
#define __LIBUBOX_UCLIENT_H

#include <libubox/blob.h>
#include <libubox/ustream.h>
#include <libubox/ustream-ssl.h>

struct uclient_cb;
struct uclient_backend;

struct uclient {
	const struct uclient_backend *backend;
	const struct uclient_cb *cb;

	struct uclient_url *url;
	void *priv;

	bool eof;
	bool error;
	int status_code;
	struct blob_attr *meta;

	struct uloop_timeout timeout;
};

struct uclient_cb {
	void (*data_read)(struct uclient *cl);
	void (*data_sent)(struct uclient *cl);
	void (*data_eof)(struct uclient *cl);
	void (*header_done)(struct uclient *cl);
	void (*error)(struct uclient *cl);
};

struct uclient *uclient_new(const char *url, const struct uclient_cb *cb);
void uclient_free(struct uclient *cl);

int uclient_connect_url(struct uclient *cl, const char *url_str);

static inline int uclient_connect(struct uclient *cl)
{
	return uclient_connect_url(cl, NULL);
}


int uclient_read(struct uclient *cl, char *buf, int len);
int uclient_write(struct uclient *cl, char *buf, int len);
int uclient_request(struct uclient *cl);

/* HTTP */
extern const struct uclient_backend uclient_backend_http;

int uclient_http_set_header(struct uclient *cl, const char *name, const char *value);
int uclient_http_reset_headers(struct uclient *cl, const char *name, const char *value);
int uclient_http_set_request_type(struct uclient *cl, const char *type);

#endif
