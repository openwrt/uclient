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

	int (*read)(struct uclient *cl, char *buf, unsigned int len);
	int (*write)(struct uclient *cl, char *buf, unsigned int len);
};

struct uclient_url {
	const struct uclient_backend *backend;
	int prefix;

	const char *host;
	const char *port;
	const char *location;

	const char *auth;
};

void uclient_backend_set_error(struct uclient *cl, int code);
void uclient_backend_set_eof(struct uclient *cl);
void uclient_backend_reset_state(struct uclient *cl);
struct uclient_url *uclient_get_url(const char *url_str, const char *auth_str);

#endif
