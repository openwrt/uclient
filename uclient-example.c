#include <libubox/blobmsg.h>

#include "uclient.h"

static void example_header_done(struct uclient *cl)
{
	struct blob_attr *cur;
	int rem;

	fprintf(stderr, "Headers: \n");
	blobmsg_for_each_attr(cur, cl->meta, rem) {
		fprintf(stderr, "%s=%s\n", blobmsg_name(cur), (char *) blobmsg_data(cur));
	}

	fprintf(stderr, "Contents:\n");
}

static void example_read_data(struct uclient *cl)
{
	char buf[256];
	int len;

	while (1) {
		len = uclient_read(cl, buf, sizeof(buf));
		if (!len)
			return;

		fwrite(buf, len, 1, stderr);
	}
}

static void example_request_sm(struct uclient *cl)
{
	static int i = 0;

	switch (i++) {
	case 0:
		uclient_connect(cl);
		uclient_http_set_request_type(cl, "HEAD");
		uclient_request(cl);
		break;
	case 1:
		uclient_connect(cl);
		uclient_http_set_request_type(cl, "GET");
		uclient_request(cl);
		break;
	default:
		uclient_free(cl);
		uloop_end();
		break;
	};
}

static void example_eof(struct uclient *cl)
{
	example_request_sm(cl);
}

static const struct uclient_cb cb = {
	.header_done = example_header_done,
	.data_read = example_read_data,
	.data_eof = example_eof,
};

int main(int argc, char **argv)
{
	struct uclient *cl;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <URL>\n", argv[0]);
		return 1;
	}

	uloop_init();
	cl = uclient_new(argv[1], &cb);
	if (!cl) {
		fprintf(stderr, "Failed to allocate uclient context\n");
		return 1;
	}
	example_request_sm(cl);
	uloop_run();
	uloop_done();

	return 0;
}
