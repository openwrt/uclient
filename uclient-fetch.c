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

#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <getopt.h>
#include <fcntl.h>

#include <libubox/blobmsg.h>

#include "uclient.h"
#include "uclient-utils.h"

#ifdef __APPLE__
#define LIB_EXT "dylib"
#else
#define LIB_EXT "so"
#endif

static struct ustream_ssl_ctx *ssl_ctx;
static const struct ustream_ssl_ops *ssl_ops;
static int quiet = false;
static bool verify = true;
static const char *output_file;
static int output_fd = -1;
static int error_ret;
static int out_bytes;
static char *username;
static char *password;
static char *auth_str;

static int open_output_file(const char *path, bool create)
{
	char *filename;
	int flags = O_WRONLY;
	int ret;

	if (create)
		flags |= O_CREAT | O_EXCL;

	if (output_file) {
		if (!strcmp(output_file, "-"))
			return STDOUT_FILENO;

		if (!quiet)
			fprintf(stderr, "Writing to stdout\n");

		unlink(output_file);
		return open(output_file, flags, 0644);
	}

	filename = uclient_get_url_filename(path, "index.html");
	if (!quiet)
		fprintf(stderr, "Writing to '%s'\n", filename);
	ret = open(filename, flags, 0644);
	free(filename);

	return ret;
}

static void request_done(struct uclient *cl)
{
	if (output_fd >= 0 && !output_file) {
		close(output_fd);
		output_fd = -1;
	}
	uclient_disconnect(cl);
	uloop_end();
}

static void header_done_cb(struct uclient *cl)
{
	static int retries;

	if (retries < 10 && uclient_http_redirect(cl)) {
		if (!quiet)
			fprintf(stderr, "Redirected to %s on %s\n", cl->url->location, cl->url->host);

		retries++;
		return;
	}

	retries = 0;
	switch (cl->status_code) {
	case 204:
	case 200:
		output_fd = open_output_file(cl->url->location, true);
		if (output_fd < 0) {
			if (!quiet)
				perror("Cannot open output file");
			error_ret = 3;
			request_done(cl);
		}
		break;

	default:
		if (!quiet)
			fprintf(stderr, "HTTP error %d\n", cl->status_code);
		request_done(cl);
		error_ret = 8;
		break;
	}
}

static void read_data_cb(struct uclient *cl)
{
	char buf[256];
	int len;

	if (output_fd < 0)
		return;

	while (1) {
		len = uclient_read(cl, buf, sizeof(buf));
		if (!len)
			return;

		out_bytes += len;
		write(output_fd, buf, len);
	}
}

static void msg_connecting(struct uclient *cl)
{
	char addr[INET6_ADDRSTRLEN];
	int port;

	if (quiet)
		return;

	uclient_get_addr(addr, &port, &cl->remote_addr);
	fprintf(stderr, "Connecting to %s %s:%d\n", cl->url->host, addr, port);
}

static void init_request(struct uclient *cl)
{
	out_bytes = 0;
	uclient_connect(cl);
	msg_connecting(cl);
	uclient_http_set_request_type(cl, "GET");
	uclient_request(cl);
}

static void eof_cb(struct uclient *cl)
{
	if (!cl->data_eof) {
		if (!quiet)
			fprintf(stderr, "Connection reset prematurely\n");
		error_ret = 4;
	} else if (!quiet) {
		fprintf(stderr, "Download completed (%d bytes)\n", out_bytes);
	}
	request_done(cl);
}

static void handle_uclient_error(struct uclient *cl, int code)
{
	const char *type = "Unknown error";
	bool ignore = false;

	switch(code) {
	case UCLIENT_ERROR_CONNECT:
		type = "Connection failed";
		error_ret = 4;
		break;
	case UCLIENT_ERROR_SSL_INVALID_CERT:
		type = "Invalid SSL certificate";
		ignore = !verify;
		error_ret = 5;
		break;
	case UCLIENT_ERROR_SSL_CN_MISMATCH:
		type = "Server hostname does not match SSL certificate";
		ignore = !verify;
		error_ret = 5;
		break;
	default:
		error_ret = 1;
		break;
	}

	if (!quiet)
		fprintf(stderr, "Connection error: %s%s\n", type, ignore ? " (ignored)" : "");

	if (ignore)
		error_ret = 0;
	else
		request_done(cl);
}

static const struct uclient_cb cb = {
	.header_done = header_done_cb,
	.data_read = read_data_cb,
	.data_eof = eof_cb,
	.error = handle_uclient_error,
};

static int usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s [options] <URL>\n"
		"Options:\n"
		"	-q:                             Turn off status messages\n"
		"	-O <file>:                      Redirect output to file (use \"-\" for stdout)\n"
		"\n"
		"HTTPS options:\n"
		"	--ca-certificate=<cert>:        Load CA certificates from file <cert>\n"
		"	--no-check-certificate:         don't validate the server's certificate\n"
		"\n", progname);
	return 1;
}


static void init_ustream_ssl(void)
{
	void *dlh;

	dlh = dlopen("libustream-ssl." LIB_EXT, RTLD_LAZY | RTLD_LOCAL);
	if (!dlh)
		return;

	ssl_ops = dlsym(dlh, "ustream_ssl_ops");
	if (!ssl_ops)
		return;

	ssl_ctx = ssl_ops->context_new(false);
}

static int no_ssl(const char *progname)
{
	fprintf(stderr, "%s: SSL support not available, please install ustream-ssl\n", progname);
	return 1;
}

enum {
	L_NO_CHECK_CERTIFICATE,
	L_CA_CERTIFICATE,
	L_USER,
	L_PASSWORD,
};

static const struct option longopts[] = {
	[L_NO_CHECK_CERTIFICATE] = { "no-check-certificate", no_argument },
	[L_CA_CERTIFICATE] = { "ca-certificate", required_argument },
	[L_USER] = { "user", required_argument },
	[L_PASSWORD] = { "password", required_argument },
	{}
};

int main(int argc, char **argv)
{
	const char *progname = argv[0];
	struct uclient *cl;
	int ch;
	int longopt_idx = 0;

	init_ustream_ssl();

	while ((ch = getopt_long(argc, argv, "qO:", longopts, &longopt_idx)) != -1) {
		switch(ch) {
		case 0:
			switch (longopt_idx) {
			case L_NO_CHECK_CERTIFICATE:
				verify = false;
				break;
			case L_CA_CERTIFICATE:
				if (ssl_ctx)
					ssl_ops->context_add_ca_crt_file(ssl_ctx, optarg);
				break;
			case L_USER:
				if (!strlen(optarg))
					break;
				username = strdup(optarg);
				memset(optarg, '*', strlen(optarg));
				break;
			case L_PASSWORD:
				if (!strlen(optarg))
					break;
				password = strdup(optarg);
				memset(optarg, '*', strlen(optarg));
				break;
			default:
				return usage(progname);
			}
			break;
		case 'O':
			output_file = optarg;
			break;
		case 'q':
			quiet = true;
			break;
		default:
			return usage(progname);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1)
		return usage(progname);

	if (!strncmp(argv[0], "https", 5) && !ssl_ctx)
		return no_ssl(progname);

	uloop_init();

	if (username) {
		if (password)
			asprintf(&auth_str, "%s:%s", username, password);
		else
			auth_str = username;
	}

	cl = uclient_new(argv[0], auth_str, &cb);
	if (!cl) {
		fprintf(stderr, "Failed to allocate uclient context\n");
		return 1;
	}

	if (ssl_ctx)
		uclient_http_set_ssl_ctx(cl, ssl_ops, ssl_ctx, verify);

	init_request(cl);
	uloop_run();
	uloop_done();

	uclient_free(cl);

	if (output_fd >= 0 && output_fd != STDOUT_FILENO)
		close(output_fd);

	if (ssl_ctx)
		ssl_ops->context_free(ssl_ctx);

	return error_ret;
}
