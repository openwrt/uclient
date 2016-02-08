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

#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <getopt.h>
#include <fcntl.h>
#include <glob.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>

#include <libubox/blobmsg.h>

#include "progress.h"
#include "uclient.h"
#include "uclient-utils.h"

#ifdef __APPLE__
#define LIB_EXT "dylib"
#else
#define LIB_EXT "so"
#endif

static const char *user_agent = "uclient-fetch";
static const char *post_data;
static struct ustream_ssl_ctx *ssl_ctx;
static const struct ustream_ssl_ops *ssl_ops;
static int quiet = false;
static bool verify = true;
static bool proxy = true;
static bool default_certs = false;
static bool no_output;
static const char *output_file;
static int output_fd = -1;
static int error_ret;
static off_t out_offset;
static off_t out_bytes;
static off_t out_len;
static char *auth_str;
static char **urls;
static int n_urls;
static int timeout;
static bool resume, cur_resume;

static struct progress pmt;
static struct uloop_timeout pmt_timer;

static int init_request(struct uclient *cl);
static void request_done(struct uclient *cl);

static void pmt_update(struct uloop_timeout *t)
{
	progress_update(&pmt, out_offset, out_bytes, out_len);
	uloop_timeout_set(t, 1000);
}

static const char *
get_proxy_url(char *url)
{
	char prefix[16];
	char *sep;

	if (!proxy)
		return NULL;

	sep = strchr(url, ':');
	if (!sep)
		return NULL;

	if (sep - url > 5)
		return NULL;

	memcpy(prefix, url, sep - url);
	strcpy(prefix + (sep - url), "_proxy");
	return getenv(prefix);
}

static int open_output_file(const char *path, uint64_t resume_offset)
{
	char *filename = NULL;
	int flags;
	int ret;

	if (cur_resume)
		flags = O_RDWR;
	else
		flags = O_WRONLY | O_TRUNC;

	if (!cur_resume && !output_file)
		flags |= O_EXCL;

	flags |= O_CREAT;

	if (output_file) {
		if (!strcmp(output_file, "-")) {
			if (!quiet)
				fprintf(stderr, "Writing to stdout\n");

			ret = STDOUT_FILENO;
			goto done;
		}
	} else {
		filename = uclient_get_url_filename(path, "index.html");
		output_file = filename;
	}

	if (!quiet)
		fprintf(stderr, "Writing to '%s'\n", output_file);
	ret = open(output_file, flags, 0644);
	if (ret < 0)
		goto free;

	if (resume_offset &&
	    lseek(ret, resume_offset, SEEK_SET) < 0) {
		if (!quiet)
			fprintf(stderr, "Failed to seek %"PRIu64" bytes in output file\n", resume_offset);
		close(ret);
		ret = -1;
		goto free;
	}

	out_offset = resume_offset;
	out_bytes += resume_offset;
done:
	if (!quiet) {
		progress_init(&pmt, output_file);
		pmt_timer.cb = pmt_update;
		pmt_timer.cb(&pmt_timer);
	}

free:
	free(filename);
	return ret;
}

static void header_done_cb(struct uclient *cl)
{
	enum {
		H_RANGE,
		H_LEN,
		__H_MAX
	};
	static const struct blobmsg_policy policy[__H_MAX] = {
		[H_RANGE] = { .name = "content-range", .type = BLOBMSG_TYPE_STRING },
		[H_LEN] = { .name = "content-length", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__H_MAX];
	uint64_t resume_offset = 0, resume_end, resume_size;
	static int retries;

	if (retries < 10) {
		int ret = uclient_http_redirect(cl);
		if (ret < 0) {
			if (!quiet)
				fprintf(stderr, "Failed to redirect to %s on %s\n", cl->url->location, cl->url->host);
			error_ret = 8;
			request_done(cl);
			return;
		}
		if (ret > 0) {
			if (!quiet)
				fprintf(stderr, "Redirected to %s on %s\n", cl->url->location, cl->url->host);

			retries++;
			return;
		}
	}

	if (cl->status_code == 204 && cur_resume) {
		/* Resume attempt failed, try normal download */
		cur_resume = false;
		init_request(cl);
		return;
	}

	blobmsg_parse(policy, __H_MAX, tb, blob_data(cl->meta), blob_len(cl->meta));

	switch (cl->status_code) {
	case 416:
		if (!quiet)
			fprintf(stderr, "File download already fully retrieved; nothing to do.\n");
		request_done(cl);
		break;
	case 206:
		if (!cur_resume) {
			if (!quiet)
				fprintf(stderr, "Error: Partial content received, full content requested\n");
			error_ret = 8;
			request_done(cl);
			break;
		}

		if (!tb[H_RANGE]) {
			if (!quiet)
				fprintf(stderr, "Content-Range header is missing\n");
			error_ret = 8;
			break;
		}

		if (sscanf(blobmsg_get_string(tb[H_RANGE]),
			   "bytes %"PRIu64"-%"PRIu64"/%"PRIu64,
			   &resume_offset, &resume_end, &resume_size) != 3) {
			if (!quiet)
				fprintf(stderr, "Content-Range header is invalid\n");
			error_ret = 8;
			break;
		}
	case 204:
	case 200:
		if (no_output)
			break;

		if (tb[H_LEN])
			out_len = strtoul(blobmsg_get_string(tb[H_LEN]), NULL, 10);

		output_fd = open_output_file(cl->url->location, resume_offset);
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

	if (!no_output && output_fd < 0)
		return;

	while (1) {
		len = uclient_read(cl, buf, sizeof(buf));
		if (!len)
			return;

		out_bytes += len;
		if (!no_output)
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
	fprintf(stderr, "Connecting to %s:%d\n", addr, port);
}

static void check_resume_offset(struct uclient *cl)
{
	char range_str[64];
	struct stat st;
	char *file;
	int ret;

	file = uclient_get_url_filename(cl->url->location, "index.html");
	if (!file)
		return;

	ret = stat(file, &st);
	free(file);
	if (ret)
		return;

	if (!st.st_size)
		return;

	snprintf(range_str, sizeof(range_str), "bytes=%"PRIu64"-", (uint64_t) st.st_size);
	uclient_http_set_header(cl, "Range", range_str);
}

static int init_request(struct uclient *cl)
{
	int rc;

	out_offset = 0;
	out_bytes = 0;
	out_len = 0;
	uclient_http_set_ssl_ctx(cl, ssl_ops, ssl_ctx, verify);

	if (timeout)
		cl->timeout_msecs = timeout * 1000;

	rc = uclient_connect(cl);
	if (rc)
		return rc;

	msg_connecting(cl);

	rc = uclient_http_set_request_type(cl, post_data ? "POST" : "GET");
	if (rc)
		return rc;

	uclient_http_reset_headers(cl);
	uclient_http_set_header(cl, "User-Agent", user_agent);
	if (cur_resume)
		check_resume_offset(cl);

	if (post_data) {
		uclient_http_set_header(cl, "Content-Type", "application/x-www-form-urlencoded");
		uclient_write(cl, post_data, strlen(post_data));
	}

	rc = uclient_request(cl);
	if (rc)
		return rc;

	return 0;
}

static void request_done(struct uclient *cl)
{
	const char *proxy_url;

	if (n_urls) {
		proxy_url = get_proxy_url(*urls);
		if (proxy_url) {
			uclient_set_url(cl, proxy_url, NULL);
			uclient_set_proxy_url(cl, *urls, auth_str);
		} else {
			uclient_set_url(cl, *urls, auth_str);
		}
		n_urls--;
		cur_resume = resume;
		error_ret = init_request(cl);
		if (error_ret == 0)
			return;
	}

	if (output_fd >= 0 && !output_file) {
		close(output_fd);
		output_fd = -1;
	}
	uclient_disconnect(cl);
	uloop_end();
}


static void eof_cb(struct uclient *cl)
{
	if (!quiet) {
		pmt_update(&pmt_timer);
		uloop_timeout_cancel(&pmt_timer);
		fprintf(stderr, "\n");
	}

	if (!cl->data_eof) {
		if (!quiet)
			fprintf(stderr, "Connection reset prematurely\n");
		error_ret = 4;
	} else if (!quiet) {
		fprintf(stderr, "Download completed (%"PRIu64" bytes)\n", (uint64_t) out_bytes);
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
	case UCLIENT_ERROR_TIMEDOUT:
		type = "Connection timed out";
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
		"	-4				Use IPv4 only\n"
		"	-6				Use IPv6 only\n"
		"	-q				Turn off status messages\n"
		"	-O <file>			Redirect output to file (use \"-\" for stdout)\n"
		"	-P <dir>			Set directory for output files\n"
		"	--user=<user>			HTTP authentication username\n"
		"	--password=<password>		HTTP authentication password\n"
		"	--user-agent|-U <str>		Set HTTP user agent\n"
		"	--post-data=STRING		use the POST method; send STRING as the data\n"
		"	--spider|-s			Spider mode - only check file existence\n"
		"	--timeout=N|-T N		Set connect/request timeout to N seconds\n"
		"	--proxy=on|off|-Y on|off	Enable/disable env var configured proxy\n"
		"\n"
		"HTTPS options:\n"
		"	--ca-certificate=<cert>		Load CA certificates from file <cert>\n"
		"	--no-check-certificate		don't validate the server's certificate\n"
		"\n", progname);
	return 1;
}

static void init_ca_cert(void)
{
	glob_t gl;
	int i;

	glob("/etc/ssl/certs/*.crt", 0, NULL, &gl);
	for (i = 0; i < gl.gl_pathc; i++)
		ssl_ops->context_add_ca_crt_file(ssl_ctx, gl.gl_pathv[i]);
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
	L_USER_AGENT,
	L_POST_DATA,
	L_SPIDER,
	L_TIMEOUT,
	L_CONTINUE,
	L_PROXY,
	L_NO_PROXY,
};

static const struct option longopts[] = {
	[L_NO_CHECK_CERTIFICATE] = { "no-check-certificate", no_argument },
	[L_CA_CERTIFICATE] = { "ca-certificate", required_argument },
	[L_USER] = { "user", required_argument },
	[L_PASSWORD] = { "password", required_argument },
	[L_USER_AGENT] = { "user-agent", required_argument },
	[L_POST_DATA] = { "post-data", required_argument },
	[L_SPIDER] = { "spider", no_argument },
	[L_TIMEOUT] = { "timeout", required_argument },
	[L_CONTINUE] = { "continue", no_argument },
	[L_PROXY] = { "proxy", required_argument },
	[L_NO_PROXY] = { "no-proxy", no_argument },
	{}
};



int main(int argc, char **argv)
{
	const char *progname = argv[0];
	const char *proxy_url;
	char *username = NULL;
	char *password = NULL;
	struct uclient *cl;
	int longopt_idx = 0;
	bool has_cert = false;
	int i, ch;
	int rc;
	int af = -1;

	signal(SIGPIPE, SIG_IGN);
	init_ustream_ssl();

	while ((ch = getopt_long(argc, argv, "46cO:P:qsT:U:Y:", longopts, &longopt_idx)) != -1) {
		switch(ch) {
		case 0:
			switch (longopt_idx) {
			case L_NO_CHECK_CERTIFICATE:
				verify = false;
				break;
			case L_CA_CERTIFICATE:
				has_cert = true;
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
			case L_USER_AGENT:
				user_agent = optarg;
				break;
			case L_POST_DATA:
				post_data = optarg;
				break;
			case L_SPIDER:
				no_output = true;
				break;
			case L_TIMEOUT:
				timeout = atoi(optarg);
				break;
			case L_CONTINUE:
				resume = true;
				break;
			case L_PROXY:
				if (strcmp(optarg, "on") != 0)
					proxy = false;
				break;
			case L_NO_PROXY:
				proxy = false;
				break;
			default:
				return usage(progname);
			}
			break;
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 'c':
			resume = true;
			break;
		case 'U':
			user_agent = optarg;
			break;
		case 'O':
			output_file = optarg;
			break;
		case 'P':
			if (chdir(optarg)) {
				if (!quiet)
					perror("Change output directory");
				exit(1);
			}
			break;
		case 'q':
			quiet = true;
			break;
		case 's':
			no_output = true;
			break;
		case 'T':
			timeout = atoi(optarg);
			break;
		case 'Y':
			if (strcmp(optarg, "on") != 0)
				proxy = false;
			break;
		default:
			return usage(progname);
		}
	}

	argv += optind;
	argc -= optind;

	if (verify && !has_cert)
		default_certs = true;

	if (argc < 1)
		return usage(progname);

	if (!ssl_ctx) {
		for (i = 0; i < argc; i++) {
			if (!strncmp(argv[i], "https", 5))
				return no_ssl(progname);
		}
	}

	urls = argv + 1;
	n_urls = argc - 1;

	uloop_init();

	if (username) {
		if (password)
			asprintf(&auth_str, "%s:%s", username, password);
		else
			auth_str = username;
	}

	if (!quiet)
		fprintf(stderr, "Downloading '%s'\n", argv[0]);

	proxy_url = get_proxy_url(argv[0]);
	if (proxy_url) {
		cl = uclient_new(proxy_url, auth_str, &cb);
		if (cl)
		    uclient_set_proxy_url(cl, argv[0], NULL);
	} else {
		cl = uclient_new(argv[0], auth_str, &cb);
	}
	if (!cl) {
		fprintf(stderr, "Failed to allocate uclient context\n");
		return 1;
	}
	if (af >= 0)
	    uclient_http_set_address_family(cl, af);

	if (ssl_ctx && default_certs)
		init_ca_cert();

	cur_resume = resume;
	rc = init_request(cl);
	if (!rc) {
		/* no error received, we can enter main loop */
		uloop_run();
	} else {
		fprintf(stderr, "Failed to establish connection\n");
		error_ret = 4;
	}

	uloop_done();

	uclient_free(cl);

	if (output_fd >= 0 && output_fd != STDOUT_FILENO)
		close(output_fd);

	if (ssl_ctx)
		ssl_ops->context_free(ssl_ctx);

	return error_ret;
}
