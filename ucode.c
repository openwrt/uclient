/*
 * uclient - ustream based protocol client library - ucode binding
 *
 * Copyright (C) 2024 Felix Fietkau <nbd@openwrt.org>
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
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <ucode/module.h>
#include "uclient.h"

static uc_resource_type_t *uc_uclient_type;
static uc_value_t *registry;
static uc_vm_t *uc_vm;

struct uc_uclient_priv {
	struct uclient_cb cb;
	const struct ustream_ssl_ops *ssl_ops;
	struct ustream_ssl_ctx *ssl_ctx;
	unsigned int idx;
};

static void uc_uclient_register(struct uc_uclient_priv *ucl, uc_value_t *res, uc_value_t *cb)
{
	size_t i, len;

	len = ucv_array_length(registry);
	for (i = 0; i < len; i += 2)
		if (!ucv_array_get(registry, i))
			break;

	ucv_array_set(registry, i, ucv_get(res));
	ucv_array_set(registry, i + 1, ucv_get(cb));
	ucl->idx = i;
}

static void free_uclient(void *ptr)
{
	struct uclient *cl = ptr;
	struct uc_uclient_priv *ucl;

	if (!cl)
		return;

	ucl = cl->priv;
	ucv_array_set(registry, ucl->idx, NULL);
	ucv_array_set(registry, ucl->idx + 1, NULL);
	uclient_free(cl);
	free(ucl);
}

static uc_value_t *
uc_uclient_free(uc_vm_t *vm, size_t nargs)
{
	struct uclient **cl = uc_fn_this("uclient");

	free_uclient(*cl);
	*cl = NULL;

	return NULL;
}

static uc_value_t *
uc_uclient_ssl_init(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	const struct ustream_ssl_ops *ops;
	struct ustream_ssl_ctx *ctx;
	struct uc_uclient_priv *ucl;
	uc_value_t *args = uc_fn_arg(0);
	bool verify = false;
	uc_value_t *cur;

	if (!cl)
		return NULL;

	ucl = cl->priv;
	if (ucl->ssl_ctx) {
		uclient_http_set_ssl_ctx(cl, NULL, NULL, false);
		ucl->ssl_ctx = NULL;
		ucl->ssl_ops = NULL;
	}

	ctx = uclient_new_ssl_context(&ops);
	if (!ctx)
		return NULL;

	ucl->ssl_ops = ops;
	ucl->ssl_ctx = ctx;

	if ((cur = ucv_object_get(args, "cert_file", NULL)) != NULL) {
		const char *str = ucv_string_get(cur);
		if (!str || ops->context_set_crt_file(ctx, str))
			goto err;
	}

	if ((cur = ucv_object_get(args, "key_file", NULL)) != NULL) {
		const char *str = ucv_string_get(cur);
		if (!str || ops->context_set_key_file(ctx, str))
			goto err;
	}

	if ((cur = ucv_object_get(args, "ca_files", NULL)) != NULL) {
		size_t len;

		if (ucv_type(cur) != UC_ARRAY)
			goto err;

		len = ucv_array_length(cur);
		for (size_t i = 0; i < len; i++) {
			uc_value_t *c = ucv_array_get(cur, i);
			const char *str;

			if (!c)
				continue;

			str = ucv_string_get(c);
			if (!str)
				goto err;

			ops->context_add_ca_crt_file(ctx, str);
		}

		verify = true;
	}

	if ((cur = ucv_object_get(args, "verify", NULL)) != NULL)
		verify = ucv_is_truish(cur);

	ops->context_set_require_validation(ctx, verify);
	uclient_http_set_ssl_ctx(cl, ops, ctx, verify);

	return ucv_boolean_new(true);

err:
	ops->context_free(ctx);
	return NULL;
}

static uc_value_t *
uc_uclient_set_timeout(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	uc_value_t *val = uc_fn_arg(0);

	if (!cl || ucv_type(val) != UC_INTEGER)
		return NULL;

	if (uclient_set_timeout(cl, ucv_int64_get(val)))
		return NULL;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uclient_set_url(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	uc_value_t *url = uc_fn_arg(0);
	uc_value_t *auth_str = uc_fn_arg(1);

	if (!cl || ucv_type(url) != UC_STRING ||
	    (auth_str && ucv_type(auth_str) != UC_STRING))
		return NULL;

	if (uclient_set_url(cl, ucv_string_get(url), ucv_string_get(auth_str)))
		return NULL;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uclient_set_proxy_url(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	uc_value_t *url = uc_fn_arg(0);
	uc_value_t *auth_str = uc_fn_arg(1);

	if (!cl || ucv_type(url) != UC_STRING ||
	    (auth_str && ucv_type(auth_str) != UC_STRING))
		return NULL;

	if (uclient_set_proxy_url(cl, ucv_string_get(url), ucv_string_get(auth_str)))
		return NULL;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uclient_get_headers(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	struct blob_attr *cur;
	uc_value_t *ret;
	size_t rem;

	if (!cl)
		return NULL;

	ret = ucv_object_new(uc_vm);
	blobmsg_for_each_attr(cur, cl->meta, rem) {
		uc_value_t *str;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		str = ucv_string_new(blobmsg_get_string(cur));
		ucv_object_add(ret, blobmsg_name(cur), ucv_get(str));
	}

	return ret;
}

static uc_value_t *
uc_uclient_connect(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");

	if (!cl || uclient_connect(cl))
		return NULL;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uclient_disconnect(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");

	if (!cl)
		return NULL;

	uclient_disconnect(cl);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uclient_request(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	uc_value_t *type = uc_fn_arg(0);
	uc_value_t *arg = uc_fn_arg(1);
	uc_value_t *cur;
	const char *type_str = ucv_string_get(type);

	if (!cl || !type_str)
		return NULL;

	if (uclient_http_set_request_type(cl, type_str))
		return NULL;

	uclient_http_reset_headers(cl);

	if ((cur = ucv_object_get(arg, "headers", NULL)) != NULL) {
		if (ucv_type(cur) != UC_OBJECT)
			return NULL;

		ucv_object_foreach(cur, key, val) {
			char *str;

			if (!val)
				continue;

			if (ucv_type(val) == UC_STRING) {
				uclient_http_set_header(cl, key, ucv_string_get(val));
				continue;
			}

			str = ucv_to_string(uc_vm, val);
			uclient_http_set_header(cl, key, str);
			free(str);
		}
	}

	if (uclient_request(cl))
		return NULL;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uclient_redirect(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");

	if (!cl || uclient_http_redirect(cl))
		return NULL;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uclient_status(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	char addr[INET6_ADDRSTRLEN];
	uc_value_t *ret;
	int port;

	if (!cl)
		return NULL;

	ret = ucv_object_new(vm);
	ucv_object_add(ret, "eof", ucv_boolean_new(cl->eof));
	ucv_object_add(ret, "data_eof", ucv_boolean_new(cl->data_eof));
	ucv_object_add(ret, "status", ucv_int64_new(cl->status_code));
	ucv_object_add(ret, "redirect", ucv_boolean_new(uclient_http_status_redirect(cl)));

	uclient_get_addr(addr, &port, &cl->local_addr);
	ucv_object_add(ret, "local_addr", ucv_get(ucv_string_new(addr)));
	ucv_object_add(ret, "local_port", ucv_get(ucv_int64_new(port)));

	uclient_get_addr(addr, &port, &cl->remote_addr);
	ucv_object_add(ret, "remote_addr", ucv_get(ucv_string_new(addr)));
	ucv_object_add(ret, "remote_port", ucv_get(ucv_int64_new(port)));

	return ret;
}

static uc_value_t *
uc_uclient_read(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");
	size_t len = ucv_int64_get(uc_fn_arg(0));
	uc_stringbuf_t *strbuf = NULL;
	static char buf[4096];
	int cur;

	if (!cl)
		return NULL;

	if (!len)
		len = sizeof(buf);

	while (len > 0) {
		cur = uclient_read(cl, buf, len);
		if (cur <= 0)
			break;

		if (!strbuf)
			strbuf = ucv_stringbuf_new();

		ucv_stringbuf_addstr(strbuf, buf, cur);
		len -= cur;
	}

	if (!strbuf)
		return NULL;

	return ucv_stringbuf_finish(strbuf);
}

static uc_value_t *
uc_uclient_write(uc_vm_t *vm, size_t nargs)
{
	struct uclient *cl = uc_fn_thisval("uclient");

	if (!cl)
		return NULL;

	for (size_t i = 0; i < nargs; i++)
		if (ucv_type(uc_fn_arg(i)) != UC_STRING)
			return NULL;

	for (size_t i = 0; i < nargs; i++) {
		uc_value_t *cur = uc_fn_arg(i);

		uclient_write(cl, ucv_string_get(cur), ucv_string_length(cur));
	}

	return ucv_boolean_new(true);
}

static void uc_uclient_cb(struct uclient *cl, const char *name, uc_value_t *arg)
{
	struct uc_uclient_priv *ucl = cl->priv;
	uc_value_t *cl_res, *cb;
	uc_vm_t *vm = uc_vm;

	cb = ucv_array_get(registry, ucl->idx + 1);
	if (!cb)
		return;

	cb = ucv_object_get(cb, name, NULL);
	if (!cb)
		return;

	if (!ucv_is_callable(cb))
		return;

	cl_res = ucv_array_get(registry, ucl->idx);
	uc_vm_stack_push(vm, ucv_get(cl_res));
	uc_vm_stack_push(vm, ucv_get(cb));
	if (arg)
		uc_vm_stack_push(vm, ucv_get(arg));

	if (uc_vm_call(vm, true, !!arg) != EXCEPTION_NONE) {
		if (vm->exhandler)
			vm->exhandler(vm, &vm->exception);
		return;
	}

	ucv_put(uc_vm_stack_pop(vm));
}

static void uc_cb_data_read(struct uclient *cl)
{
	uc_uclient_cb(cl, "data_read", NULL);
}

static void uc_cb_data_sent(struct uclient *cl)
{
	uc_uclient_cb(cl, "data_sent", NULL);
}

static void uc_cb_data_eof(struct uclient *cl)
{
	uc_uclient_cb(cl, "data_eof", NULL);
}

static void uc_cb_header_done(struct uclient *cl)
{
	uc_uclient_cb(cl, "header_done", NULL);
}

static void uc_cb_error(struct uclient *cl, int code)
{
	uc_uclient_cb(cl, "error", ucv_int64_new(code));
}

static uc_value_t *
uc_uclient_new(uc_vm_t *vm, size_t nargs)
{
	struct uc_uclient_priv *ucl;
	uc_value_t *url = uc_fn_arg(0);
	uc_value_t *auth_str = uc_fn_arg(1);
	uc_value_t *cb = uc_fn_arg(2);
	static bool _init_done;
	struct uclient *cl;
	uc_value_t *ret;

	if (!_init_done) {
		uloop_init();
		_init_done = true;
	}

	uc_vm = vm;

	if (ucv_type(url) != UC_STRING ||
	    (auth_str && ucv_type(auth_str) != UC_STRING) ||
	    ucv_type(cb) != UC_OBJECT)
		return NULL;

	ucl = calloc(1, sizeof(*ucl));
	if (ucv_object_get(cb, "data_read", NULL))
		ucl->cb.data_read = uc_cb_data_read;
	if (ucv_object_get(cb, "data_sent", NULL))
		ucl->cb.data_sent = uc_cb_data_sent;
	if (ucv_object_get(cb, "data_eof", NULL))
		ucl->cb.data_eof = uc_cb_data_eof;
	if (ucv_object_get(cb, "header_done", NULL))
		ucl->cb.header_done = uc_cb_header_done;
	if (ucv_object_get(cb, "error", NULL))
		ucl->cb.error = uc_cb_error;

	cl = uclient_new(ucv_string_get(url), ucv_string_get(auth_str), &ucl->cb);
	if (!cl) {
		free(ucl);
		return NULL;
	}

	cl->priv = ucl;
	ret = ucv_resource_new(uc_uclient_type, cl);
	uc_uclient_register(ucl, ret, cb);

	return ret;
}
static const uc_function_list_t uclient_fns[] = {
	{ "free", uc_uclient_free },
	{ "ssl_init", uc_uclient_ssl_init },
	{ "set_url", uc_uclient_set_url },
	{ "set_proxy_url", uc_uclient_set_proxy_url },
	{ "set_timeout", uc_uclient_set_timeout },
	{ "get_headers", uc_uclient_get_headers },

	{ "connect", uc_uclient_connect },
	{ "disconnect", uc_uclient_disconnect },
	{ "request", uc_uclient_request },
	{ "redirect", uc_uclient_redirect },
	{ "status", uc_uclient_status },

	{ "read", uc_uclient_read },
	{ "write", uc_uclient_write },
};

static const uc_function_list_t global_fns[] = {
	{ "new", uc_uclient_new },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_uclient_type = uc_type_declare(vm, "uclient", uclient_fns, free_uclient);
	registry = ucv_array_new(vm);
	uc_vm_registry_set(vm, "uclient.registry", registry);
	uc_function_list_register(scope, global_fns);
}
