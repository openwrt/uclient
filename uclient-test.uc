#!/usr/bin/env ucode
'use strict';
import { basename, stdout } from "fs";
let uloop = require("uloop");
let uclient = require("uclient");

function fetch_data() {
	let data;
	while (length(data = uc.read()) > 0)
		print(data);
}

let url = shift(ARGV);
if (!url) {
	warn(`Usage: ${basename(sourcepath())} <url>\n`);
	exit(1);
}

uloop.init();
uc = uclient.new(url, null, {
	header_done: (cb) => {
		warn(sprintf("Headers: %.J\nStatus: %.J\n", uc.get_headers(), uc.status()));
	},
	data_read: fetch_data,
	data_eof: (cb) => {
		stdout.flush();
		uloop.end();
	},
	error: (cb, code) => {
		warn(`Error: ${code}\n`);
		uloop.end();
	}
});

if (!uc.ssl_init({ verify: false })) {
	warn(`Failed to initialize SSL\n`);
	exit(1);
}

if (!uc.connect()) {
	warn(`Failed to connect\n`);
	exit(1);
}

if (!uc.request("GET")) {
	warn(`Failed to send request\n`);
	exit(1);
}

uloop.run();
