/* Instantiate a private key crypto key
 *
 * Copyright (C) 2013 SUSE Linux Products GmbH. All rights reserved.
 * Written by Chun-Yi Lee (jlee@suse.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKCS1: "fmt
#include <linux/module.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>

/*
 * Attempt to parse a data blob for a private key.
 */
static int pkcs1_private_key_preparse(struct key_preparsed_payload *prep)
{
	int ret;

	pr_info("pkcs1_private_key.c::pkcs1_private_key_preparse");

	ret = -EKEYREJECTED;

	/* TODO: Attempt to decode the PKCS1 private key blob */

	/* TODO: check the parser result */

	/* TODO: fingerprint need gnerate by hash private key data */

	/* TODO: Propose a description? */

	/* TODO: We're pinning the module by being linked against it */

	return ret;
}

static struct asymmetric_key_parser pkcs1_private_key_parser = {
	.owner	= THIS_MODULE,
	.name	= "pkcs1",
	.parse	= pkcs1_private_key_preparse,
};

/*
 * Module stuff
 */
static int __init pkcs1_private_key_init(void)
{
	return register_asymmetric_key_parser(&pkcs1_private_key_parser);
}

static void __exit pkcs1_private_key_exit(void)
{
	unregister_asymmetric_key_parser(&pkcs1_private_key_parser);
}

module_init(pkcs1_private_key_init);
module_exit(pkcs1_private_key_exit);
