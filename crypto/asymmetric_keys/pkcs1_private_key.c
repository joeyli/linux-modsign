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
#include <linux/slab.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include "public_key.h"
#include "pkcs1_privatekey-asn1.h"

struct pkcs1_privatekey_parse_context {
	struct public_key *pub;		/* Public key details */
	unsigned char nr_mpi;		/* Number of MPIs stored */
};

/*
 * Attempt to parse a data blob for a private key.
 */
static int pkcs1_private_key_preparse(struct key_preparsed_payload *prep)
{
	struct pkcs1_privatekey_parse_context *ctx;
	const void *data = prep->data;
	size_t datalen = prep->datalen;
	int ret;

	pr_info("pkcs1_private_key_preparse start\n");

	ret = -ENOMEM;
	ctx = kzalloc(sizeof(struct pkcs1_privatekey_parse_context),
			GFP_KERNEL);
	if (!ctx)
		goto error_no_ctx;
	ctx->pub = kzalloc(sizeof(struct public_key), GFP_KERNEL);
	if (!ctx->pub)
		goto error_no_pub;

	/* Attempt to decode the PKCS1 private key blob */
	ret = asn1_ber_decoder(&pkcs1_privatekey_decoder, ctx, data, datalen);
	if (ret < 0)
		goto error_decode;

	/*
	 * TODO: check the parser result
	 * private key should match with a public key in keyring?
	 */

	ctx->pub->algo = &RSA_public_key_algorithm;
	ctx->pub->id_type = PKEY_ID_RSA_PRIVATE;

	/* TODO: fingerprint need gnerate by hash private key data */

	/* TODO: Propose a description? */

	/* TODO: We're pinning the module by being linked against it */
	__module_get(public_key_subtype.owner);
	prep->type_data[0] = &public_key_subtype;
	prep->payload = ctx->pub;
	/* prep->quotalen = 100;?? */

	/* TODO: set permission to view only? */

	pr_info("pkcs1_private_key_preparse done\n");

	return ret;

error_decode:
	public_key_destroy(ctx->pub);
error_no_pub:
	kfree(ctx);
error_no_ctx:
	return ret;
}

int rsa_privatekey_extract_mpi(void *context, size_t hdrlen,
				unsigned char tag,
				const void *value, size_t vlen)
{
	struct pkcs1_privatekey_parse_context *ctx = context;
	MPI mpi;

	if (ctx->nr_mpi >= ARRAY_SIZE(ctx->pub->mpi)) {
		/* does not grab exponent1, exponent2 and coefficient */
		if (ctx->nr_mpi > 8) {
			pr_err("Too many public key MPIs in pkcs1 private key\n");
			return -EBADMSG;
		} else {
			ctx->nr_mpi++;
			return 0;
		}
	}

	mpi = mpi_read_raw_data(value, vlen);
	if (!mpi)
		return -ENOMEM;

	ctx->pub->mpi[ctx->nr_mpi++] = mpi;
	return 0;
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
