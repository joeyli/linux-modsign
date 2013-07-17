#include <linux/sched.h>
#include <linux/efi.h>
#include <linux/mpi.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>

#include "power.h"

#define EFI_HIBERNATE_GUID \
	EFI_GUID(0xfe141863, 0xc070, 0x478e, 0xb8, 0xa3, 0x87, 0x8a, 0x5d, 0xc9, 0xef, 0x21)
static efi_char16_t efi_s4_sign_key_name[10] = { 'S', '4', 'S', 'i', 'g', 'n', 'K', 'e', 'y', 0 };
static efi_char16_t efi_s4_wake_key_name[10] = { 'S', '4', 'W', 'a', 'k', 'e', 'K', 'e', 'y', 0 };

static struct key *s4_sign_key;
static struct key *s4_wake_key;

/* TODO: kill, for debugging */
void printu8(u8 *message, int length)
{
	char *message_str;
	int i;

	message_str = kzalloc(length * 2 + 1, GFP_KERNEL);
	if (!message_str)
		return;

	for (i = 0; i < length; i++)
		sprintf(message_str + i * 2, "%02x", message[i]);

	pr_info("%s\n", message_str);

	kfree(message_str);
}

static int efi_status_to_err(efi_status_t status)
{
	int err;

	switch (status) {
	case EFI_INVALID_PARAMETER:
		err = -EINVAL;
		break;
	case EFI_OUT_OF_RESOURCES:
		err = -ENOSPC;
		break;
	case EFI_DEVICE_ERROR:
		err = -EIO;
		break;
	case EFI_WRITE_PROTECTED:
		err = -EROFS;
		break;
	case EFI_SECURITY_VIOLATION:
		err = -EACCES;
		break;
	case EFI_NOT_FOUND:
		err = -EIO;
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

static struct key *efi_key_load(efi_char16_t *var_name, char *key_desc)
{
	const struct cred *cred = current_cred();
	unsigned long datasize = 0;
	u32 attributes;
	void *data;
	struct key *key;
	efi_status_t status;
	int err;

	key = ERR_PTR(-EINVAL);

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return 0;

	/* obtain the size */
	status = efi.get_variable(var_name, &EFI_HIBERNATE_GUID,
				  NULL, &datasize, NULL);
	if (status != EFI_BUFFER_TOO_SMALL) {
		pr_err("Couldn't get size: 0x%lx\n", status);
		key = ERR_PTR(efi_status_to_err(status));
		goto error_size;
	}

	data = kmalloc(datasize, GFP_KERNEL);
	if (!data) {
		key = ERR_PTR(-ENOMEM);
		goto error_size;
	}

	status = efi.get_variable(var_name, &EFI_HIBERNATE_GUID,
				&attributes, &datasize, data);
	if (status) {
		key = ERR_PTR(efi_status_to_err(status));
		pr_err("Get variable error: %ld, ", PTR_ERR(key));
		goto error_get;
	}

	key = key_alloc(&key_type_asymmetric, key_desc,
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			cred, 0, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(key)) {
		pr_err("Allocate key error: %ld, ", PTR_ERR(key));
		goto error_get;
	}

	err = key_instantiate_and_link(key, data, datasize, NULL, NULL);
	if (err < 0) {
		pr_err("Key instantiate error: %d", err);
		if (key)
			key_put(key);
		key = ERR_PTR(err);
	}

error_get:
	kfree(data);
error_size:
	return key;
}

struct key *load_sign_key(void)
{
	pr_info("sign_key_read, before: \n");
	if (s4_sign_key && !IS_ERR(s4_sign_key))
		printu8(s4_sign_key->payload.data, 32);              /* TODO: kill debug */
	pr_info("\n");

	s4_sign_key = efi_key_load(efi_s4_sign_key_name, "s4_sign_key");
	if (IS_ERR(s4_sign_key))
		pr_err("Load private key fail: %ld", PTR_ERR(s4_sign_key));
	if (!s4_sign_key)						/* TODO: kill */
		pr_info("s4_sign_key load to NULL???\n");

	pr_info("sign_key_read, after: \n");                         /* TODO: kill */
	if (s4_sign_key && !IS_ERR(s4_sign_key))
		printu8(s4_sign_key->payload.data, 32);
	pr_info("\n");

	return s4_sign_key;
}

static int init_sign_key(void)
{
	struct key *key;

	key = load_sign_key();
	if (IS_ERR(key))
		return PTR_ERR(key);

	return 0;
}


struct key *get_sign_key(void)
{
	return s4_sign_key;
}

struct key *load_wake_key(void)
{
	s4_wake_key = efi_key_load(efi_s4_wake_key_name, "s4_wake_key");
	if (IS_ERR(s4_wake_key))
		pr_err("Load S4 wake key fail: %ld", PTR_ERR(s4_wake_key));
	if (!s4_wake_key)						/* TODO: kill */
		pr_info("s4_wake_key load to NULL???\n");

	return s4_wake_key;
}

size_t get_key_length(const struct key *key)
{
	const struct public_key *pk = key->payload.data;
	size_t len;

	/* TODO: better check the RSA type */

	len = mpi_get_nbits(pk->rsa.n);
	len = (len + 7) / 8;

	return len;
}

late_initcall(init_sign_key);
