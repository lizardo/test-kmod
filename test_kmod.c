#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <check.h>
#include <asm/errno.h>
#include <sys/socket.h>

#include "load_kmod.h"
#include "test_stub.h"

#define asmregparm __attribute__((regparm(3)))

extern char *last_printk_fmt;

#define STUB_FREE_SK		0x01	/* Force sock->sk = NULL */
#define STUB_SK_ERR		0x02	/* Set sk->sk_err = 1 */

extern asmregparm int l2cap_debugfs_open(void);
extern asmregparm int l2cap_sock_create(short sock_type, void **opaque);
extern asmregparm int l2cap_sock_release(void *opaque, int free_sk);

#define LAST_PRINTK(fmt) (last_printk_fmt && strcmp(last_printk_fmt + 3, \
			fmt "\n") == 0)

START_TEST (test_init)
{
	ENABLE_STUB(proto_register) = 1;
	fail_unless(init_module() == -1,
		"Module initialization failure expected");
	ENABLE_STUB(proto_register) = 0;

	ENABLE_STUB(__alloc_workqueue_key) = 1;
	fail_unless(init_module() == -ENOMEM,
		"Module initialization failure expected");
	ENABLE_STUB(__alloc_workqueue_key) = 0;

	ENABLE_STUB(bt_sock_register) = 1;
	fail_unless(init_module() == -1 &&
		LAST_PRINTK("%s: L2CAP socket registration failed"),
		"Module initialization failure expected");
	ENABLE_STUB(bt_sock_register) = 0;

	ENABLE_STUB(hci_register_proto) = 1;
	fail_unless(init_module() == -1 &&
		LAST_PRINTK("%s: L2CAP protocol registration failed"),
		"Module initialization failure expected");
	ENABLE_STUB(hci_register_proto) = 0;

	ENABLE_STUB(debugfs_create_file) = 1;
	fail_unless(init_module() == 0 &&
		/* The debugfs_create_file() failure is ignored */
		LAST_PRINTK("Bluetooth: L2CAP socket layer initialized"),
		"Module initialization failed");
	ENABLE_STUB(debugfs_create_file) = 0;
}
END_TEST

START_TEST (test_cleanup)
{
	ENABLE_STUB(bt_sock_unregister) = 1;
	cleanup_module();
	fail_unless(LAST_PRINTK("%s: L2CAP socket unregistration failed"),
		"Module cleanup failed");
	ENABLE_STUB(bt_sock_unregister) = 0;

	ENABLE_STUB(hci_unregister_proto) = 1;
	cleanup_module();
	fail_unless(LAST_PRINTK("%s: L2CAP protocol unregistration failed"),
		"Module cleanup failed");
	ENABLE_STUB(hci_unregister_proto) = 0;
}
END_TEST

START_TEST (test_debugfs_fops)
{
	fail_unless(l2cap_debugfs_open() == 0,
		"l2cap_debugfs_fops->open() failed");
}
END_TEST

START_TEST (test_sock_create)
{
	void *opaque;

	fail_unless(l2cap_sock_create(0, NULL) == -ESOCKTNOSUPPORT,
		"l2cap_sock_family_ops->create() failure expected (-ESOCKTNOSUPPORT)");

	ENABLE_STUB(capable) = 1;
	fail_unless(l2cap_sock_create(SOCK_RAW, NULL) == -EPERM,
		"l2cap_sock_family_ops->create() failure expected (-EPERM)");
	ENABLE_STUB(capable) = 0;

	ENABLE_STUB(sk_alloc) = 1;
	fail_unless(l2cap_sock_create(SOCK_RAW, NULL) == -ENOMEM,
		"l2cap_sock_family_ops->create() failure expected (-ENOMEM)");
	ENABLE_STUB(sk_alloc) = 0;

	fail_unless(l2cap_sock_create(SOCK_RAW, &opaque) == 0,
		"l2cap_sock_family_ops->create() failed");

	fail_unless(l2cap_sock_release(opaque, STUB_SK_ERR) == -1,
		"l2cap_sock_family_ops->release() failure expected (-1)");

	fail_unless(l2cap_sock_create(SOCK_RAW, &opaque) == 0,
		"l2cap_sock_family_ops->create() failed");

	fail_unless(l2cap_sock_release(opaque, STUB_FREE_SK) == 0,
		"l2cap_sock_family_ops->release() failed");

	fail_unless(l2cap_sock_create(SOCK_STREAM, &opaque) == 0,
		"l2cap_sock_family_ops->create() failed");

	fail_unless(l2cap_sock_release(opaque, 0) == 0,
		"l2cap_sock_family_ops->release() failed");
}
END_TEST

static void setup(void)
{
	init_module();
}

static void teardown(void)
{
	cleanup_module();
	free(last_printk_fmt);
	last_printk_fmt = NULL;
}

static Suite *kmod_suite(void)
{
	Suite *s = suite_create("kmod");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_init);
	tcase_add_test(tc_core, test_cleanup);
	tcase_add_test(tc_core, test_debugfs_fops);
	tcase_add_test(tc_core, test_sock_create);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <module.ko>\n", argv[0]);
		return 1;
	}

	load_module(argv[1]);

	Suite *s = kmod_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	int number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
