#define DECL_DATA(n)	extern int __dummy__
#define DECL_FUNC(n)	extern int __dummy__
#define DECL_FUNC2(n)	extern int __dummy__

#define STUB_ADDR (void *)0x1234

#include "test_stub.h"
#include "stubs.h"

char *last_printk_fmt;

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

extern asmlinkage int printf (const char *, ...);
#if 0
extern asmlinkage int vsnprintf (char *, size_t, const char *, va_list)
		__attribute__ ((__nothrow__))
		__attribute__ ((__format__ (__printf__, 3, 0)));
#endif
extern asmlinkage int vprintf (const char *, va_list);
extern asmlinkage void *malloc (size_t)
		__attribute__ ((__nothrow__))
		__attribute__ ((__malloc__))
		__attribute__ ((__warn_unused_result__));
extern asmlinkage void *calloc (size_t, size_t)
		__attribute__ ((__nothrow__))
		__attribute__ ((__malloc__));
extern asmlinkage void free (void *) __attribute__ ((__nothrow__));
#if 0
extern asmlinkage void *memcpy (void *, const void *, size_t)
		__attribute__ ((__nothrow__))
		__attribute__ ((__nonnull__ (1, 2)));
extern asmlinkage void *memset (void *, int, size_t)
		__attribute__ ((__nothrow__))
		__attribute__ ((__nonnull__ (1)));
#endif
extern asmlinkage char *strdup (const char *)
		__attribute__ ((__nothrow__))
		__attribute__ ((__malloc__))
		__attribute__ ((__nonnull__ (1)));
extern asmlinkage void __gcov_init (void *);
extern asmlinkage void __gcov_merge_add (void *, unsigned);

struct tracepoint __tracepoint_kmalloc;
DECL_DATA(__tracepoint_kmalloc);

long long dynamic_debug_enabled;
DECL_DATA(dynamic_debug_enabled);
long long dynamic_debug_enabled2;
DECL_DATA(dynamic_debug_enabled2);

// This will cause the following warning:
// warning: initialization discards qualifiers from pointer target type
unsigned long volatile __jiffy_data jiffies;
DECL_DATA(jiffies);

struct kmem_cache *kmalloc_caches[SLUB_PAGE_SHIFT];
DECL_DATA(kmalloc_caches);

struct dentry *bt_debugfs = STUB_ADDR;
DECL_DATA(bt_debugfs);

static struct task_struct _current_task;
struct task_struct *current_task = &_current_task;
DECL_DATA(current_task);

struct kernel_param_ops param_ops_bool;
DECL_DATA(param_ops_bool);

struct pv_lock_ops pv_lock_ops;
DECL_DATA(pv_lock_ops);

const struct file_operations *l2cap_debugfs_fops;
const struct net_proto_family *l2cap_sock_family_ops;

void *kmem_cache_alloc(struct kmem_cache *s, gfp_t flags)
{
	int index = ((long)s - (long)kmalloc_caches) / sizeof(struct kmem_cache);
	printf("kmem_cache_alloc: gfpflags=%#x, index=%d\n", flags, index);
	return malloc(1 << index);
}
DECL_FUNC(kmem_cache_alloc);

void *kmem_cache_alloc_notrace(struct kmem_cache *s, gfp_t flags)
{
	return kmem_cache_alloc(s, flags);
}
DECL_FUNC(kmem_cache_alloc_notrace);

void *__kmalloc(size_t size, gfp_t flags)
{
	printf("__kmalloc: size=%zu, flags=%#x\n", size, flags);
	return malloc(size);
}
DECL_FUNC(__kmalloc);

unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
{
	printf("__get_free_pages: gfp_mask=%#x, order=%d\n", gfp_mask, order);
	return (long)malloc(4096);
}
DECL_FUNC(__get_free_pages);

void kfree(const void *objp)
{
	printf("kfree: objp=%p\n", objp);
	free((void *)objp);
}
DECL_FUNC(kfree);

unsigned long _copy_from_user(void *to, const void *from, unsigned long n)
{
	printf("_copy_from_user: to=%p, from=%p, n=%ld\n", to, from, n);
	memcpy(to, from, n);
	return n;
}
DECL_FUNC(_copy_from_user);

unsigned long copy_to_user(void *to,
     const void *from, unsigned long n)
{
	printf("%s: to=%p, from=%p, n=%d\n", __FUNCTION__, to, from, n);
	return 0;
}
DECL_FUNC(copy_to_user);

void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
	printf("%s: list=%p, newsk=%p\n", __FUNCTION__, list, newsk);
}
DECL_FUNC(skb_queue_head);

struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t priority)
{
	printf("%s: skb=%p, priority=%d\n", __FUNCTION__, skb, priority);
	return NULL;
}
DECL_FUNC(skb_clone);

void skb_trim(struct sk_buff *skb, unsigned int len)
{
	printf("%s: skb=%p, len=%d\n", __FUNCTION__, skb, len);
}
DECL_FUNC(skb_trim);

void skb_queue_purge(struct sk_buff_head *list)
{
	printf("%s: list=%p\n", __FUNCTION__, list);
}
DECL_FUNC(skb_queue_purge);

struct hci_dev *hci_get_route(bdaddr_t *src, bdaddr_t *dst)
{
	printf("%s: src=%p, dst=%p\n", __FUNCTION__, src, dst);
	return NULL;
}
DECL_FUNC(hci_get_route);

unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	printf("%s: skb=%p, len=%d\n", __FUNCTION__, skb, len);
	return NULL;
}
DECL_FUNC(skb_pull);

unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	printf("%s: skb=%p, len=%d\n", __FUNCTION__, skb, len);
	return NULL;
}
DECL_FUNC(skb_put);

struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
	printf("%s: list=%p\n", __FUNCTION__, list);
	return NULL;
}
DECL_FUNC(skb_dequeue);

struct sk_buff *__alloc_skb(unsigned int size,
       gfp_t priority, int fclone, int node)
{
	printf("%s: size=%d, priority=%d, fclone=%d, node=%d\n", __FUNCTION__,
			size, priority, fclone, node);
	return NULL;
}
DECL_FUNC(__alloc_skb);

void kfree_skb(struct sk_buff *skb)
{
	printf("%s: skb=%p\n", __FUNCTION__, skb);
}
DECL_FUNC(kfree_skb);

char *batostr(bdaddr_t *ba)
{
	printf("%s: ba=%p\n", __FUNCTION__, ba);
	return NULL;
}
DECL_FUNC(batostr);

void sock_init_data(struct socket *sock, struct sock *sk)
{
	printf("[stub] %s: sock=%p, sk=%p\n", __FUNCTION__, sock, sk);

	sk->sk_type = sock->type;
	sock->sk = sk;
}
DECL_FUNC(sock_init_data);

int sock_no_mmap(struct file *file,
          struct socket *sock,
          struct vm_area_struct *vma)
{
	printf("%s: file=%p, sock=%p, vma=%p\n", __FUNCTION__, file, sock, vma);
	return -1;
}
DECL_FUNC(sock_no_mmap);

int sock_no_socketpair(struct socket *sock1,
         struct socket *sock2)
{
	printf("%s: sock1=%p, sock2=%p\n", __FUNCTION__, sock1, sock2);
	return -1;
}
DECL_FUNC(sock_no_socketpair);

void release_sock(struct sock *sk)
{
	printf("%s: sk=%p\n", __FUNCTION__, sk);
}
DECL_FUNC(release_sock);

int bt_err(__u16 code)
{
	printf("%s: code=%d\n", __FUNCTION__, code);
	return -1;
}
DECL_FUNC(bt_err);

void bt_accept_enqueue(struct sock *parent, struct sock *sk)
{
	printf("%s: parent=%p, sk=%p\n", __FUNCTION__, parent, sk);
}
DECL_FUNC(bt_accept_enqueue);

struct sock *bt_accept_dequeue(struct sock *parent, struct socket *newsock)
{
	printf("%s: parent=%p, newsock=%p\n", __FUNCTION__, parent, newsock);
	return NULL;
}
DECL_FUNC(bt_accept_dequeue);

void bt_accept_unlink(struct sock *sk)
{
	printf("%s: sk=%p\n", __FUNCTION__, sk);
}
DECL_FUNC(bt_accept_unlink);

uint bt_sock_poll(struct file *file, struct socket *sock,
		poll_table *wait)
{
	printf("%s: file=%p, sock=%p, wait=%p\n", __FUNCTION__, file, sock,
			wait);
	return 0;
}
DECL_FUNC(bt_sock_poll);

int bt_sock_wait_state(struct sock *sk, int state, unsigned long timeo)
{
	printf("%s: sk=%p, state=%d, timeo=%d\n", __FUNCTION__, sk, state,
			timeo);
	return -1;
}
DECL_FUNC(bt_sock_wait_state);

void bt_sock_unlink(struct bt_sock_list *l, struct sock *s)
{
	printf("%s: l=%p, s=%p\n", __FUNCTION__, l, s);
}
DECL_FUNC(bt_sock_unlink);

int bt_sock_register(int proto, const struct net_proto_family *ops)
{
	STUB_RETURN(bt_sock_register, -1);

	printf("[stub] %s: proto=%d, ops=%p\n", __FUNCTION__, proto, ops);

	l2cap_sock_family_ops = ops;

	return 0;
}
DECL_FUNC(bt_sock_register);

int bt_sock_unregister(int proto)
{
	STUB_RETURN(bt_sock_unregister, -1);

	printf("[stub] %s: proto=%d\n", __FUNCTION__, proto);
	return 0;
}
DECL_FUNC(bt_sock_unregister);

void lock_sock_nested(struct sock *sk, int subclass)
{
	printf("%s: sk=%p, subclass=%d\n", __FUNCTION__, sk, subclass);
}
DECL_FUNC(lock_sock_nested);

struct sock *sk_alloc(struct net *net, int family,
       gfp_t priority,
       struct proto *prot)
{
	STUB_RETURN(sk_alloc, NULL);

	printf("[stub] %s: net=%p, family=%d, priority=%d, prot=%p\n", __FUNCTION__,
			net, family, priority, prot);

	return calloc(1, prot->obj_size);
}
DECL_FUNC(sk_alloc);

void bt_sock_link(struct bt_sock_list *l, struct sock *s)
{
	printf("%s: l=%p, s=%p\n", __FUNCTION__, l, s);
}
DECL_FUNC(bt_sock_link);

void sk_free(struct sock *sk)
{
	printf("[stub] %s: sk=%p\n", __FUNCTION__, sk);

	free(sk);
}
DECL_FUNC(sk_free);

int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	printf("%s: sk=%p, skb=%p\n", __FUNCTION__, sk, skb);
	return -1;
}
DECL_FUNC(sock_queue_rcv_skb);

struct sk_buff *sock_alloc_send_skb(struct sock *sk, unsigned long size,
		int noblock, int *errcode)
{
	return NULL;
}
DECL_FUNC(sock_alloc_send_skb);

void sk_stop_timer(struct sock *sk, struct timer_list *timer)
{
	printf("%s: sk=%p, timer=%p\n", __FUNCTION__, sk, timer);
}
DECL_FUNC(sk_stop_timer);

void sk_reset_timer(struct sock *sk, struct timer_list *timer,
      unsigned long expires)
{
	printf("%s: sk=%p, timer=%p, expires=%d\n", __FUNCTION__, sk, timer,
			expires);
}
DECL_FUNC(sk_reset_timer);

void init_timer_key(struct timer_list *timer, const char *name,
		struct lock_class_key *key)
{
	printf("%s: timer=%p, name=%s, key=%p\n", __FUNCTION__, timer, name,
			key);
}
DECL_FUNC(init_timer_key);

int mod_timer(struct timer_list *timer, unsigned long expires)
{
	printf("%s: timer=%p, expires=%d\n", __FUNCTION__, timer, expires);
	return -1;
}
DECL_FUNC(mod_timer);

int del_timer(struct timer_list *timer)
{
	printf("%s: timer=%p\n", __FUNCTION__, timer);
	return -1;
}
DECL_FUNC(del_timer);

int memcpy_fromiovec(unsigned char *kdata, struct iovec *iov, int len)
{
	printf("%s: kdata=%p, iov=%p, len=%d\n", __FUNCTION__, kdata, iov, len);
	return -1;
}
DECL_FUNC(memcpy_fromiovec);

void *_memcpy(void *dest, const void *src, size_t n)
{
	printf("%s: dest=%p, src=%p, n=%d\n", __FUNCTION__, dest, src, n);
	return NULL;
}
DECL_FUNC2(memcpy);

void *_memset(void *s, int c, size_t n)
{
	printf("%s: s=%p, c=%d, n=%d\n", __FUNCTION__, s, c, n);
	return NULL;
}
DECL_FUNC2(memset);

void hci_send_acl(struct hci_conn *conn, struct sk_buff *skb,
		__u16 flags)
{
	printf("%s: conn=%p, skb=%p, flags=%d\n", __FUNCTION__, conn, skb,
			flags);
}
DECL_FUNC(hci_send_acl);

int hci_conn_check_link_mode(struct hci_conn *conn)
{
	printf("%s: conn=%p\n", __FUNCTION__, conn);
	return -1;
}
DECL_FUNC(hci_conn_check_link_mode);

int hci_conn_security(struct hci_conn *conn, __u8 sec_level,
		__u8 auth_type)
{
	printf("%s: conn=%p, sec_level=%d, auth_type=%d\n", __FUNCTION__, conn,
			sec_level, auth_type);
	return -1;
}
DECL_FUNC(hci_conn_security);

struct hci_conn *hci_connect(struct hci_dev *hdev, int type,
		bdaddr_t *dst, __u8 sec_level, __u8 auth_type)
{
	printf("%s: hdev=%p, type=%d, dst=%p, sec_level=%d, auth_type=%d\n",
			__FUNCTION__, hdev, type, dst, sec_level, auth_type);
	return NULL;
}
DECL_FUNC(hci_connect);

int hci_register_proto(struct hci_proto *hproto)
{
	STUB_RETURN(hci_register_proto, -1);

	printf("[stub] %s: hproto=%p\n", __FUNCTION__, hproto);
	return 0;
}
DECL_FUNC(hci_register_proto);

int hci_unregister_proto(struct hci_proto *hproto)
{
	STUB_RETURN(hci_unregister_proto, -1);

	printf("[stub] %s: hproto=%p\n", __FUNCTION__, hproto);
	return 0;
}
DECL_FUNC(hci_unregister_proto);

void local_bh_enable(void)
{
	printf("%s\n", __FUNCTION__);
}
DECL_FUNC(local_bh_enable);

void local_bh_disable(void)
{
	printf("%s\n", __FUNCTION__);
}
DECL_FUNC(local_bh_disable);

int param_get_bool(char *buffer, const struct kernel_param *kp)
{
	printf("%s: buffer=%p, kp=%p\n", __FUNCTION__, buffer, kp);
	return 0;
}
DECL_FUNC(param_get_bool);

struct crypto_tfm *crypto_alloc_base(const char *alg_name, u32 type, u32 mask)
{
	printf("%s: alg_name=%s, type=%d, mask=%d\n", __FUNCTION__, alg_name, type, mask);
	return NULL;
}
DECL_FUNC(crypto_alloc_base);

void crypto_destroy_tfm(void *mem, struct crypto_tfm *tfm)
{
	printf("%s: mem=%p, tfm=%p\n", __FUNCTION__, mem, tfm);
}
DECL_FUNC(crypto_destroy_tfm);

int proto_register(struct proto *prot, int alloc_slab)
{
	STUB_RETURN(proto_register, -1);

	printf("[stub] %s: prot=%p, alloc_slab=%d\n", __FUNCTION__, prot, alloc_slab);
	return 0;
}
DECL_FUNC(proto_register);

void proto_unregister(struct proto *prot)
{
	printf("%s: prot=%p\n", __FUNCTION__, prot);
}
DECL_FUNC(proto_unregister);

signed long schedule_timeout(signed long timeout)
{
	printf("%s: timeout=%d\n", __FUNCTION__, timeout);
	return -1;
}
DECL_FUNC(schedule_timeout);

unsigned long msecs_to_jiffies(const unsigned int m)
{
	printf("%s: m=%d\n", __FUNCTION__, m);
	return 0;
}
DECL_FUNC(msecs_to_jiffies);

int capable(int cap)
{
	STUB_RETURN(capable, 0);

	printf("[stub] %s: cap=%d\n", __FUNCTION__, cap);

	return 1;
}
DECL_FUNC(capable);

void module_put(struct module *module)
{
	printf("%s: module=%p\n", module);
}
DECL_FUNC(module_put);

int bt_sock_ioctl(struct socket *sock, unsigned int cmd,
		unsigned long arg)
{
	printf("%s: sock=%p, cmd=%d, arg=%d\n", __FUNCTION__, sock, cmd, arg);
	return -1;
}
DECL_FUNC(bt_sock_ioctl);

int bt_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *msg, size_t len, int flags)
{
	printf("%s: iocb=%p, sock=%p, msg=%p, len=%d, flags=%d\n",
			__FUNCTION__, iocb, sock, msg, len, flags);
	return -1;
}
DECL_FUNC(bt_sock_recvmsg);

int bt_sock_stream_recvmsg(struct kiocb *iocb, struct socket *sock,
   struct msghdr *msg, size_t len, int flags)
{
	printf("%s: iocb=%p, sock=%p, msg=%p, len=%d, flags=%d\n",
			__FUNCTION__, iocb, sock, msg, len, flags);
	return -1;
}
DECL_FUNC(bt_sock_stream_recvmsg);

int single_open(struct file *file, int (*show)(struct seq_file *, void *),
		void *data)
{
	printf("[stub] %s: file=%p, show=%p, data=%p\n", __FUNCTION__, file, show,
			data);

	show(NULL, NULL);

	return 0;
}
DECL_FUNC(single_open);

int single_release(struct inode *inode, struct file *file)
{
	printf("%s: inode=%p, file=%p\n", __FUNCTION__, inode, file);
	return -1;
}
DECL_FUNC(single_release);

int seq_printf(struct seq_file *m, const char *f, ...)
{
	printf("%s: m=%p, f=%s\n", __FUNCTION__, m, f);
	return -1;
}
DECL_FUNC(seq_printf);

ssize_t seq_read(struct file *file, char *buf, size_t size, loff_t *ppos)
{
	printf("%s: file=%p, buf=%p, size=%d, ppos=%p\n", __FUNCTION__, file,
			buf, size, ppos);
	return -1;
}
DECL_FUNC(seq_read);

loff_t seq_lseek(struct file *file , loff_t offset, int origin)
{
	printf("%s: file=%p, offset=%d, origin=%d\n", __FUNCTION__, file, offset, origin);
	return -1;
}
DECL_FUNC(seq_lseek);

void add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t *wait)
{
	printf("%s: q=%p, wait=%p\n", __FUNCTION__, q, wait);
}
DECL_FUNC(add_wait_queue_exclusive);

void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
	printf("%s: q=%p, wait=%p\n", __FUNCTION__, q, wait);
}
DECL_FUNC(add_wait_queue);

void remove_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
	printf("%s: q=%p, wait=%p\n", __FUNCTION__, q, wait);
}
DECL_FUNC(remove_wait_queue);

struct workqueue_struct *__alloc_workqueue_key(const char *name,
		unsigned int flags, int max_active, struct lock_class_key *key,
		const char *lock_name)
{
	STUB_RETURN(__alloc_workqueue_key, NULL);

	printf("[stub] %s: name=%s, flags=%d, max_active=%d, key=%p, lock_name=%s\n",
			__FUNCTION__, name, flags, max_active, key, lock_name);
	return STUB_ADDR;
}
DECL_FUNC(__alloc_workqueue_key);

int queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	printf("%s: wq=%p, work=%p", __FUNCTION__, wq, work);
	return -1;
}
DECL_FUNC(queue_work);

void flush_workqueue(struct workqueue_struct *wq)
{
	printf("%s: wq=%p\n", __FUNCTION__, wq);
}
DECL_FUNC(flush_workqueue);

void destroy_workqueue(struct workqueue_struct *wq)
{
	printf("%s: wq=%p\n", __FUNCTION__, wq);
}
DECL_FUNC(destroy_workqueue);

void debugfs_remove(struct dentry *dentry)
{
	printf("%s: dentry=%p\n", __FUNCTION__, dentry);
}
DECL_FUNC(debugfs_remove);

struct dentry *debugfs_create_file(const char *name, mode_t mode,
		struct dentry *parent, void *data,
		const struct file_operations *fops)
{
	STUB_RETURN(debugfs_create_file, NULL);

	printf("[stub] %s: name=%s, mode=%d, parent=%p, data=%p, fops=%p\n",
			__FUNCTION__, name, mode, parent, data, fops);

	l2cap_debugfs_fops = fops;

	return STUB_ADDR;
}
DECL_FUNC(debugfs_create_file);

u16 crc16(u16 crc, const u8 *buffer, size_t len)
{
	printf("%s: crc=%d, buffer=%p, len=%d\n", __FUNCTION__, crc, buffer,
			len);
	return 0;
}
DECL_FUNC(crc16);

void sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen)
{
	printf("%s: sg=%p, buf=%p, buflen=%d\n", __FUNCTION__, sg, buf, buflen);
}
DECL_FUNC(sg_init_one);

void hex_dump_to_buffer(const void *buf, size_t len,
		int rowsize, int groupsize,
		char *linebuf, size_t linebuflen, bool ascii)
{
	printf("%s: buf=%p, len=%d, rowsize=%d, groupsize=%d, linebuf=%p, "
			"linebuflen=%d, ascii=%d\n", __FUNCTION__, buf, len,
			rowsize, groupsize, linebuf, linebuflen, ascii);
}
DECL_FUNC(hex_dump_to_buffer);

int default_wake_function(wait_queue_t *wait, unsigned mode, int flags, void *key)
{
	printf("%s: wait=%p, mode=%d, flags=%d, key=%p\n", __FUNCTION__, wait,
			mode, flags, key);
	return -1;
}
DECL_FUNC(default_wake_function);

void get_random_bytes(void *buf, int nbytes)
{
	printf("%s: buf=%p, nbytes=%d\n", __FUNCTION__, buf, nbytes);
}
DECL_FUNC(get_random_bytes);

int _snprintf(char *buf, size_t size, const char * fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(buf, size, fmt, ap);
	va_end(ap);

	return ret;
}
DECL_FUNC2(snprintf);

asmlinkage int printk(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);

	free(last_printk_fmt);
	last_printk_fmt = strdup(fmt);

	return ret;
}
DECL_FUNC(printk);

void mcount(void)
{
//	printf("%s\n", __FUNCTION__);
}
DECL_FUNC(mcount);

void __stack_chk_fail(void)
{
	printf("%s\n", __FUNCTION__);
}
DECL_FUNC(__stack_chk_fail);

void __put_user_4(void)
{
	printf("%s\n", __FUNCTION__);
}
DECL_FUNC(__put_user_4);

int __get_user_4(void)
{
	printf("%s\n", __FUNCTION__);
	return -1;
}
DECL_FUNC(__get_user_4);

int _cond_resched(void)
{
	printf("%s\n", __FUNCTION__);
	return -1;
}
DECL_FUNC(_cond_resched);

void hci_le_start_enc(struct hci_conn *conn, u8 ltk[16])
{
	printf("%s: conn=%p, ltk=%p\n", __FUNCTION__, conn, ltk);
}
DECL_FUNC(hci_le_start_enc);

void ___gcov_init(char *p1)
{
	printf("%s: p1=\"%s\" (%p)\n", __FUNCTION__, p1, p1);
	__gcov_init(p1);
}
DECL_FUNC2(__gcov_init);

void ___gcov_merge_add(void *p1, unsigned p2)
{
//	printf("%s: p1=%p, p2=%d\n", __FUNCTION__, p1, p2);
	__gcov_merge_add(p1, p2);
}
DECL_FUNC2(__gcov_merge_add);

/* The following functions are just wrappers to avoid exposing kernel
 * structures to test_kmod.c */

int l2cap_debugfs_open(void)
{
	struct inode inode;
	struct file file;

	if (!l2cap_debugfs_fops)
		return -1;

	memset(&inode, 0, sizeof(inode));
	memset(&file, 0, sizeof(file));

	return l2cap_debugfs_fops->open(&inode, &file);
}

int l2cap_sock_create(short sock_type, void **opaque)
{
	struct net net;
	struct socket *sock;
	int protocol = 0;
	int kern = 0;
	int ret;

	if (!l2cap_sock_family_ops)
		return -1;

	memset(&net, 0, sizeof(net));
	sock = calloc(1, sizeof(*sock));

	sock->type = sock_type;

	ret = l2cap_sock_family_ops->create(&net, sock, protocol, kern);

	if (opaque)
		*opaque = sock;
	else
		free(sock);

	return ret;
}

#define STUB_FREE_SK		0x01	/* Force sock->sk = NULL */
#define STUB_SK_ERR		0x02	/* Set sk->sk_err = 1 */

int l2cap_sock_release(void *opaque, unsigned int stub_flags)
{
	struct socket *sock = opaque;
	int ret;

	sock->sk->sk_refcnt.counter = 1;
	if (stub_flags & STUB_SK_ERR)
		sock->sk->sk_err = 1;
	if (stub_flags & STUB_FREE_SK) {
		free(sock->sk);
		sock->sk = NULL;
	}
	ret = sock->ops->release(sock);
	free(sock);
	return ret;
}

#include "symtable.h"
