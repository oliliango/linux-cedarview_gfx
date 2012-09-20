/*
 * Persistent Storage - platform driver interface parts.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 * Copyright (C) 2010 Intel Corporation <tony.luck@intel.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kmsg_dump.h>
#include <linux/console.h>
#include <linux/module.h>
#include <linux/pstore.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/hardirq.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/notifier.h>

#include "internal.h"

/*
 * We defer making "oops" entries appear in pstore - see
 * whether the system is actually still running well enough
 * to let someone see the entry
 */
static int pstore_update_ms = -1;
module_param_named(update_ms, pstore_update_ms, int, 0600);
MODULE_PARM_DESC(update_ms, "milliseconds before pstore updates its content "
		 "(default is -1, which means runtime updates are disabled; "
		 "enabling this option is not safe, it may lead to further "
		 "corruption on Oopses)");

static int pstore_new_entry;

static void pstore_timefunc(unsigned long);
static DEFINE_TIMER(pstore_timer, pstore_timefunc, 0, 0);

static void pstore_dowork(struct work_struct *);
static DECLARE_WORK(pstore_work, pstore_dowork);

/*
 * pstore_lock just protects "psinfo" during
 * calls to pstore_register()
 */
static DEFINE_SPINLOCK(pstore_lock);
struct pstore_info *psinfo;

static char *backend;

/* How much of the console log to snapshot */
static unsigned long kmsg_bytes = 10240;

void pstore_set_kmsg_bytes(int bytes)
{
	kmsg_bytes = bytes;
}

static ATOMIC_NOTIFIER_HEAD(pstore_notifiers);

int pstore_notifier_register(struct notifier_block *n)
{
	return atomic_notifier_chain_register(&pstore_notifiers, n);
}
EXPORT_SYMBOL_GPL(pstore_notifier_register);

int pstore_notifier_unregister(struct notifier_block *n)
{
	return atomic_notifier_chain_unregister(&pstore_notifiers, n);
}
EXPORT_SYMBOL_GPL(pstore_notifier_unregister);

/* Tag each group of saved records with a sequence number */
static int	oopscount;

static const char *get_reason_str(enum kmsg_dump_reason reason)
{
	switch (reason) {
	case KMSG_DUMP_PANIC:
		return "Panic";
	case KMSG_DUMP_OOPS:
		return "Oops";
	case KMSG_DUMP_EMERG:
		return "Emergency";
	case KMSG_DUMP_RESTART:
		return "Restart";
	case KMSG_DUMP_HALT:
		return "Halt";
	case KMSG_DUMP_POWEROFF:
		return "Poweroff";
	default:
		return "Unknown";
	}
}

static int pstore_ext_flush(void)
{
	int ret;

	if (!psinfo->ext_len)
		return 0;

	ret = psinfo->write(psinfo->ext_type, psinfo->ext_reason,
			    &psinfo->ext_id, psinfo->ext_part++,
			    0, psinfo->ext_len, psinfo);

	if (ret == 0 && psinfo->ext_reason == KMSG_DUMP_OOPS &&
	    pstore_is_mounted())
		pstore_new_entry = 1;

	psinfo->ext_len = 0;

	return ret;
}

/*
 * callback from kmsg_dump. (s2,l2) has the most recently
 * written bytes, older bytes are in (s1,l1). Save as much
 * as we can from the end of the buffer.
 */
static void pstore_dump(struct kmsg_dumper *dumper,
			enum kmsg_dump_reason reason)
{
	unsigned long	total = 0;
	const char	*why;
	u64		id;
	unsigned int	part = 1;
	unsigned long	flags = 0;
	int		is_locked = 0;
	int		ret;

	why = get_reason_str(reason);

	if (in_nmi()) {
		is_locked = spin_trylock(&psinfo->buf_lock);
		if (!is_locked)
			pr_err("pstore dump routine blocked in NMI, may corrupt error record\n");
	} else
		spin_lock_irqsave(&psinfo->buf_lock, flags);
	oopscount++;

	psinfo->ext_id = 0;
	psinfo->ext_len = 0;
	psinfo->ext_part = 0;
	psinfo->ext_type = PSTORE_TYPE_UNKNOWN;
	psinfo->ext_reason = reason;

	atomic_notifier_call_chain(&pstore_notifiers, PSTORE_BEGIN, psinfo);

	while (total < kmsg_bytes) {
		char *dst;
		unsigned long size;
		int hsize;
		size_t len;

		dst = psinfo->buf;
		if (psinfo->flags & PSTORE_NO_HEADINGS)
			hsize = 0;
		else
			hsize = sprintf(dst, "%s#%d Part%d\n", why, oopscount,
					part);
		size = psinfo->bufsize - hsize;
		dst += hsize;

		if (!kmsg_dump_get_buffer(dumper, true, dst, size, &len))
			break;

		ret = psinfo->write(PSTORE_TYPE_DMESG, reason, &id, part,
				    oopscount, hsize + len, psinfo);
		if (ret == 0 && reason == KMSG_DUMP_OOPS && pstore_is_mounted())
			pstore_new_entry = 1;

		total += hsize + len;
		part++;
	}

	atomic_notifier_call_chain(&pstore_notifiers, PSTORE_DUMP, psinfo);

	pstore_ext_flush();

	atomic_notifier_call_chain(&pstore_notifiers, PSTORE_END, psinfo);

	if (in_nmi()) {
		if (is_locked)
			spin_unlock(&psinfo->buf_lock);
	} else
		spin_unlock_irqrestore(&psinfo->buf_lock, flags);
}

static struct kmsg_dumper pstore_dumper = {
	.dump = pstore_dump,
};

#ifdef CONFIG_PSTORE_CONSOLE
static void pstore_console_write(struct console *con, const char *s, unsigned c)
{
	const char *e = s + c;

	while (s < e) {
		unsigned long flags;
		u64 id;

		if (c > psinfo->bufsize)
			c = psinfo->bufsize;

		if (oops_in_progress) {
			if (!spin_trylock_irqsave(&psinfo->buf_lock, flags))
				break;
		} else {
			spin_lock_irqsave(&psinfo->buf_lock, flags);
		}
		memcpy(psinfo->buf, s, c);
		psinfo->write(PSTORE_TYPE_CONSOLE, 0, &id, 0, 0, c, psinfo);
		spin_unlock_irqrestore(&psinfo->buf_lock, flags);
		s += c;
		c = e - s;
	}
}

static struct console pstore_console = {
	.name	= "pstore",
	.write	= pstore_console_write,
	.flags	= CON_PRINTBUFFER | CON_ENABLED | CON_ANYTIME,
	.index	= -1,
};

static void pstore_register_console(void)
{
	register_console(&pstore_console);
}
#else
static void pstore_register_console(void) {}
#endif

static int pstore_write_compat(enum pstore_type_id type,
			       enum kmsg_dump_reason reason,
			       u64 *id, unsigned int part, int count,
			       size_t size, struct pstore_info *psi)
{
	return psi->write_buf(type, reason, id, part, psinfo->buf, size, psi);
}

#ifdef CONFIG_DEBUG_FS

static DEFINE_SPINLOCK(dbg_lock);

static int dbg_dump(void *data, u64 val)
{
	unsigned long flags;

	switch (val) {
	case KMSG_DUMP_PANIC:
	case KMSG_DUMP_OOPS:
	case KMSG_DUMP_EMERG:
	case KMSG_DUMP_RESTART:
	case KMSG_DUMP_HALT:
	case KMSG_DUMP_POWEROFF:
		spin_lock_irqsave(&dbg_lock, flags);
		kmsg_dump(val);
		spin_unlock_irqrestore(&dbg_lock, flags);
		return 0;
	}
	return -EINVAL;
}
DEFINE_SIMPLE_ATTRIBUTE(dbg_dump_fops, NULL, dbg_dump, "%llu\n");

static int dbg_panic(void *data, u64 val)
{
	panic(KERN_EMERG "pstore debugging panic!\n");
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(dbg_panic_fops, NULL, dbg_panic, "%llu\n");

static void pstore_debugfs_init(void)
{
	struct dentry *root;

	root = debugfs_create_dir("pstore", NULL);
	debugfs_create_file("dump", S_IWUSR, root, NULL, &dbg_dump_fops);
	debugfs_create_file("panic", S_IWUSR, root, NULL, &dbg_panic_fops);
}

#else

static inline void pstore_debugfs_init(void)
{
}

#endif

/*
 * platform specific persistent storage driver registers with
 * us here. If pstore is already mounted, call the platform
 * read function right away to populate the file system. If not
 * then the pstore mount code will call us later to fill out
 * the file system.
 *
 * Register with kmsg_dump to save last part of console log on panic.
 */
int pstore_register(struct pstore_info *psi)
{
	struct module *owner = psi->owner;

	spin_lock(&pstore_lock);
	if (psinfo) {
		spin_unlock(&pstore_lock);
		return -EBUSY;
	}

	if (backend && strcmp(backend, psi->name)) {
		spin_unlock(&pstore_lock);
		return -EINVAL;
	}

	if (!psi->write)
		psi->write = pstore_write_compat;
	psinfo = psi;
	mutex_init(&psinfo->read_mutex);
	spin_unlock(&pstore_lock);

	if (owner && !try_module_get(owner)) {
		psinfo = NULL;
		return -EINVAL;
	}

	if (psinfo->flags & PSTORE_MAX_KMSG_BYTES)
		kmsg_bytes = ULONG_MAX;

	if (pstore_is_mounted())
		pstore_get_records(0);

	kmsg_dump_register(&pstore_dumper);
	pstore_register_console();
	pstore_register_ftrace();

	if (pstore_update_ms >= 0) {
		pstore_timer.expires = jiffies +
			msecs_to_jiffies(pstore_update_ms);
		add_timer(&pstore_timer);
	}

	pstore_debugfs_init();

	return 0;
}
EXPORT_SYMBOL_GPL(pstore_register);

/*
 * Read all the records from the persistent store. Create
 * files in our filesystem.  Don't warn about -EEXIST errors
 * when we are re-scanning the backing store looking to add new
 * error records.
 */
void pstore_get_records(int quiet)
{
	struct pstore_info *psi = psinfo;
	char			*buf = NULL;
	ssize_t			size;
	u64			id;
	int			count;
	enum pstore_type_id	type;
	struct timespec		time;
	int			failed = 0, rc;

	if (!psi)
		return;

	mutex_lock(&psi->read_mutex);
	if (psi->open && psi->open(psi))
		goto out;

	while ((size = psi->read(&id, &type, &count, &time, &buf, psi)) > 0) {
		rc = pstore_mkfile(type, psi->name, id, count, buf,
				  (size_t)size, time, psi);
		kfree(buf);
		buf = NULL;
		if (rc && (rc != -EEXIST || !quiet))
			failed++;
	}
	if (psi->close)
		psi->close(psi);
out:
	mutex_unlock(&psi->read_mutex);

	if (failed)
		printk(KERN_WARNING "pstore: failed to load %d record(s) from '%s'\n",
		       failed, psi->name);
}

static void pstore_dowork(struct work_struct *work)
{
	pstore_get_records(1);
}

static void pstore_timefunc(unsigned long dummy)
{
	if (pstore_new_entry) {
		pstore_new_entry = 0;
		schedule_work(&pstore_work);
	}

	mod_timer(&pstore_timer, jiffies + msecs_to_jiffies(pstore_update_ms));
}

/* pstore_write must only be called from PSTORE_DUMP notifier callbacks */
int pstore_write(enum pstore_type_id type, const char *buf, size_t size)
{
	size_t len;
	int err = 0, err2;

	if (!psinfo)
		return -ENODEV;

	/*
	 * No locking is needed because pstore_write is called only from
	 * PSTORE_DUMP notifier callbacks.
	 */

	if (type != psinfo->ext_type) {
		err = pstore_ext_flush();
		psinfo->ext_type = type;
		psinfo->ext_part = 1;
	}

	while (size) {
		len = min(size, psinfo->bufsize - psinfo->ext_len);
		memcpy(psinfo->buf + psinfo->ext_len, buf, len);
		psinfo->ext_len += len;
		buf += len;
		size -= len;
		if (psinfo->ext_len == psinfo->bufsize) {
			err2 = pstore_ext_flush();
			if (err2 && !err)
				err = err2;
		}
	}

	return err;
}
EXPORT_SYMBOL_GPL(pstore_write);

module_param(backend, charp, 0444);
MODULE_PARM_DESC(backend, "Pstore backend to use");
