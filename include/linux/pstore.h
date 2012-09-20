/*
 * Persistent Storage - pstore.h
 *
 * Copyright (C) 2010 Intel Corporation <tony.luck@intel.com>
 *
 * This code is the generic layer to export data records from platform
 * level persistent storage via a file system.
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
#ifndef _LINUX_PSTORE_H
#define _LINUX_PSTORE_H

#include <linux/time.h>
#include <linux/kmsg_dump.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/errno.h>

/* types */
enum pstore_type_id {
	PSTORE_TYPE_DMESG	= 0,
	PSTORE_TYPE_MCE		= 1,
	PSTORE_TYPE_CONSOLE	= 2,
	PSTORE_TYPE_FTRACE	= 3,
	PSTORE_TYPE_TASK_DUMP	= 4,
	PSTORE_TYPE_UNKNOWN	= 255
};

struct module;

/* Notifier events */
#define PSTORE_BEGIN		1
#define PSTORE_DUMP		2
#define PSTORE_END		3

#define PSTORE_NO_HEADINGS	BIT(0)
#define PSTORE_MAX_KMSG_BYTES	BIT(1)

struct pstore_info {
	struct module		*owner;
	char			*name;
	unsigned int		flags;
	spinlock_t		buf_lock;	/* serialize access to 'buf' */
	char			*buf;
	size_t			bufsize;
	struct mutex		read_mutex;	/* serialize open/read/close */
	u64			ext_id;
	size_t			ext_len;
	unsigned int		ext_part;
	enum pstore_type_id	ext_type;
	enum kmsg_dump_reason	ext_reason;
	int		(*open)(struct pstore_info *psi);
	int		(*close)(struct pstore_info *psi);
	ssize_t		(*read)(u64 *id, enum pstore_type_id *type,
			int *count, struct timespec *time, char **buf,
			struct pstore_info *psi);
	int		(*write)(enum pstore_type_id type,
			enum kmsg_dump_reason reason, u64 *id,
			unsigned int part, int count, size_t size,
			struct pstore_info *psi);
	int		(*write_buf)(enum pstore_type_id type,
			enum kmsg_dump_reason reason, u64 *id,
			unsigned int part, const char *buf, size_t size,
			struct pstore_info *psi);
	int		(*erase)(enum pstore_type_id type, u64 id,
			int count, struct timespec time,
			struct pstore_info *psi);
	void		*data;
};

#ifdef CONFIG_PSTORE
extern int pstore_register(struct pstore_info *);
extern int pstore_notifier_register(struct notifier_block *n);
extern int pstore_notifier_unregister(struct notifier_block *n);
/* pstore_write must only be called from PSTORE_DUMP notifier callbacks */
extern int pstore_write(enum pstore_type_id type, const char *buf, size_t size);
#else
static inline int
pstore_register(struct pstore_info *psi)
{
	return -ENODEV;
}
static inline int
pstore_notifier_register(struct notifier_block *n)
{
	return 0;
}
static inline int
pstore_notifier_unregister(struct notifier_block *n)
{
	return 0;
}
static inline int
pstore_write(enum pstore_type_id type, const char *buf, size_t size)
{
	return 0;
}
#endif

#endif /*_LINUX_PSTORE_H*/
