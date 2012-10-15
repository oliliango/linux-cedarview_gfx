/*
 * Persistent Storage task dumper
 *
 * Copyright (C) 2012 Intel Corporation
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

#include <linux/module.h>
#include <linux/console.h>
#include <linux/sched.h>
#include <linux/hardirq.h>
#include <linux/delay.h>
#include <linux/pstore.h>

static int enabled;

static void pstore_dump_tasks(struct console *console, const char *s,
			      unsigned int count)
{
	pstore_write(PSTORE_TYPE_TASK_DUMP, s, count);
}

static struct console pstore_dump_tasks_console = {
	.name	= "dump_tasks",
	.write	= pstore_dump_tasks,
	.flags	= CON_ANYTIME | CON_ENABLED,
	.index	= -1,
};

static int pstore_notifier_cb(struct notifier_block *nb, unsigned long event,
			      void *_psinfo)
{
	struct pstore_info *psinfo = _psinfo;
	int retry;

	if (psinfo->ext_reason != KMSG_DUMP_PANIC || !enabled)
		return NOTIFY_DONE;

	switch (event) {
	case PSTORE_DUMP:
		pstore_dump_tasks_console.flags |= CON_ENABLED;
		show_state();

		/* Make sure data gets pushed to console drivers.
		 * Yes, can take a long time to write everything,
		 * shortening the length increases the chances of
		 * ending up with an incomplete log.
		 */
		retry = 100;
		while (retry) {
			if (console_trylock()) {
				console_unlock();
				break;
			} else {
				mdelay(100);
				retry--;
			}
		}

		break;
	case PSTORE_END:
		pstore_dump_tasks_console.flags &= ~CON_ENABLED;
	}

	return NOTIFY_DONE;
}

static struct notifier_block pstore_notifier = {
	.notifier_call = pstore_notifier_cb,
	/* Leave other dumpers do their job. This one can take longer. */
	.priority = -1,
};

static int __init pstore_dump_tasks_init(void)
{
	register_console(&pstore_dump_tasks_console);
	console_stop(&pstore_dump_tasks_console);
	pstore_notifier_register(&pstore_notifier);
	return 0;
}
module_init(pstore_dump_tasks_init);

static void __exit pstore_dump_tasks_exit(void)
{
	pstore_notifier_unregister(&pstore_notifier);
	unregister_console(&pstore_dump_tasks_console);
}
module_exit(pstore_dump_tasks_exit);

module_param(enabled, int,  S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(enabled, "set to 1 to enable task dump, 0 to disable (default 0)");

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Adrian Hunter");
MODULE_DESCRIPTION("Persistent Storage task dumper");
