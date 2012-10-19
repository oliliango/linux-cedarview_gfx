/*
 * cpufreq_snb.c: Native P state management for Intel processors
 *
 * (C) Copyright 2012 Intel Corporation
 * Author: Dirk Brandewie <dirk.j.brandewie@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */



#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/tick.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/cpufreq.h>
#include <linux/sysfs.h>
#include <linux/types.h>

#include <trace/events/power.h>

#include <asm/div64.h>
#include <asm/msr.h>
#include <asm/cpu_device_id.h>

#define SAMPLE_COUNT		3

struct sampling_state {
	int idle_mode;
	int first_sample;
};

struct sample {
	ktime_t start_time;
	ktime_t end_time;
	int core_pct_busy;
	int freq_pct_busy;
	u64 duration_us;
	u64 idletime_us;
	u64 aperf;
	u64 mperf;
};

struct freqdata {
	int	current_freq;
	int	min_freq;
	int	max_freq;
	int	turbo_freq;
};

struct _pid {
	int setpoint;
	int32_t integral;
	int32_t p_gain;
	int32_t i_gain;
	int32_t d_gain;
	int deadband;
	int last_err;
};

struct cpudata {
	int cpu;

	char name[64];

	struct timer_list timer;

	struct freq_adjust_policy *freq_policy;
	struct freqdata clock;
	struct sampling_state sampling_state;
	struct _pid pid;
	struct _pid idle_pid;

	int min_freq_count;

	ktime_t prev_sample;
	u64	prev_idle_time_us;
	u64	prev_aperf;
	u64	prev_mperf;
	int	sample_ptr;
	struct sample samples[SAMPLE_COUNT];
};

static unsigned int snb_usage;
static DEFINE_MUTEX(snb_mutex);

struct cpudata **all_cpu_data;
struct freq_adjust_policy {
	int sample_rate_ms;    /* sample rate */
	int deadband; /*adjust freq on last sample or average */
	int setpoint; /* starting freq when we have no info */
	int p_gain_pct;
	int d_gain_pct;
	int i_gain_pct;
};

struct freq_adjust_policy default_policy = {
	.sample_rate_ms = 10,
	.deadband = 0,
	.setpoint = 110,
	.p_gain_pct = 17,
	.d_gain_pct = 0,
	.i_gain_pct = 4,
};

#define FRAC_BITS 8
#define int_tofp(X) ((int64_t)(X) << FRAC_BITS)
#define fp_toint(X) ((X) >> FRAC_BITS)

static inline int32_t mul_fp(int32_t x, int32_t y)
{
	return ((int64_t)x * (int64_t)y) >> FRAC_BITS;
}

static inline int32_t div_fp(int32_t x, int32_t y)
{
	return div_s64((int64_t)x << FRAC_BITS, (int64_t)y);
}


static inline void pid_reset(struct _pid *pid, int setpoint, int busy,
			int deadband, int integral) {
	pid->setpoint = setpoint;
	pid->deadband  = deadband;
	pid->integral  = int_tofp(integral);
	pid->last_err  = setpoint - busy;
}

static inline void pid_p_gain_set(struct _pid *pid, int percent)
{
	pid->p_gain = div_fp(int_tofp(percent), int_tofp(100));
}

static inline void pid_i_gain_set(struct _pid *pid, int percent)
{
	pid->i_gain = div_fp(int_tofp(percent), int_tofp(100));
}

static inline void pid_d_gain_set(struct _pid *pid, int percent)
{

	pid->d_gain = div_fp(int_tofp(percent), int_tofp(100));
}

static inline int pid_calc(struct _pid *pid, int busy)
{
	int err, result;
	int32_t pterm, dterm, fp_error;
	int32_t integral_limit;

	integral_limit = int_tofp(30);
	err = pid->setpoint - busy;

	if (abs(err) <= pid->deadband)
		return 0;

	fp_error = int_tofp(err);
	pterm = mul_fp(pid->p_gain, fp_error);
	pid->integral += mul_fp(pid->i_gain, fp_error);

	/* limit the integral term */
	if (pid->integral > integral_limit)
		pid->integral = integral_limit;
	if (pid->integral < -integral_limit)
		pid->integral = -integral_limit;

	dterm = mul_fp(pid->d_gain, (err - pid->last_err));
	result = pterm + pid->integral + dterm;

	pid->last_err = err;
	return fp_toint(result);
}


static inline void snb_busy_pid_reset(struct cpudata *cpu)
{
	pid_reset(&cpu->pid,
		cpu->freq_policy->setpoint,
		100,
		cpu->freq_policy->deadband,
		0);

	pid_p_gain_set(&cpu->pid, cpu->freq_policy->p_gain_pct);
	pid_d_gain_set(&cpu->pid, cpu->freq_policy->d_gain_pct);
	pid_i_gain_set(&cpu->pid, cpu->freq_policy->i_gain_pct);
}

static inline void snb_idle_pid_reset(struct cpudata *cpu)
{
	pid_reset(&cpu->idle_pid,
		75,
		50,
		cpu->freq_policy->deadband,
		0);

	pid_p_gain_set(&cpu->idle_pid, cpu->freq_policy->p_gain_pct);
	pid_d_gain_set(&cpu->idle_pid, cpu->freq_policy->d_gain_pct);
	pid_i_gain_set(&cpu->idle_pid, cpu->freq_policy->i_gain_pct);
}

static inline void snb_reset_all_pid(void)
{
	unsigned int cpu;
	for_each_online_cpu(cpu) {
		if (all_cpu_data[cpu])
			snb_busy_pid_reset(all_cpu_data[cpu]);
	}
}

/************************** sysfs begin ************************/
#define show_one(file_name, object)					\
	static ssize_t show_##file_name					\
	(struct kobject *kobj, struct attribute *attr, char *buf)	\
	{								\
		return sprintf(buf, "%u\n", default_policy.object);	\
	}

static ssize_t store_sample_rate_ms(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	default_policy.sample_rate_ms = input;
	snb_reset_all_pid();
	return count;
}

static ssize_t store_d_gain_pct(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	default_policy.d_gain_pct = input;
	snb_reset_all_pid();

	return count;
}

static ssize_t store_i_gain_pct(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	default_policy.i_gain_pct = input;
	snb_reset_all_pid();

	return count;
}

static ssize_t store_deadband(struct kobject *a, struct attribute *b,
			const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	default_policy.deadband = input;
	snb_reset_all_pid();

	return count;
}

static ssize_t store_setpoint(struct kobject *a, struct attribute *b,
			const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	default_policy.setpoint = input;
	snb_reset_all_pid();

	return count;
}

static ssize_t store_p_gain_pct(struct kobject *a, struct attribute *b,
				const char *buf, size_t count)
{
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	default_policy.p_gain_pct = input;
	snb_reset_all_pid();

	return count;
}

show_one(sample_rate_ms, sample_rate_ms);
show_one(d_gain_pct, d_gain_pct);
show_one(i_gain_pct, i_gain_pct);
show_one(deadband, deadband);
show_one(setpoint, setpoint);
show_one(p_gain_pct, p_gain_pct);


define_one_global_rw(sample_rate_ms);
define_one_global_rw(d_gain_pct);
define_one_global_rw(i_gain_pct);
define_one_global_rw(deadband);
define_one_global_rw(setpoint);
define_one_global_rw(p_gain_pct);


static struct attribute *snb_attributes[] = {
	&sample_rate_ms.attr,
	&d_gain_pct.attr,
	&i_gain_pct.attr,
	&deadband.attr,
	&setpoint.attr,
	&p_gain_pct.attr,
	NULL
};

static struct attribute_group snb_attr_group = {
	.attrs = snb_attributes,
	.name = "snb",
};

/************************** sysfs end ************************/

static int snb_get_min_freq(void)
{
	u64 value;
	rdmsrl(0xCE, value);
	return (value >> 40) & 0xFF;
}

static int snb_get_max_freq(void)
{
	u64 value;
	rdmsrl(0xCE, value);
	return (value >> 8) & 0xFF;
}

static int snb_get_turbo_freq(void)
{
	u64 value;
	int nont, ret;
	rdmsrl(0x1AD, value);
	nont = snb_get_max_freq();
	ret = ((value) & 255);
	if (ret <= nont)
		ret = nont;
	return ret;
}


static void snb_set_freq(struct cpudata *cpu, int clock)
{
	clock = clamp_t(int, clock, cpu->clock.min_freq, cpu->clock.turbo_freq);

	if (clock == cpu->clock.current_freq)
		return;

#ifndef MODULE
	trace_cpu_frequency(clock * 100000, cpu->cpu);
	trace_power_frequency(POWER_PSTATE, clock * 100000, cpu->cpu);
#endif

	cpu->clock.current_freq = clock;
	wrmsrl(MSR_IA32_PERF_CTL, clock << 8);
}

static inline void snb_freq_increase(struct cpudata *cpu, int steps)
{
	int target;
	target = cpu->clock.current_freq + steps;

	snb_set_freq(cpu, target);
}

static inline void snb_freq_decrease(struct cpudata *cpu, int steps)
{
	int target;
	target = cpu->clock.current_freq - steps;
	snb_set_freq(cpu, target);
}

static void snb_get_cpu_freqs(struct cpudata *cpu)
{
	sprintf(cpu->name, "Intel 2nd generation core");

	cpu->clock.min_freq = snb_get_min_freq();
	cpu->clock.max_freq = snb_get_max_freq();
	cpu->clock.turbo_freq = snb_get_turbo_freq();

	/* goto max clock so we don't slow up boot if we are built-in
	   if we are a module we will take care of it during normal
	   operation
	*/
	snb_set_freq(cpu, cpu->clock.max_freq);
}


static inline void snb_calc_busy(struct cpudata *cpu, struct sample *sample)
{
	u64 ta, tm;

	sample->freq_pct_busy = div64_u64(sample->idletime_us * 100,
				sample->duration_us);

	ta = sample->aperf;
	tm = sample->mperf;

	ta <<= 8;
	do_div(ta, tm);

	sample->core_pct_busy = ((100 - sample->freq_pct_busy) * (ta) >> 8);
}

static inline int snb_sample(struct cpudata *cpu)
{
	ktime_t now;
	u64 idle_time_us;
	u64 aperf, mperf;

	now = ktime_get();
	idle_time_us = get_cpu_idle_time_us(cpu->cpu, NULL);

	rdmsrl(MSR_IA32_APERF, aperf);
	rdmsrl(MSR_IA32_APERF, mperf);
	/* for the first sample, don't actually record a sample, just
	 * set the baseline */
	if (cpu->prev_idle_time_us > 0) {
		cpu->sample_ptr = (cpu->sample_ptr + 1) % SAMPLE_COUNT;
		cpu->samples[cpu->sample_ptr].start_time = cpu->prev_sample;
		cpu->samples[cpu->sample_ptr].end_time = now;
		cpu->samples[cpu->sample_ptr].duration_us =
			ktime_us_delta(now, cpu->prev_sample);
		cpu->samples[cpu->sample_ptr].idletime_us =
			idle_time_us - cpu->prev_idle_time_us;

		cpu->samples[cpu->sample_ptr].aperf = aperf;
		cpu->samples[cpu->sample_ptr].mperf = mperf;
		cpu->samples[cpu->sample_ptr].aperf -= cpu->prev_aperf;
		cpu->samples[cpu->sample_ptr].mperf -= cpu->prev_mperf;

		snb_calc_busy(cpu, &cpu->samples[cpu->sample_ptr]);
	}

	cpu->prev_sample = now;
	cpu->prev_idle_time_us = idle_time_us;
	cpu->prev_aperf = aperf;
	cpu->prev_mperf = mperf;
	return cpu->sample_ptr;
}

static inline void snb_set_sample_time(struct cpudata *cpu)
{
	int sample_time;
	int delay;

	sample_time = cpu->freq_policy->sample_rate_ms;
	delay = msecs_to_jiffies(sample_time);
	delay -= jiffies % delay;
	mod_timer(&cpu->timer, jiffies + delay);
}

static inline void snb_idle_mode(struct cpudata *cpu)
{
	cpu->sampling_state.idle_mode = 1;
}

static inline void snb_normal_mode(struct cpudata *cpu)
{
	cpu->sampling_state.idle_mode = 0;
}

static inline int snb_get_scaled_busy(struct cpudata *cpu)
{
	int32_t busy_scaled;
	int32_t core_busy, turbo_freq, current_freq;

	core_busy    = int_tofp(cpu->samples[cpu->sample_ptr].core_pct_busy);
	turbo_freq   = int_tofp(cpu->clock.turbo_freq);
	current_freq = int_tofp(cpu->clock.current_freq);
	busy_scaled = mul_fp(core_busy, div_fp(turbo_freq, current_freq));

	return fp_toint(busy_scaled);
}

static inline void snb_adjust_busy_freq(struct cpudata *cpu)
{
	int busy_scaled;
	struct _pid *pid;
	int ctl = 0;
	int steps;

	pid = &cpu->pid;

	busy_scaled =  snb_get_scaled_busy(cpu);

	ctl = pid_calc(pid, busy_scaled);

	steps = abs(ctl);
	if (ctl < 0)
		snb_freq_increase(cpu, steps);
	else
		snb_freq_decrease(cpu, steps);
}

static inline void snb_adjust_idle_freq(struct cpudata *cpu)
{
	int busy_scaled;
	struct _pid *pid;
	int ctl = 0;
	int steps;

	pid = &cpu->idle_pid;

	busy_scaled =  snb_get_scaled_busy(cpu);

	ctl = pid_calc(pid, 100 - busy_scaled);

	steps = abs(ctl);
	if (ctl < 0)
		snb_freq_decrease(cpu, steps);
	else
		snb_freq_increase(cpu, steps);

	if (cpu->clock.current_freq == cpu->clock.min_freq)
		snb_normal_mode(cpu);
}
static inline int snb_valid_sample(struct cpudata *cpu, int idx)
{
	struct sample *sample = &cpu->samples[idx];

	return sample->duration_us <
		(cpu->freq_policy->sample_rate_ms * USEC_PER_MSEC  * 2);
}

static void snb_timer_func(unsigned long __data)
{
	struct cpudata *cpu = (struct cpudata *) __data;
	struct freq_adjust_policy *policy;
	int idx;

	policy = cpu->freq_policy;

	idx = snb_sample(cpu);

	if (snb_valid_sample(cpu, idx)) {
		if (!cpu->sampling_state.idle_mode)
			snb_adjust_busy_freq(cpu);
		else
			snb_adjust_idle_freq(cpu);
	}

#if defined(XPERF_FIX)
	if (cpu->clock.current_freq == cpu->clock.min_freq) {
		cpu->min_freq_count++;
		if (!(cpu->min_freq_count % 5)) {
			snb_set_freq(cpu, cpu->clock.max_freq);
			snb_idle_mode(cpu);
		}
	} else
		cpu->min_freq_count = 0;
#endif
	snb_set_sample_time(cpu);
}

static void snb_exit(unsigned int cpu)
{
	if (!all_cpu_data)
		return;

	if (all_cpu_data[cpu]) {
		del_timer_sync(&all_cpu_data[cpu]->timer);
		kfree(all_cpu_data[cpu]);
	}
}

#define ICPU(model, policy) \
	{ X86_VENDOR_INTEL, 6, model, X86_FEATURE_ANY, (unsigned long)&policy }

static const struct x86_cpu_id intel_cpufreq_ids[] = {
	ICPU(0x2a, default_policy),
	ICPU(0x2d, default_policy),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, intel_cpufreq_ids);

static int snb_init(unsigned int cpu)
{
	int rc;
	const struct x86_cpu_id *id;

	id = x86_match_cpu(intel_cpufreq_ids);
	if (!id)
		return -ENODEV;

	all_cpu_data[cpu] = kzalloc(sizeof(struct cpudata), GFP_KERNEL);
	if (!all_cpu_data[cpu]) {
		rc = -ENOMEM;
		goto unwind;
	}

	snb_get_cpu_freqs(all_cpu_data[cpu]);

	all_cpu_data[cpu]->cpu = cpu;
	all_cpu_data[cpu]->freq_policy =
		(struct freq_adjust_policy *)id->driver_data;
	init_timer_deferrable(&all_cpu_data[cpu]->timer);
	all_cpu_data[cpu]->timer.function = snb_timer_func;
	all_cpu_data[cpu]->timer.data =
		(unsigned long)all_cpu_data[cpu];
	all_cpu_data[cpu]->timer.expires = jiffies + HZ/100;
	snb_busy_pid_reset(all_cpu_data[cpu]);
	snb_idle_pid_reset(all_cpu_data[cpu]);
	pr_info("snb: enabling %d\n", cpu);
	add_timer_on(&all_cpu_data[cpu]->timer, cpu);
	return 0;

unwind:
	snb_exit(cpu);
	return -ENODEV;
}

/**
 * cpufreq_set - set the CPU frequency
 * @policy: pointer to policy struct where freq is being set
 * @freq: target frequency in kHz
 *
 * Sets the CPU frequency to freq.
 */
static int cpufreq_snb_set(struct cpufreq_policy *policy, unsigned int freq)
{
	int ret = 0;
	return ret;
}


static ssize_t cpufreq_snb_show_speed(struct cpufreq_policy *policy, char *buf)
{
	return 0;
}

static int cpufreq_snb(struct cpufreq_policy *policy,
				   unsigned int event)
{
	unsigned int cpu = policy->cpu;
	int rc = 0;

	switch (event) {
	case CPUFREQ_GOV_START:
		if (!cpu_online(cpu))
			return -EINVAL;
		mutex_lock(&snb_mutex);
		snb_usage++;
		rc = snb_init(cpu);

		if (snb_usage == 1)
			rc = sysfs_create_group(cpufreq_global_kobject,
						&snb_attr_group);

		mutex_unlock(&snb_mutex);
		break;
	case CPUFREQ_GOV_STOP:
		mutex_lock(&snb_mutex);
		snb_usage--;
		snb_exit(cpu);
		if (!snb_usage)
			sysfs_remove_group(cpufreq_global_kobject,
					&snb_attr_group);

		mutex_unlock(&snb_mutex);
		break;
	case CPUFREQ_GOV_LIMITS:
		mutex_lock(&snb_mutex);
		mutex_unlock(&snb_mutex);
		break;
	}
	return rc;
}

static struct cpufreq_governor cpufreq_gov_snb = {
	.name		= "snb",
	.governor	= cpufreq_snb,
	.store_setspeed	= cpufreq_snb_set,
	.show_setspeed	= cpufreq_snb_show_speed,
	.owner		= THIS_MODULE,
};

static int __init cpufreq_gov_snb_init(void)
{
	pr_info("Sandybridge frequency driver initializing.\n");

	all_cpu_data = vmalloc(sizeof(void *) * num_possible_cpus());
	if (!all_cpu_data)
		return -ENOMEM;
	memset(all_cpu_data, 0, sizeof(void *) * num_possible_cpus());


	return cpufreq_register_governor(&cpufreq_gov_snb);
}

static void __exit cpufreq_gov_snb_exit(void)
{
	vfree(all_cpu_data);
	all_cpu_data = NULL;
	cpufreq_unregister_governor(&cpufreq_gov_snb);
}


MODULE_AUTHOR("Dirk Brandewie <dirk.j.brandewie@intel.com>");
MODULE_DESCRIPTION("'cpufreq_snb' - cpufreq governor for Sandy Bridge");
MODULE_LICENSE("GPL");


fs_initcall(cpufreq_gov_snb_init);
module_exit(cpufreq_gov_snb_exit);
