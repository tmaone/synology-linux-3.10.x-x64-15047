/*
 * originally written by: Kirk Reiser <kirk@braille.uwo.ca>
* this version considerably modified by David Borowski, david575@rogers.com
 *
 * Copyright (C) 1998-99  Kirk Reiser.
 * Copyright (C) 2003 David Borowski.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * this code is specificly written as a driver for the speakup screenreview
 * package and is not a general device driver.
 */

#include "spk_priv.h"
#include "speakup.h"
#include "speakup_acnt.h" /* local header file for Accent values */

#define DRV_VERSION "2.11"
#define PROCSPEECH '\r'

static int synth_probe(struct spk_synth *synth);

static struct var_t vars[] = {
	{ CAPS_START, .u.s = {"\033P8" } },
	{ CAPS_STOP, .u.s = {"\033P5" } },
	{ RATE, .u.n = {"\033R%c", 9, 0, 17, 0, 0, "0123456789abcdefgh" } },
	{ PITCH, .u.n = {"\033P%d", 5, 0, 9, 0, 0, NULL } },
	{ VOL, .u.n = {"\033A%d", 9, 0, 9, 0, 0, NULL } },
	{ TONE, .u.n = {"\033V%d", 5, 0, 9, 0, 0, NULL } },
	{ DIRECT, .u.n = {NULL, 0, 0, 1, 0, 0, NULL } },
	V_LAST_VAR
};

/*
 * These attributes will appear in /sys/accessibility/speakup/acntsa.
 */
static struct kobj_attribute caps_start_attribute =
	__ATTR(caps_start, USER_RW, spk_var_show, spk_var_store);
static struct kobj_attribute caps_stop_attribute =
	__ATTR(caps_stop, USER_RW, spk_var_show, spk_var_store);
static struct kobj_attribute pitch_attribute =
	__ATTR(pitch, USER_RW, spk_var_show, spk_var_store);
static struct kobj_attribute rate_attribute =
	__ATTR(rate, USER_RW, spk_var_show, spk_var_store);
static struct kobj_attribute tone_attribute =
	__ATTR(tone, USER_RW, spk_var_show, spk_var_store);
static struct kobj_attribute vol_attribute =
	__ATTR(vol, USER_RW, spk_var_show, spk_var_store);

static struct kobj_attribute delay_time_attribute =
	__ATTR(delay_time, ROOT_W, spk_var_show, spk_var_store);
static struct kobj_attribute direct_attribute =
	__ATTR(direct, USER_RW, spk_var_show, spk_var_store);
static struct kobj_attribute full_time_attribute =
	__ATTR(full_time, ROOT_W, spk_var_show, spk_var_store);
static struct kobj_attribute jiffy_delta_attribute =
	__ATTR(jiffy_delta, ROOT_W, spk_var_show, spk_var_store);
static struct kobj_attribute trigger_time_attribute =
	__ATTR(trigger_time, ROOT_W, spk_var_show, spk_var_store);

/*
 * Create a group of attributes so that we can create and destroy them all
 * at once.
 */
static struct attribute *synth_attrs[] = {
	&caps_start_attribute.attr,
	&caps_stop_attribute.attr,
	&pitch_attribute.attr,
	&rate_attribute.attr,
	&tone_attribute.attr,
	&vol_attribute.attr,
	&delay_time_attribute.attr,
	&direct_attribute.attr,
	&full_time_attribute.attr,
	&jiffy_delta_attribute.attr,
	&trigger_time_attribute.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct spk_synth synth_acntsa = {
	.name = "acntsa",
	.version = DRV_VERSION,
	.long_name = "Accent-SA",
	.init = "\033T2\033=M\033Oi\033N1\n",
	.procspeech = PROCSPEECH,
	.clear = SYNTH_CLEAR,
	.delay = 400,
	.trigger = 50,
	.jiffies = 30,
	.full = 40000,
	.startup = SYNTH_START,
	.checkval = SYNTH_CHECK,
	.vars = vars,
	.probe = synth_probe,
	.release = spk_serial_release,
	.synth_immediate = spk_synth_immediate,
	.catch_up = spk_do_catch_up,
	.flush = spk_synth_flush,
	.is_alive = spk_synth_is_alive_restart,
	.synth_adjust = NULL,
	.read_buff_add = NULL,
	.get_index = NULL,
	.indexing = {
		.command = NULL,
		.lowindex = 0,
		.highindex = 0,
		.currindex = 0,
	},
	.attributes = {
		.attrs = synth_attrs,
		.name = "acntsa",
	},
};

static int synth_probe(struct spk_synth *synth)
{
	int failed;

	failed = spk_serial_synth_probe(synth);
	if (failed == 0) {
		spk_synth_immediate(synth, "\033=R\r");
		mdelay(100);
	}
	synth->alive = !failed;
	return failed;
}

module_param_named(ser, synth_acntsa.ser, int, S_IRUGO);
module_param_named(start, synth_acntsa.startup, short, S_IRUGO);

MODULE_PARM_DESC(ser, "Set the serial port for the synthesizer (0-based).");
MODULE_PARM_DESC(start, "Start the synthesizer once it is loaded.");

static int __init acntsa_init(void)
{
	return synth_add(&synth_acntsa);
}

static void __exit acntsa_exit(void)
{
	synth_remove(&synth_acntsa);
}

module_init(acntsa_init);
module_exit(acntsa_exit);
MODULE_AUTHOR("Kirk Reiser <kirk@braille.uwo.ca>");
MODULE_AUTHOR("David Borowski");
MODULE_DESCRIPTION("Speakup support for Accent SA synthesizer");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
