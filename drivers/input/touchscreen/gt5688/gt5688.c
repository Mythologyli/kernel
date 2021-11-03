/* drivers/input/touchscreen/gt5688.c
 *
 * 2010 - 2014 Goodix Technology.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be a reference
 * to you, when you are integrating the GOODiX's CTP IC into your system,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Version: 1.4
 * Release Date:  2015/07/10
 */

#include <linux/irq.h>
#include "gt5688.h"
#include <linux/input/mt.h>

static struct work_struct gt5688_work;
static struct input_dev *input_dev;
static struct workqueue_struct *gt5688_wq;
static const char *gt5688_ts_name = "goodix-ts";
static const char *input_dev_phys = "input/ts";
#ifdef CONFIG_PM
static const struct dev_pm_ops gt5688_ts_pm_ops;
#endif

#ifdef GTP_CONFIG_OF
bool gt5688_gt5688;
int gt5688_rst_gpio;
int gt5688_int_gpio;
int gt5688_enable_gpio;
#endif

static int gt5688_register_powermanger(void);
static int gt5688_unregister_powermanger(void);

/**
 * gt5688_i2c_write - i2c write.
 * @addr: register address.
 * @buffer: data buffer.
 * @len: the bytes of data to write.
 *Return: 0: success, otherwise: failed
 */
s32 gt5688_i2c_write(u16 addr, u8 *buffer, s32 len)
{
	struct i2c_msg msg = {
		.flags = 0,
		.addr = gt5688_i2c_client->addr,
	};
	return gt5688_do_i2c_write(&msg, addr, buffer, len);
}

/**
 * gt5688_i2c_read - i2c read.
 * @addr: register address.
 * @buffer: data buffer.
 * @len: the bytes of data to write.
 *Return: 0: success, otherwise: failed
 */
s32 gt5688_i2c_read(u16 addr, u8 *buffer, s32 len)
{
	u8 addr_buf[GTP_ADDR_LENGTH] = { (addr >> 8) & 0xFF, addr & 0xFF };
	struct i2c_msg msgs[2] = {
		{
		 .addr = gt5688_i2c_client->addr,
		 .flags = 0,
		 .buf = addr_buf,
		 .len = GTP_ADDR_LENGTH},
		{
		 .addr = gt5688_i2c_client->addr,
		 .flags = I2C_M_RD}
	};
	return gt5688_do_i2c_read(msgs, addr, buffer, len);
}

static spinlock_t irq_lock;
static s32 irq_is_disable;

/**
 * gt5688_irq_enable - enable irq function.
 *
 */
void gt5688_irq_enable(void)
{
	unsigned long irqflags = 0;

	GTP_DEBUG_FUNC();

	spin_lock_irqsave(&irq_lock, irqflags);
	if (irq_is_disable) {
		enable_irq(gt5688_i2c_client->irq);
		irq_is_disable = 0;
	}
	spin_unlock_irqrestore(&irq_lock, irqflags);
}

/**
 * gt5688_irq_enable - disable irq function.
 *
 */
void gt5688_irq_disable(void)
{
	unsigned long irqflags;

	GTP_DEBUG_FUNC();

	spin_lock_irqsave(&irq_lock, irqflags);
	if (!irq_is_disable) {
		irq_is_disable = 1;
		disable_irq_nosync(gt5688_i2c_client->irq);
	}
	spin_unlock_irqrestore(&irq_lock, irqflags);
}

#ifndef GTP_CONFIG_OF
int gt5688_power_switch(s32 state)
{
    return 0;
}
#endif

int gt5688_debug_proc(u8 *buf, int count)
{
	return -1;
}

#if GTP_CHARGER_SWITCH
u32 gt5688_get_charger_status(void)
{
#error Need to get charger status of your platform.
}
#endif

/**
 * gt5688_ts_irq_handler - External interrupt service routine for interrupt mode.
 * @irq:  interrupt number.
 * @dev_id: private data pointer.
 * Return: Handle Result.
 *  		IRQ_HANDLED: interrupt handled successfully
 */
static irqreturn_t gt5688_ts_irq_handler(int irq, void *dev_id)
{
	GTP_DEBUG_FUNC();
	gt5688_irq_disable();
	queue_work(gt5688_wq, &gt5688_work);
	return IRQ_HANDLED;
}

/**
 * gt5688_touch_down - Report touch point event .
 * @id: trackId
 * @x:  input x coordinate
 * @y:  input y coordinate
 * @w:  input pressure
 * Return: none.
 */
void gt5688_touch_down(s32 x, s32 y, s32 size, s32 id)
{
#if GTP_CHANGE_X2Y
	GTP_SWAP(x, y);
#endif
	y = gt5688_abs_y_max - y;
	x = gt5688_abs_x_max - x;

	if (gt5688_ics_slot_report) {
		input_mt_slot(input_dev, id);
		input_report_abs(input_dev, ABS_MT_PRESSURE, size);
		input_report_abs(input_dev, ABS_MT_TOUCH_MAJOR, size);
		input_report_abs(input_dev, ABS_MT_TRACKING_ID, id);
		input_report_abs(input_dev, ABS_MT_POSITION_X, x);
		input_report_abs(input_dev, ABS_MT_POSITION_Y, y);
	} else {
		input_report_key(input_dev, BTN_TOUCH, 1);

		if ((!size) && (!id)) {
			/* for virtual button */
			input_report_abs(input_dev, ABS_MT_PRESSURE, 100);
			input_report_abs(input_dev, ABS_MT_TOUCH_MAJOR, 100);
		} else {
			input_report_abs(input_dev, ABS_MT_PRESSURE, size);
			input_report_abs(input_dev, ABS_MT_TOUCH_MAJOR, size);
			input_report_abs(input_dev, ABS_MT_TRACKING_ID, id);
		}
		input_report_abs(input_dev, ABS_MT_POSITION_X, x);
		input_report_abs(input_dev, ABS_MT_POSITION_Y, y);
		input_mt_sync(input_dev);

	}
}

/**
 * gt5688_touch_up -  Report touch release event.
 * @id: trackId
 * Return: none.
 */
void gt5688_touch_up(s32 id)
{
	if (gt5688_ics_slot_report) {
		input_mt_slot(input_dev, id);
		input_report_abs(input_dev, ABS_MT_TRACKING_ID, -1);
	} else {
		input_report_key(input_dev, BTN_TOUCH, 0);
		input_mt_sync(input_dev);
	}
}

/**
 * gt5688_ts_work_func - Goodix touchscreen work function.
 * @iwork: work struct of gt5688_workqueue.
 * Return: none.
 */
static void gt5688_ts_work_func(struct work_struct *work)
{
	u8 end_cmd = 0;
	u8 finger = 0;
	s32 ret = 0;
	u8 point_data[11] = { 0 };

	if (gt5688_update_info.status) {
		GTP_DEBUG("Ignore interrupts during fw update.");
		return;
	}

#if GTP_GESTURE_WAKEUP
	ret = gesture_event_handler(input_dev);
	if (ret >= 0) {
		goto exit_work_func;
	}
#endif

	if (gt5688_halt) {
		GTP_DEBUG("Ignore interrupts after suspend...");
		return;
	}

	ret = gt5688_i2c_read(GTP_READ_COOR_ADDR, point_data, sizeof(point_data));
	if (ret < 0) {
		GTP_ERROR("I2C transfer error!");
#if !GTP_ESD_PROTECT
		gt5688_power_reset();
#endif
		goto exit_work_func;
	}

	finger = point_data[0];
	if (finger == 0x00) {
		gt5688_request_event_handler();
	}

	if ((finger & 0x80) == 0) {
#if HOTKNOT_BLOCK_RW
		if (!hotknot_paired_flag)
#endif
		{
			/*GTP_ERROR("buffer not ready:0x%02x", finger);*/
			goto exit_eint;
		}
	}
#if HOTKNOT_BLOCK_RW
	ret = hotknot_event_handler(point_data);
	if (!ret) {
		goto exit_work_func;
	}
#endif

#if GTP_PROXIMITY
	ret = gt5688_prox_event_handler(point_data);
	if (ret > 0) {
		goto exit_work_func;
	}
#endif

#if GTP_WITH_STYLUS
	ret = gt5688_touch_event_handler(point_data, input_dev, pen_dev);
#else
	ret = gt5688_touch_event_handler(point_data, input_dev, NULL);
#endif

exit_work_func:
	if (!gt5688_rawdiff_mode && (ret >= 0 || ret == ERROR_VALUE)) {
		ret = gt5688_i2c_write(GTP_READ_COOR_ADDR, &end_cmd, 1);
		if (ret < 0) {
			GTP_ERROR("I2C write end_cmd  error!");
		}
	}
exit_eint:
	gt5688_irq_enable();

}

/*
 * Devices Tree support,
 */
#ifdef GTP_CONFIG_OF

static struct regulator *vdd_ana;
/**
 * gt5688_parse_dt - parse platform infomation form devices tree.
 */
static int gt5688_parse_dt(struct device *dev)
{
	struct device_node *np;
	const char *tp_type;

	if (!dev)
		return -ENODEV;

	np = dev->of_node;

	if (!of_property_read_string(np, "goodix,ic_type", &tp_type)) {
		GTP_INFO("GTP ic_type: %s", tp_type);

		if (strstr(tp_type, "gt5688"))
			gt5688_gt5688 = true;
	}

	gt5688_int_gpio = of_get_named_gpio(np, "goodix,irq-gpio", 0);
	gt5688_rst_gpio = of_get_named_gpio(np, "goodix,rst-gpio", 0);
	gt5688_enable_gpio = of_get_named_gpio(np, "goodix,enable-gpio", 0);

	if (!gpio_is_valid(gt5688_int_gpio) || !gpio_is_valid(gt5688_rst_gpio)) {
		GTP_ERROR("Invalid GPIO, irq-gpio:%d, rst-gpio:%d",
				gt5688_int_gpio, gt5688_rst_gpio);
		return -EINVAL;
	}

	vdd_ana = devm_regulator_get_optional(dev, "vdd_ana");
	if (PTR_ERR(vdd_ana) == -ENODEV) {
		GTP_ERROR("vdd_ana not specified, fallback to power-supply");
		vdd_ana = devm_regulator_get_optional(dev, "power");
		if (PTR_ERR(vdd_ana) == -ENODEV) {
			GTP_ERROR("power not specified, ignore power ctrl");
			vdd_ana = NULL;
		}
	}
	if (IS_ERR(vdd_ana)) {
		GTP_ERROR("regulator get of vdd_ana/power-supply failed");
		return PTR_ERR(vdd_ana);
	}

	gt5688_ics_slot_report = of_property_read_bool(dev->of_node, "gtp_ics_slot_report");
	return 0;
}

/**
 * gt5688_power_switch - power switch .
 * @on: 1-switch on, 0-switch off.
 * return: 0-succeed, -1-faileds
 */
int gt5688_power_switch(int on)
{
	int ret;
	struct i2c_client *client = gt5688_i2c_client;

	if (!client || !vdd_ana)
		return -1;

	if (on) {
		GTP_DEBUG("GTP power on.");
		ret = regulator_enable(vdd_ana);
	} else {
		GTP_DEBUG("GTP power off.");
		ret = regulator_disable(vdd_ana);
	}
	return ret;
}
#endif

static void gt5688_remove_gpio_and_power(void)
{
	if (gpio_is_valid(gt5688_int_gpio))
		gpio_free(gt5688_int_gpio);

	if (gpio_is_valid(gt5688_rst_gpio))
		gpio_free(gt5688_rst_gpio);

	if (gpio_is_valid(gt5688_enable_gpio))
		gpio_free(gt5688_enable_gpio);

	if (gt5688_i2c_client && gt5688_i2c_client->irq)
		free_irq(gt5688_i2c_client->irq, gt5688_i2c_client);
}


/**
 * gt5688_request_io_port - Request gpio(INT & RST) ports.
 */
static s32 gt5688_request_io_port(void)
{
	s32 ret = 0;

	GTP_DEBUG_FUNC();
	ret = gpio_request(GTP_INT_PORT, "GTP_INT_IRQ");
	if (ret < 0) {
		GTP_ERROR("Failed to request GPIO:%d, ERRNO:%d", (s32) GTP_INT_PORT, ret);
		return ret;
	}

	GTP_GPIO_AS_INT(GTP_INT_PORT);
	gt5688_i2c_client->irq = GTP_INT_IRQ;

	ret = gpio_request(GTP_RST_PORT, "GTP_RST_PORT");
	if (ret < 0) {
		GTP_ERROR("Failed to request GPIO:%d, ERRNO:%d", (s32) GTP_RST_PORT, ret);
		gpio_free(GTP_INT_PORT);
		return ret;
	}

	GTP_GPIO_AS_INPUT(GTP_RST_PORT);
	return 0;
}

/**
 * gt5688_request_irq - Request interrupt.
 * Return
 *      0: succeed, -1: failed.
 */
static s32 gt5688_request_irq(void)
{
	s32 ret = -1;
	const u8 irq_table[] = GTP_IRQ_TAB;

	GTP_DEBUG_FUNC();
	GTP_DEBUG("INT trigger type:%x", gt5688_int_type);

	ret = request_irq(gt5688_i2c_client->irq, gt5688_ts_irq_handler, irq_table[gt5688_int_type], gt5688_i2c_client->name, gt5688_i2c_client);
	if (ret) {
		GTP_ERROR("Request IRQ failed!ERRNO:%d.", ret);
		GTP_GPIO_AS_INPUT(GTP_INT_PORT);
		gpio_free(GTP_INT_PORT);

		return -1;
	} else {
		gt5688_irq_disable();
		return 0;
	}
}

/**
 * gt5688_request_input_dev -  Request input device Function.
 * Return
 *      0: succeed, -1: failed.
 */
static s8 gt5688_request_input_dev(void)
{
	s8 ret = -1;
#if GTP_HAVE_TOUCH_KEY
	u8 index = 0;
#endif

	GTP_DEBUG_FUNC();

	input_dev = input_allocate_device();
	if (input_dev == NULL) {
		GTP_ERROR("Failed to allocate input device.");
		return -ENOMEM;
	}

	input_dev->evbit[0] = BIT_MASK(EV_SYN) | BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS);
	if (gt5688_ics_slot_report) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 7, 0))
		input_mt_init_slots(input_dev, 16, INPUT_MT_DIRECT);
#else
		input_mt_init_slots(input_dev, 16);
#endif
	} else {
		input_dev->keybit[BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH);
	}
	set_bit(INPUT_PROP_DIRECT, input_dev->propbit);

#if GTP_HAVE_TOUCH_KEY
	for (index = 0; index < GTP_MAX_KEY_NUM; index++) {
		input_set_capability(input_dev, EV_KEY, gt5688_touch_key_array[index]);
	}
#endif

#if GTP_GESTURE_WAKEUP
	input_set_capability(input_dev, EV_KEY, KEY_GES_REGULAR);
	input_set_capability(input_dev, EV_KEY, KEY_GES_CUSTOM);
#endif

#if GTP_CHANGE_X2Y
	input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, gt5688_abs_y_max, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, gt5688_abs_x_max, 0, 0);
#else
	input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, gt5688_abs_x_max, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, gt5688_abs_y_max, 0, 0);
#endif
	input_set_abs_params(input_dev, ABS_MT_PRESSURE, 0, 255, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(input_dev, ABS_MT_TRACKING_ID, 0, 255, 0, 0);

	input_set_abs_params(input_dev, ABS_X, 0, 255, 0, 0);
	input_set_abs_params(input_dev, ABS_Y, 0, 255, 0, 0);

	input_dev->name = gt5688_ts_name;
	input_dev->phys = input_dev_phys;
	input_dev->id.bustype = BUS_I2C;
	input_dev->id.vendor = 0xDEAD;
	input_dev->id.product = 0xBEEF;
	input_dev->id.version = 10427;

	ret = input_register_device(input_dev);
	if (ret) {
		GTP_ERROR("Register %s input device failed", input_dev->name);
		return -ENODEV;
	}

	return 0;
}

/**
 * gt5688_ts_probe -   I2c probe.
 * @client: i2c device struct.
 * @id: device id.
 * Return  0: succeed, -1: failed.
 */
static int gt5688_ts_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	s32 ret = -1;
#if GTP_AUTO_UPDATE
	struct task_struct *thread = NULL;
#endif
	/*do NOT remove these logs*/
	GTP_INFO("GTP Driver Version: %s", GTP_DRIVER_VERSION);
	GTP_INFO("GTP I2C Address: 0x%02x", client->addr);

	GTP_INFO("####################### ===GTP TEST 20200630 BEIQI=== ##########################");
	gt5688_i2c_client = client;
	spin_lock_init(&irq_lock);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		GTP_ERROR("I2C check functionality failed.");
		return -ENODEV;
	}

#ifdef GTP_CONFIG_OF	/* device tree support */
	if (client->dev.of_node) {
		ret = gt5688_parse_dt(&client->dev);
		if (ret)
			return ret;
	}
#endif

	ret = gt5688_request_io_port();
	if (ret < 0) {
		GTP_ERROR("GTP request IO port failed.");
		return ret;
	}

	ret = gt5688_init();
	if (ret != 0) {
		GTP_ERROR("GTP init failed!!!");
		return ret;
	}

	gt5688_wq = create_singlethread_workqueue("gt5688_wq");
	if (!gt5688_wq) {
		GTP_ERROR("Creat workqueue failed.");
		return -ENOMEM;
	}

	INIT_WORK(&gt5688_work, gt5688_ts_work_func);

	ret = gt5688_request_input_dev();
	if (ret < 0) {
		GTP_ERROR("GTP request input dev failed");
	}

	ret = gt5688_request_irq();
	if (ret < 0) {
		GTP_DEBUG("GTP works in polling mode.");
	} else {
		GTP_DEBUG("GTP works in interrupt mode.");
	}

#if GTP_GESTURE_WAKEUP
	enable_irq_wake(client->irq);
#endif

	gt5688_irq_enable();

#if GTP_ESD_PROTECT
	/*must before auto update*/
	gt5688_init_esd_protect();
	gt5688_esd_switch(SWITCH_ON);
#endif

#if GTP_AUTO_UPDATE
	thread = kthread_run(gt5688_auto_update_proc, (void *)NULL, "gt5688_auto_update");
	if (IS_ERR(thread)) {
		ret = PTR_ERR(thread);
		GTP_ERROR("Failed to create auto-update thread: %d.", ret);
	}
#endif
	gt5688_register_powermanger();
	return 0;
}

/**
 * gt5688_ts_remove -  Goodix touchscreen driver release function.
 * @client: i2c device struct.
 * Return  0: succeed, -1: failed.
 */
static int gt5688_ts_remove(struct i2c_client *client)
{
	GTP_DEBUG_FUNC();
	GTP_DEBUG("GTP driver removing...");
	gt5688_unregister_powermanger();

#if GTP_GESTURE_WAKEUP
	disable_irq_wake(client->irq);
#endif
	gt5688_deinit();
	input_unregister_device(input_dev);
	gt5688_remove_gpio_and_power();
	if (gt5688_wq) {
		destroy_workqueue(gt5688_wq);
	}

	return 0;
}

#if defined(CONFIG_FB)
/* frame buffer notifier block control the suspend/resume procedure */
static struct notifier_block gt5688_fb_notifier;
static int tp_status;

static int gtp_fb_notifier_callback(struct notifier_block *noti, unsigned long event, void *data)
{
	struct fb_event *ev_data = data;
	int *blank;

#if GTP_INCELL_PANEL
#ifndef FB_EARLY_EVENT_BLANK
#error Need add FB_EARLY_EVENT_BLANK to fbmem.c
#endif

	if (ev_data && ev_data->data && event == FB_EARLY_EVENT_BLANK
	    && tp_status != FB_BLANK_UNBLANK) {
		blank = ev_data->data;
		if (*blank == FB_BLANK_UNBLANK) {
			tp_status = *blank;
			GTP_DEBUG("Resume by fb notifier.");
			gt5688_resume();
		}
	}
#else
	if (ev_data && ev_data->data && event == FB_EVENT_BLANK
	    && tp_status != FB_BLANK_UNBLANK) {
		blank = ev_data->data;
		if (*blank == FB_BLANK_UNBLANK) {
			tp_status = *blank;
			GTP_DEBUG("Resume by fb notifier.");
			if (gpio_is_valid(gt5688_enable_gpio)){
				gpio_direction_output(gt5688_enable_gpio, 1);
			}
			gt5688_resume();
		}
	}
#endif

	if (ev_data && ev_data->data && event == FB_EVENT_BLANK
	    && tp_status == FB_BLANK_UNBLANK) {
		blank = ev_data->data;
		if (*blank == FB_BLANK_POWERDOWN) {
			tp_status = *blank;
			GTP_DEBUG("Suspend by fb notifier.");
			gt5688_suspend();
		}
	}

	return 0;
}

#elif defined(CONFIG_HAS_EARLYSUSPEND)
/* earlysuspend module the suspend/resume procedure */
static void gt5688_ts_early_suspend(struct early_suspend *h)
{
	gt5688_suspend();
}

static void gt5688_ts_late_resume(struct early_suspend *h)
{
	gt5688_resume();
}

static struct early_suspend gt5688_early_suspend = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1,
	.suspend = gt5688_ts_early_suspend,
	.resume = gt5688_ts_late_resume,
};
#endif

#ifdef CONFIG_PM
/**
 * gt5688_ts_suspend - i2c suspend callback function.
 * @dev: i2c device.
 * Return  0: succeed, -1: failed.
 */
static int gt5688_pm_suspend(struct device *dev)
{
    return gt5688_suspend();
}

/**
 * gt5688_ts_resume - i2c resume callback function.
 * @dev: i2c device.
 * Return  0: succeed, -1: failed.
 */
static int gt5688_pm_resume(struct device *dev)
{
       return gt5688_resume();
}

/* bus control the suspend/resume procedure */
static const struct dev_pm_ops gt5688_ts_pm_ops = {
       .suspend = gt5688_pm_suspend,
       .resume = gt5688_pm_resume,
};
#endif

static int gt5688_register_powermanger(void)
{
#if   defined(CONFIG_FB)
	tp_status = FB_BLANK_UNBLANK;
	gt5688_fb_notifier.notifier_call = gtp_fb_notifier_callback;
	fb_register_client(&gt5688_fb_notifier);

#elif defined(CONFIG_HAS_EARLYSUSPEND)
	register_early_suspend(&gt5688_early_suspend);
#endif
	return 0;
}

static int gt5688_unregister_powermanger(void)
{
#if   defined(CONFIG_FB)
	fb_unregister_client(&gt5688_fb_notifier);

#elif defined(CONFIG_HAS_EARLYSUSPEND)
	unregister_early_suspend(&gt5688_early_suspend);
#endif
	return 0;
}

#ifdef GTP_CONFIG_OF
static const struct of_device_id gt5688_match_table[] = {
		{.compatible = "goodix,gt5688",},
		{ },
};
#endif

static const struct i2c_device_id gt5688_ts_id[] = {
	{GTP_I2C_NAME, 0},
	{}
};

static struct i2c_driver gt5688_ts_driver = {
	.probe = gt5688_ts_probe,
	.remove = gt5688_ts_remove,
	.id_table = gt5688_ts_id,
	.driver = {
		   .name = GTP_I2C_NAME,
#ifdef GTP_CONFIG_OF
		   .of_match_table = gt5688_match_table,
#endif
#if !defined(CONFIG_FB) && defined(CONFIG_PM)
		   .pm = &gt5688_ts_pm_ops,
#endif
		   },
};

/**
 * gt5688_ts_init - Driver Install function.
 * Return   0---succeed.
 */
static int __init gt5688_ts_init(void)
{
	GTP_DEBUG_FUNC();
	GTP_DEBUG("GTP driver installing...");

	return i2c_add_driver(&gt5688_ts_driver);
}

/**
 * gt5688_ts_exit - Driver uninstall function.
 * Return   0---succeed.
 */
static void __exit gt5688_ts_exit(void)
{
	GTP_DEBUG_FUNC();
	GTP_DEBUG("GTP driver exited.");
	i2c_del_driver(&gt5688_ts_driver);
}

//module_init(gt5688_ts_init);
//module_exit(gt5688_ts_exit);
late_initcall(gt5688_ts_init);

MODULE_DESCRIPTION("GTP Series Driver");
MODULE_LICENSE("GPL");
