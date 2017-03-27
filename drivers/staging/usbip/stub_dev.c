#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/device.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/module.h>

#include "usbip_common.h"
#include "stub.h"

static struct usb_device_id stub_table[] = {
#if 0
	 
	{ USB_DEVICE(0x05ac, 0x0301) },    
	{ USB_DEVICE(0x0430, 0x0009) },    
	{ USB_DEVICE(0x059b, 0x0001) },    
	{ USB_DEVICE(0x04b3, 0x4427) },    
	{ USB_DEVICE(0x05a9, 0xa511) },    
	{ USB_DEVICE(0x55aa, 0x0201) },    
	{ USB_DEVICE(0x046d, 0x0870) },    
	{ USB_DEVICE(0x04bb, 0x0101) },    
	{ USB_DEVICE(0x04bb, 0x0904) },    
	{ USB_DEVICE(0x04bb, 0x0201) },    
	{ USB_DEVICE(0x08bb, 0x2702) },    
	{ USB_DEVICE(0x046d, 0x08b2) },    
#endif
	 
	{ .driver_info = 1 },
	{ 0, }                                      
};
MODULE_DEVICE_TABLE(usb, stub_table);

static ssize_t show_status(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	struct stub_device *sdev = dev_get_drvdata(dev);
	int status;

	if (!sdev) {
		dev_err(dev, "sdev is null\n");
		return -ENODEV;
	}

	spin_lock_irq(&sdev->ud.lock);
	status = sdev->ud.status;
	spin_unlock_irq(&sdev->ud.lock);

	return snprintf(buf, PAGE_SIZE, "%d\n", status);
}
static DEVICE_ATTR(usbip_status, S_IRUGO, show_status, NULL);

static ssize_t store_sockfd(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct stub_device *sdev = dev_get_drvdata(dev);
	int sockfd = 0;
	struct socket *socket;
	ssize_t err = -EINVAL;

	if (!sdev) {
		dev_err(dev, "sdev is null\n");
		return -ENODEV;
	}

	sscanf(buf, "%d", &sockfd);

	if (sockfd != -1) {
		dev_info(dev, "stub up\n");

		spin_lock_irq(&sdev->ud.lock);

		if (sdev->ud.status != SDEV_ST_AVAILABLE) {
			dev_err(dev, "not ready\n");
			goto err;
		}

		socket = sockfd_to_socket(sockfd);
		if (!socket)
			goto err;

		sdev->ud.tcp_socket = socket;

		spin_unlock_irq(&sdev->ud.lock);

		sdev->ud.tcp_rx = kthread_get_run(stub_rx_loop, &sdev->ud,
						  "stub_rx");
		sdev->ud.tcp_tx = kthread_get_run(stub_tx_loop, &sdev->ud,
						  "stub_tx");

		spin_lock_irq(&sdev->ud.lock);
		sdev->ud.status = SDEV_ST_USED;
		spin_unlock_irq(&sdev->ud.lock);

	} else {
		dev_info(dev, "stub down\n");
#ifdef MY_ABC_HERE
	 
#else
		spin_lock_irq(&sdev->ud.lock);
		if (sdev->ud.status != SDEV_ST_USED)
			goto err;

		spin_unlock_irq(&sdev->ud.lock);
#endif
		usbip_event_add(&sdev->ud, SDEV_EVENT_DOWN);
	}

	return count;

err:
	spin_unlock_irq(&sdev->ud.lock);
	return err;
}
static DEVICE_ATTR(usbip_sockfd, S_IWUSR, NULL, store_sockfd);

static int stub_add_files(struct device *dev)
{
	int err = 0;

	err = device_create_file(dev, &dev_attr_usbip_status);
	if (err)
		goto err_status;

	err = device_create_file(dev, &dev_attr_usbip_sockfd);
	if (err)
		goto err_sockfd;

	err = device_create_file(dev, &dev_attr_usbip_debug);
	if (err)
		goto err_debug;

	return 0;

err_debug:
	device_remove_file(dev, &dev_attr_usbip_sockfd);
err_sockfd:
	device_remove_file(dev, &dev_attr_usbip_status);
err_status:
	return err;
}

static void stub_remove_files(struct device *dev)
{
	device_remove_file(dev, &dev_attr_usbip_status);
	device_remove_file(dev, &dev_attr_usbip_sockfd);
	device_remove_file(dev, &dev_attr_usbip_debug);
}

static void stub_shutdown_connection(struct usbip_device *ud)
{
	struct stub_device *sdev = container_of(ud, struct stub_device, ud);

	if (ud->tcp_socket) {
		dev_dbg(&sdev->udev->dev, "shutdown tcp_socket %p\n",
			ud->tcp_socket);
		kernel_sock_shutdown(ud->tcp_socket, SHUT_RDWR);
	}

	if (ud->tcp_rx) {
		kthread_stop_put(ud->tcp_rx);
		ud->tcp_rx = NULL;
	}
	if (ud->tcp_tx) {
		kthread_stop_put(ud->tcp_tx);
		ud->tcp_tx = NULL;
	}

	if (ud->tcp_socket) {
		fput(ud->tcp_socket->file);
		ud->tcp_socket = NULL;
	}

	stub_device_cleanup_urbs(sdev);

	{
		unsigned long flags;
		struct stub_unlink *unlink, *tmp;

		spin_lock_irqsave(&sdev->priv_lock, flags);
		list_for_each_entry_safe(unlink, tmp, &sdev->unlink_tx, list) {
			list_del(&unlink->list);
			kfree(unlink);
		}
		list_for_each_entry_safe(unlink, tmp, &sdev->unlink_free,
					 list) {
			list_del(&unlink->list);
			kfree(unlink);
		}
		spin_unlock_irqrestore(&sdev->priv_lock, flags);
	}
}

static void stub_device_reset(struct usbip_device *ud)
{
	struct stub_device *sdev = container_of(ud, struct stub_device, ud);
	struct usb_device *udev = sdev->udev;
	int ret;

	dev_dbg(&udev->dev, "device reset");

	ret = usb_lock_device_for_reset(udev, sdev->interface);
	if (ret < 0) {
		dev_err(&udev->dev, "lock for reset\n");
		spin_lock_irq(&ud->lock);
		ud->status = SDEV_ST_ERROR;
		spin_unlock_irq(&ud->lock);
		return;
	}

	ret = usb_reset_device(udev);
	usb_unlock_device(udev);

	spin_lock_irq(&ud->lock);
	if (ret) {
		dev_err(&udev->dev, "device reset\n");
		ud->status = SDEV_ST_ERROR;
	} else {
		dev_info(&udev->dev, "device reset\n");
		ud->status = SDEV_ST_AVAILABLE;
	}
	spin_unlock_irq(&ud->lock);
}

static void stub_device_unusable(struct usbip_device *ud)
{
	spin_lock_irq(&ud->lock);
	ud->status = SDEV_ST_ERROR;
	spin_unlock_irq(&ud->lock);
}

static struct stub_device *stub_device_alloc(struct usb_device *udev,
					     struct usb_interface *interface)
{
	struct stub_device *sdev;
	int busnum = interface_to_busnum(interface);
	int devnum = interface_to_devnum(interface);

	dev_dbg(&interface->dev, "allocating stub device");

	sdev = kzalloc(sizeof(struct stub_device), GFP_KERNEL);
	if (!sdev)
		return NULL;

	sdev->interface = usb_get_intf(interface);
	sdev->udev = usb_get_dev(udev);

	sdev->devid		= (busnum << 16) | devnum;
	sdev->ud.side		= USBIP_STUB;
	sdev->ud.status		= SDEV_ST_AVAILABLE;
	spin_lock_init(&sdev->ud.lock);
	sdev->ud.tcp_socket	= NULL;

	INIT_LIST_HEAD(&sdev->priv_init);
	INIT_LIST_HEAD(&sdev->priv_tx);
	INIT_LIST_HEAD(&sdev->priv_free);
	INIT_LIST_HEAD(&sdev->unlink_free);
	INIT_LIST_HEAD(&sdev->unlink_tx);
	spin_lock_init(&sdev->priv_lock);

	init_waitqueue_head(&sdev->tx_waitq);

	sdev->ud.eh_ops.shutdown = stub_shutdown_connection;
	sdev->ud.eh_ops.reset    = stub_device_reset;
	sdev->ud.eh_ops.unusable = stub_device_unusable;

	usbip_start_eh(&sdev->ud);

	dev_dbg(&interface->dev, "register new interface\n");

	return sdev;
}

static void stub_device_free(struct stub_device *sdev)
{
	kfree(sdev);
}

static int stub_probe(struct usb_interface *interface,
		      const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(interface);
	struct stub_device *sdev = NULL;
	const char *udev_busid = dev_name(interface->dev.parent);
	int err = 0;
	struct bus_id_priv *busid_priv;

	dev_dbg(&interface->dev, "Enter probe\n");

	busid_priv = get_busid_priv(udev_busid);
	if (!busid_priv || (busid_priv->status == STUB_BUSID_REMOV) ||
	    (busid_priv->status == STUB_BUSID_OTHER)) {
		dev_info(&interface->dev, "%s is not in match_busid table... "
			 "skip!\n", udev_busid);

		return -ENODEV;
	}

	if (udev->descriptor.bDeviceClass == USB_CLASS_HUB) {
		dev_dbg(&udev->dev, "%s is a usb hub device... skip!\n",
			 udev_busid);
		return -ENODEV;
	}

	if (!strcmp(udev->bus->bus_name, "vhci_hcd")) {
		dev_dbg(&udev->dev, "%s is attached on vhci_hcd... skip!\n",
			 udev_busid);
		return -ENODEV;
	}

	if (busid_priv->status == STUB_BUSID_ALLOC) {
		sdev = busid_priv->sdev;
		if (!sdev)
			return -ENODEV;

		busid_priv->interf_count++;
		dev_info(&interface->dev, "usbip-host: register new interface "
			 "(bus %u dev %u ifn %u)\n",
			 udev->bus->busnum, udev->devnum,
			 interface->cur_altsetting->desc.bInterfaceNumber);

		usb_set_intfdata(interface, sdev);

		err = stub_add_files(&interface->dev);
		if (err) {
			dev_err(&interface->dev, "stub_add_files for %s\n",
				udev_busid);
			usb_set_intfdata(interface, NULL);
			busid_priv->interf_count--;
			return err;
		}

		usb_get_intf(interface);
		return 0;
	}

	sdev = stub_device_alloc(udev, interface);
	if (!sdev)
		return -ENOMEM;

	dev_info(&interface->dev, "usbip-host: register new device "
		 "(bus %u dev %u ifn %u)\n", udev->bus->busnum, udev->devnum,
		 interface->cur_altsetting->desc.bInterfaceNumber);

	busid_priv->interf_count = 0;
	busid_priv->shutdown_busid = 0;

	usb_set_intfdata(interface, sdev);
	busid_priv->interf_count++;
	busid_priv->sdev = sdev;

	err = stub_add_files(&interface->dev);
	if (err) {
		dev_err(&interface->dev, "stub_add_files for %s\n", udev_busid);
		usb_set_intfdata(interface, NULL);
		usb_put_intf(interface);
		usb_put_dev(udev);
		kthread_stop_put(sdev->ud.eh);

		busid_priv->interf_count = 0;
		busid_priv->sdev = NULL;
		stub_device_free(sdev);
		return err;
	}
	busid_priv->status = STUB_BUSID_ALLOC;

	return 0;
}

static void shutdown_busid(struct bus_id_priv *busid_priv)
{
	if (busid_priv->sdev && !busid_priv->shutdown_busid) {
		busid_priv->shutdown_busid = 1;
		usbip_event_add(&busid_priv->sdev->ud, SDEV_EVENT_REMOVED);

		usbip_stop_eh(&busid_priv->sdev->ud);
	}
}

static void stub_disconnect(struct usb_interface *interface)
{
	struct stub_device *sdev;
	const char *udev_busid = dev_name(interface->dev.parent);
	struct bus_id_priv *busid_priv;

	dev_dbg(&interface->dev, "Enter disconnect\n");

	busid_priv = get_busid_priv(udev_busid);
	if (!busid_priv) {
		BUG();
		return;
	}

	sdev = usb_get_intfdata(interface);

	if (!sdev) {
		dev_err(&interface->dev, "could not get device");
		return;
	}

	usb_set_intfdata(interface, NULL);

	stub_remove_files(&interface->dev);

	if (busid_priv->sdev->ud.eh == current) {
		busid_priv->interf_count--;
		return;
	}

	if (busid_priv->interf_count > 1) {
		busid_priv->interf_count--;
		shutdown_busid(busid_priv);
		usb_put_intf(interface);
		return;
	}

	busid_priv->interf_count = 0;

	shutdown_busid(busid_priv);

	usb_put_dev(sdev->udev);
	usb_put_intf(interface);

	busid_priv->sdev = NULL;
	stub_device_free(sdev);

	if (busid_priv->status == STUB_BUSID_ALLOC) {
		busid_priv->status = STUB_BUSID_ADDED;
	} else {
		busid_priv->status = STUB_BUSID_OTHER;
		del_match_busid((char *)udev_busid);
	}
}

static int stub_pre_reset(struct usb_interface *interface)
{
	dev_dbg(&interface->dev, "pre_reset\n");
	return 0;
}

static int stub_post_reset(struct usb_interface *interface)
{
	dev_dbg(&interface->dev, "post_reset\n");
	return 0;
}

struct usb_driver stub_driver = {
#ifdef MY_ABC_HERE
	.name		= "usbip",
#else
	.name		= "usbip-host",
#endif
	.probe		= stub_probe,
	.disconnect	= stub_disconnect,
	.id_table	= stub_table,
	.pre_reset	= stub_pre_reset,
	.post_reset	= stub_post_reset,
};
