#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/mbus.h>
#include <linux/clk.h>
#include <linux/platform_data/usb-ehci-orion.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>

#include "ehci.h"

#define rdl(off)	__raw_readl(hcd->regs + (off))
#define wrl(off, val)	__raw_writel((val), hcd->regs + (off))

#define USB_CMD			0x140
#define USB_MODE		0x1a8
#define USB_CAUSE		0x310
#define USB_MASK		0x314
#define USB_WINDOW_CTRL(i)	(0x320 + ((i) << 4))
#define USB_WINDOW_BASE(i)	(0x324 + ((i) << 4))
#define USB_IPG			0x360
#define USB_PHY_PWR_CTRL	0x400
#define USB_PHY_TX_CTRL		0x420
#define USB_PHY_RX_CTRL		0x430
#define USB_PHY_IVREF_CTRL	0x440
#define USB_PHY_TST_GRP_CTRL	0x450

#define DRIVER_DESC "EHCI orion driver"

static const char hcd_name[] = "ehci-orion";

static struct hc_driver __read_mostly ehci_orion_hc_driver;

static void orion_usb_phy_v1_setup(struct usb_hcd *hcd)
{
	 
	wrl(USB_CAUSE, 0);
	wrl(USB_MASK, 0);

	wrl(USB_CMD, rdl(USB_CMD) | 0x2);
	while (rdl(USB_CMD) & 0x2);

	wrl(USB_IPG, (rdl(USB_IPG) & ~0x7f00) | 0xc00);

	wrl(USB_PHY_PWR_CTRL, (rdl(USB_PHY_PWR_CTRL) & ~0xc0)| 0x40);

	wrl(USB_PHY_TX_CTRL, (rdl(USB_PHY_TX_CTRL) & ~0x78) | 0x202040);

	wrl(USB_PHY_RX_CTRL, (rdl(USB_PHY_RX_CTRL) & ~0xc2003f0) | 0xc0000010);

	wrl(USB_PHY_IVREF_CTRL, (rdl(USB_PHY_IVREF_CTRL) & ~0x80003 ) | 0x32);

	wrl(USB_PHY_TST_GRP_CTRL, rdl(USB_PHY_TST_GRP_CTRL) & ~0x8000);

	wrl(USB_CMD, rdl(USB_CMD) & ~0x1);
	wrl(USB_CMD, rdl(USB_CMD) | 0x2);
	while (rdl(USB_CMD) & 0x2);

	wrl(USB_MODE, 0x13);
}

static void
ehci_orion_conf_mbus_windows(struct usb_hcd *hcd,
			     const struct mbus_dram_target_info *dram)
{
	int i;

	for (i = 0; i < 4; i++) {
		wrl(USB_WINDOW_CTRL(i), 0);
		wrl(USB_WINDOW_BASE(i), 0);
	}

	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;

		wrl(USB_WINDOW_CTRL(i), ((cs->size - 1) & 0xffff0000) |
					(cs->mbus_attr << 8) |
					(dram->mbus_dram_target_id << 4) | 1);
		wrl(USB_WINDOW_BASE(i), cs->base);
	}
}

static int ehci_orion_drv_probe(struct platform_device *pdev)
{
	struct orion_ehci_data *pd = pdev->dev.platform_data;
	const struct mbus_dram_target_info *dram;
	struct resource *res;
	struct usb_hcd *hcd;
	struct ehci_hcd *ehci;
	struct clk *clk;
	void __iomem *regs;
	int irq, err;
	enum orion_ehci_phy_ver phy_version;
#if defined (MY_DEF_HERE)
	struct device_node	*node = pdev->dev.of_node;
	u32 vbus_gpio_pin = 0;
#endif  

	if (usb_disabled())
		return -ENODEV;

	pr_debug("Initializing Orion-SoC USB Host Controller\n");

	if (pdev->dev.of_node)
		irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	else
		irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(&pdev->dev,
			"Found HC with no IRQ. Check %s setup!\n",
			dev_name(&pdev->dev));
		err = -ENODEV;
		goto err1;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev,
			"Found HC with no register addr. Check %s setup!\n",
			dev_name(&pdev->dev));
		err = -ENODEV;
		goto err1;
	}

	if (!pdev->dev.dma_mask)
		pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;
	if (!pdev->dev.coherent_dma_mask)
		pdev->dev.coherent_dma_mask = DMA_BIT_MASK(32);

	if (!request_mem_region(res->start, resource_size(res),
				ehci_orion_hc_driver.description)) {
		dev_dbg(&pdev->dev, "controller already in use\n");
		err = -EBUSY;
		goto err1;
	}

	regs = ioremap(res->start, resource_size(res));
	if (regs == NULL) {
		dev_dbg(&pdev->dev, "error mapping memory\n");
		err = -EFAULT;
		goto err2;
	}

	clk = clk_get(&pdev->dev, NULL);
	if (!IS_ERR(clk)) {
		clk_prepare_enable(clk);
		clk_put(clk);
	}

	hcd = usb_create_hcd(&ehci_orion_hc_driver,
			&pdev->dev, dev_name(&pdev->dev));
	if (!hcd) {
		err = -ENOMEM;
		goto err3;
	}

#if defined (MY_DEF_HERE)
	if (node) {
		if (of_property_read_bool(node, "power-control-capable")) {
			hcd->power_control_support = 1;
		} else {
			hcd->power_control_support = 0;
		}
		if (of_property_read_bool(node, "vbus-gpio")) {
			of_property_read_u32(node, "vbus-gpio", &vbus_gpio_pin);
			 
			hcd->vbus_gpio_pin = vbus_gpio_pin;
		} else {
			hcd->vbus_gpio_pin = -1;
			dev_warn(&pdev->dev, "failed to get Vbus gpio\n");
		}
	}
#endif  

	hcd->rsrc_start = res->start;
	hcd->rsrc_len = resource_size(res);
	hcd->regs = regs;

	ehci = hcd_to_ehci(hcd);
	ehci->caps = hcd->regs + 0x100;
	hcd->has_tt = 1;

	dram = mv_mbus_dram_info();
	if (dram)
		ehci_orion_conf_mbus_windows(hcd, dram);

	if (pdev->dev.of_node)
		phy_version = EHCI_PHY_NA;
	else
		phy_version = pd->phy_version;

	switch (phy_version) {
	case EHCI_PHY_NA:	 
		break;
	case EHCI_PHY_ORION:
		orion_usb_phy_v1_setup(hcd);
		break;
	case EHCI_PHY_DD:
	case EHCI_PHY_KW:
	default:
		printk(KERN_WARNING "Orion ehci -USB phy version isn't supported.\n");
	}
#if defined (MY_DEF_HERE)
	dev_info(&pdev->dev, "USB2 Vbus gpio %d\n", hcd->vbus_gpio_pin);
	dev_info(&pdev->dev, "power control %s\n", hcd->power_control_support ? "enabled" : "disabled");
#endif  
	err = usb_add_hcd(hcd, irq, IRQF_SHARED);
	if (err)
		goto err4;

	return 0;

err4:
	usb_put_hcd(hcd);
err3:
	if (!IS_ERR(clk)) {
		clk_disable_unprepare(clk);
		clk_put(clk);
	}
	iounmap(regs);
err2:
	release_mem_region(res->start, resource_size(res));
err1:
	dev_err(&pdev->dev, "init %s fail, %d\n",
		dev_name(&pdev->dev), err);

	return err;
}

static int ehci_orion_drv_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct clk *clk;

	usb_remove_hcd(hcd);
	iounmap(hcd->regs);
	release_mem_region(hcd->rsrc_start, hcd->rsrc_len);
	usb_put_hcd(hcd);

	clk = clk_get(&pdev->dev, NULL);
	if (!IS_ERR(clk)) {
		clk_disable_unprepare(clk);
		clk_put(clk);
	}
	return 0;
}

static const struct of_device_id ehci_orion_dt_ids[] = {
	{ .compatible = "marvell,orion-ehci", },
	{},
};
MODULE_DEVICE_TABLE(of, ehci_orion_dt_ids);

static struct platform_driver ehci_orion_driver = {
	.probe		= ehci_orion_drv_probe,
	.remove		= ehci_orion_drv_remove,
	.shutdown	= usb_hcd_platform_shutdown,
	.driver = {
		.name	= "orion-ehci",
		.owner  = THIS_MODULE,
		.of_match_table = of_match_ptr(ehci_orion_dt_ids),
	},
};

static int __init ehci_orion_init(void)
{
	if (usb_disabled())
		return -ENODEV;

	pr_info("%s: " DRIVER_DESC "\n", hcd_name);

	ehci_init_driver(&ehci_orion_hc_driver, NULL);
	return platform_driver_register(&ehci_orion_driver);
}
module_init(ehci_orion_init);

static void __exit ehci_orion_cleanup(void)
{
	platform_driver_unregister(&ehci_orion_driver);
}
module_exit(ehci_orion_cleanup);

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_ALIAS("platform:orion-ehci");
MODULE_AUTHOR("Tzachi Perelstein");
MODULE_LICENSE("GPL v2");
