
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/irq.h>

#define HYPERCALL_DRIVER_NAME "Qumranet hypercall driver"
#define HYPERCALL_DRIVER_VERSION "1"
#define PCI_VENDOR_ID_HYPERCALL	0x5002
#define PCI_DEVICE_ID_HYPERCALL 0x2258

MODULE_AUTHOR ("Dor Laor <dor.laor@qumranet.com>");
MODULE_DESCRIPTION (HYPERCALL_DRIVER_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(HYPERCALL_DRIVER_VERSION);

static int debug = 0;
module_param(debug, int, 0);
MODULE_PARM_DESC (debug, "toggle debug flag");

#define HYPERCALL_DEBUG 1
#if HYPERCALL_DEBUG
#  define DPRINTK(fmt, args...) printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#  define assert(expr) \
        if(unlikely(!(expr))) {				        \
        printk(KERN_ERR "Assertion failed! %s,%s,%s,line=%d\n",	\
        #expr,__FILE__,__FUNCTION__,__LINE__);		        \
        }
#else
#  define DPRINTK(fmt, args...)
#  define assert(expr) do {} while (0)
#endif

static struct pci_device_id hypercall_pci_tbl[] = {
	{PCI_VENDOR_ID_HYPERCALL, PCI_DEVICE_ID_HYPERCALL, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{0,}
};
MODULE_DEVICE_TABLE (pci, hypercall_pci_tbl);



/****** Hypercall device definitions ***************/
/* To be moved into a shared file with user space  */
#define HP_CMD          0x00  // The command register  WR
#define HP_ISRSTATUS    0x04  // Interrupt status reg RD 
#define HP_TXSIZE       0x08
#define HP_TXBUFF       0x0c
#define HP_RXSIZE       0x10
#define HP_RXBUFF       0x14

// HP_CMD register commands
#define HP_CMD_DI		1 // disable interrupts
#define HP_CMD_EI		2 // enable interrupts
#define HP_CMD_INIT		4 // reset device
#define HP_CMD_RESET		(HP_CMD_INIT|HP_CMD_DI)

/* Bits in HP_ISR - Interrupt status register */
#define HPISR_RX	0x01  // Data is ready to be read

#define HP_MEM_SIZE    0xE0
/******* End of Hypercall device definitions	   */

/* read PIO/MMIO register */
#define HIO_READ8(reg, ioaddr)		ioread8(ioaddr + (reg))
#define HIO_READ16(reg, ioaddr)		ioread16(ioaddr + (reg))
#define HIO_READ32(reg, ioaddr)		ioread32(ioaddr + (reg))

/* write PIO/MMIO register */
#define HIO_WRITE8(reg, val8, ioaddr)	iowrite8((val8), ioaddr + (reg))
#define HIO_WRITE16(reg, val16, ioaddr)	iowrite16((val16), ioaddr + (reg))
#define HIO_WRITE32(reg, val32, ioaddr)	iowrite32((val32), ioaddr + (reg))


struct hypercall_dev {
	struct pci_dev  *pci_dev;
	u32 		state;
	spinlock_t	lock;
	u8		name[128];
	u16		irq;
	u32		regs_len;
	void __iomem 	*io_addr;
	unsigned long	base_addr;	/* device I/O address	*/
};


static int hypercall_close(struct hypercall_dev* dev);
static int hypercall_open(struct hypercall_dev *dev);
static void hypercall_cleanup_dev(struct hypercall_dev *dev);
static irqreturn_t hypercall_interrupt(int irq, void *dev_instance,
				       struct pt_regs *regs);


static int __devinit hypercall_init_board(struct pci_dev *pdev,
					  struct hypercall_dev **dev_out)
{
	unsigned long ioaddr;
	struct hypercall_dev *dev;
	int rc;
	u32 disable_dev_on_err = 0;
	unsigned long pio_start, pio_end, pio_flags, pio_len;
	unsigned long mmio_start, mmio_end, mmio_flags, mmio_len;

	assert(pdev != NULL);

	*dev_out = NULL;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		printk (KERN_ERR "%s: Unable to alloc hypercall device\n", pci_name(pdev));
		return -ENOMEM;
	}
	dev->pci_dev = pdev;
	rc = pci_enable_device(pdev);
	if (rc)
		goto err_out;
	disable_dev_on_err = 1;

	pio_start = pci_resource_start (pdev, 0);
	pio_end = pci_resource_end (pdev, 0);
	pio_flags = pci_resource_flags (pdev, 0);
	pio_len = pci_resource_len (pdev, 0);

	mmio_start = pci_resource_start (pdev, 1);
	mmio_end = pci_resource_end (pdev, 1);
	mmio_flags = pci_resource_flags (pdev, 1);
	mmio_len = pci_resource_len (pdev, 1);

	DPRINTK("PIO region size == 0x%02lX\n", pio_len);
	DPRINTK("MMIO region size == 0x%02lX\n", mmio_len);

	rc = pci_request_regions (pdev, "hypercall");
	if (rc)
		goto err_out;

#define USE_IO_OPS 1
#ifdef USE_IO_OPS
	ioaddr = (unsigned long)pci_iomap(pdev, 0, 0);
	//ioaddr = ioport_map(pio_start, pio_len);
	if (!ioaddr) {
		printk(KERN_ERR "%s: cannot map PIO, aborting\n", pci_name(pdev));
		rc = -EIO;
		goto err_out;
	}
	dev->base_addr = (unsigned long)pio_start;
	dev->io_addr = (void*)ioaddr;
	dev->regs_len = pio_len;
#else
	ioaddr = pci_iomap(pdev, 1, 0);
	if (ioaddr == NULL) {
		printk(KERN_ERR "%s: cannot remap MMIO, aborting\n", pci_name(pdev));
		rc = -EIO;
		goto err_out;
	}
	dev->base_addr = ioaddr;
	dev->io_addr = (void*)ioaddr;
	dev->regs_len = mmio_len;
#endif /* USE_IO_OPS */

	*dev_out = dev;
	return 0;

err_out:
	hypercall_cleanup_dev(dev);
	if (disable_dev_on_err)
		pci_disable_device(pdev);
	return rc;
}

static int __devinit hypercall_init_one(struct pci_dev *pdev,
				        const struct pci_device_id *ent)
{
	struct hypercall_dev *dev;
	u8 pci_rev;

	assert(pdev != NULL);
	assert(ent != NULL);

	pci_read_config_byte(pdev, PCI_REVISION_ID, &pci_rev);

	if (pdev->vendor == PCI_VENDOR_ID_HYPERCALL &&
	    pdev->device == PCI_DEVICE_ID_HYPERCALL) {
		printk(KERN_INFO "pci dev %s (id %04x:%04x rev %02x) is a guest hypercall device\n",
		       pci_name(pdev), pdev->vendor, pdev->device, pci_rev);
	}

	if (hypercall_init_board(pdev, &dev) != 0)
		return -1;
	
	assert(dev != NULL);
                    
	dev->irq = pdev->irq;

	spin_lock_init(&dev->lock);
        pci_set_drvdata(pdev, dev);

	printk (KERN_INFO "name=%s: base_addr=0x%lx, io_addr=0x%lx, IRQ=%d\n",
		dev->name, dev->base_addr, (unsigned long)dev->io_addr, dev->irq);
	hypercall_open(dev);
	return 0;
}

static void __devexit hypercall_remove_one(struct pci_dev *pdev)
{
	struct hypercall_dev *dev = pci_get_drvdata(pdev);

	assert(dev != NULL);

	hypercall_close(dev);
	hypercall_cleanup_dev(dev);
	pci_disable_device(pdev);
}

/* 
 * The interrupt handler does all of the rx  work and cleans up
 * after the tx
 */
static irqreturn_t hypercall_interrupt(int irq, void *dev_instance,
				       struct pt_regs *regs)
{
	struct hypercall_dev *dev = (struct hypercall_dev *)dev_instance;
	void __iomem *ioaddr = (void __iomem*)dev->io_addr;
	u32 status;
	int irq_handled = IRQ_NONE;
	int rx_buf_size;
	int i;
	u8 buffer[HP_MEM_SIZE];
	u8 *pbuf;

	DPRINTK("base addr is 0x%lx, io_addr=0x%lx\n", dev->base_addr, (long)dev->io_addr);
	
	spin_lock(&dev->lock);
	status = HIO_READ8(HP_ISRSTATUS, ioaddr);
	DPRINTK("irq status is 0x%x\n", status);

	/* shared irq? */
	if (unlikely((status & HPISR_RX) == 0)) {
		DPRINTK("not handeling irq, not ours\n");
		goto out;
	}
	
	/* Disable device interrupts */
	HIO_WRITE8(HP_CMD, HP_CMD_DI, ioaddr);
	DPRINTK("disable device interrupts\n");

	rx_buf_size = HIO_READ8(HP_RXSIZE, ioaddr);
	DPRINTK("Rx buffer size is %d\n", rx_buf_size);

	if (rx_buf_size > HP_MEM_SIZE)
		rx_buf_size = HP_MEM_SIZE;

	for (i=0, pbuf=buffer; i<rx_buf_size; i++, pbuf++) {
		*pbuf = HIO_READ8(HP_RXBUFF, ioaddr + i);
		DPRINTK("Read 0x%x as dword %d\n", *pbuf, i);
	}
	*pbuf = '\0';
	DPRINTK("Read buffer %s", (char*)buffer);

	HIO_WRITE8(HP_CMD, HP_CMD_EI, ioaddr);
	DPRINTK("Enable interrupt\n");
	irq_handled = IRQ_HANDLED;
 out:
	spin_unlock(&dev->lock);
	return irq_handled;
}


static int hypercall_open(struct hypercall_dev *dev)
{
	int rc;

	rc = request_irq(dev->irq, &hypercall_interrupt,
			 SA_SHIRQ, dev->name, dev);
	if (rc) {
		printk(KERN_ERR "%s failed to request an irq\n", __FUNCTION__);
		return rc;
	}

	//hypercall_thread_start(dev);

	return 0;
}

static int hypercall_close(struct hypercall_dev* dev)
{
	//hypercall_thread_stop(dev);
	synchronize_irq(dev->irq);
	free_irq(dev->irq, dev);

	return 0;
}

#ifdef CONFIG_PM

static int hypercall_suspend(struct pci_dev *pdev, pm_message_t state)
{
	pci_save_state(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
	DPRINTK("Power mgmt suspend, set power state to PCI_D3hot\n");

	return 0;
}

static int hypercall_resume(struct pci_dev *pdev)
{
	pci_restore_state(pdev);
	pci_set_power_state(pdev, PCI_D0);
	DPRINTK("Power mgmt resume, set power state to PCI_D0\n");

	return 0;
}

#endif /* CONFIG_PM */

static void hypercall_cleanup_dev(struct hypercall_dev *dev)
{
	DPRINTK("cleaning up\n");
        pci_release_regions(dev->pci_dev);
	pci_iounmap(dev->pci_dev, (void*)dev->io_addr);
	pci_set_drvdata (dev->pci_dev, NULL);
	kfree(dev);
}

static struct pci_driver hypercall_pci_driver = {
	.name		= HYPERCALL_DRIVER_NAME,
	.id_table	= hypercall_pci_tbl,
	.probe		= hypercall_init_one,
	.remove		= __devexit_p(hypercall_remove_one),
#ifdef CONFIG_PM
	.suspend	= hypercall_suspend,
	.resume		= hypercall_resume,
#endif /* CONFIG_PM */
};

static int __init hypercall_init_module(void)
{
	printk (KERN_INFO HYPERCALL_DRIVER_NAME "\n");
	return pci_module_init(&hypercall_pci_driver);
}

static void __exit hypercall_cleanup_module(void)
{
	pci_unregister_driver(&hypercall_pci_driver);
}

module_init(hypercall_init_module);
module_exit(hypercall_cleanup_module);
