#include "hw.h"
#include "qdev.h"
#include "isa.h"

struct testdev {
    ISADevice dev;
    CharDriverState *chr;
};

static void test_device_serial_write(void *opaque, uint32_t addr, uint32_t data)
{
    struct testdev *dev = opaque;
    uint8_t buf[1] = { data };

    if (dev->chr) {
        qemu_chr_write(dev->chr, buf, 1);
    }
}

static void test_device_exit(void *opaque, uint32_t addr, uint32_t data)
{
    exit(data);
}

static uint32_t test_device_memsize_read(void *opaque, uint32_t addr)
{
    return ram_size;
}

static void test_device_irq_line(void *opaque, uint32_t addr, uint32_t data)
{
    extern qemu_irq *ioapic_irq_hack;

    qemu_set_irq(ioapic_irq_hack[addr - 0x2000], !!data);
}

static int init_test_device(ISADevice *isa)
{
    struct testdev *dev = DO_UPCAST(struct testdev, dev, isa);

    register_ioport_write(0xf1, 1, 1, test_device_serial_write, dev);
    register_ioport_write(0xf4, 1, 4, test_device_exit, dev);
    register_ioport_read(0xd1, 1, 4, test_device_memsize_read, dev);
    register_ioport_write(0x2000, 24, 1, test_device_irq_line, NULL);
    return 0;
}

static ISADeviceInfo testdev_info = {
    .qdev.name  = "testdev",
    .qdev.size  = sizeof(struct testdev),
    .init       = init_test_device,
    .qdev.props = (Property[]) {
        DEFINE_PROP_CHR("chardev", struct testdev, chr),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void testdev_register_devices(void)
{
    isa_qdev_register(&testdev_info);
}

device_init(testdev_register_devices)
