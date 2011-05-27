/*
 * qemu/kvm integration
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 *
 * Licensed under the terms of the GNU GPL version 2 or higher.
 */
#include "config.h"
#include "config-host.h"

#include <assert.h>
#include <string.h>
#include "hw/hw.h"
#include "sysemu.h"
#include "qemu-common.h"
#include "console.h"
#include "block.h"
#include "compatfd.h"
#include "gdbstub.h"
#include "monitor.h"
#include "cpus.h"

#include "qemu-kvm.h"

#define EXPECTED_KVM_API_VERSION 12

#if EXPECTED_KVM_API_VERSION != KVM_API_VERSION
#error libkvm: userspace and kernel version mismatch
#endif

int kvm_irqchip = 1;
int kvm_pit = 1;
int kvm_pit_reinject = 1;
int kvm_nested = 0;

#define ALIGN(x, y) (((x)+(y)-1) & ~((y)-1))

static inline void set_gsi(KVMState *s, unsigned int gsi)
{
    uint32_t *bitmap = s->used_gsi_bitmap;

    if (gsi < s->max_gsi) {
        bitmap[gsi / 32] |= 1U << (gsi % 32);
    } else {
        DPRINTF("Invalid GSI %u\n", gsi);
    }
}

static inline void clear_gsi(KVMState *s, unsigned int gsi)
{
    uint32_t *bitmap = s->used_gsi_bitmap;

    if (gsi < s->max_gsi) {
        bitmap[gsi / 32] &= ~(1U << (gsi % 32));
    } else {
        DPRINTF("Invalid GSI %u\n", gsi);
    }
}

static int kvm_init_irq_routing(KVMState *s)
{
#ifdef KVM_CAP_IRQ_ROUTING
    int r, gsi_count;

    gsi_count = kvm_check_extension(s, KVM_CAP_IRQ_ROUTING);
    if (gsi_count > 0) {
        int gsi_bits, i;

        /* Round up so we can search ints using ffs */
        gsi_bits = ALIGN(gsi_count, 32);
        s->used_gsi_bitmap = qemu_mallocz(gsi_bits / 8);
        s->max_gsi = gsi_bits;

        /* Mark any over-allocated bits as already in use */
        for (i = gsi_count; i < gsi_bits; i++) {
            set_gsi(s, i);
        }
    }

    s->irq_routes = qemu_mallocz(sizeof(*s->irq_routes));
    s->nr_allocated_irq_routes = 0;

    r = kvm_arch_init_irq_routing();
    if (r < 0) {
        return r;
    }
#endif

    return 0;
}

int kvm_create_irqchip(KVMState *s)
{
#ifdef KVM_CAP_IRQCHIP
    int r;

    if (!kvm_irqchip || !kvm_check_extension(s, KVM_CAP_IRQCHIP)) {
        return 0;
    }

    r = kvm_vm_ioctl(s, KVM_CREATE_IRQCHIP);
    if (r < 0) {
        fprintf(stderr, "Create kernel PIC irqchip failed\n");
        return r;
    }

    s->irqchip_inject_ioctl = KVM_IRQ_LINE;
#if defined(KVM_CAP_IRQ_INJECT_STATUS) && defined(KVM_IRQ_LINE_STATUS)
    if (kvm_check_extension(s, KVM_CAP_IRQ_INJECT_STATUS)) {
        s->irqchip_inject_ioctl = KVM_IRQ_LINE_STATUS;
    }
#endif
    s->irqchip_in_kernel = 1;

    r = kvm_init_irq_routing(s);
    if (r < 0) {
        return r;
    }
#endif

    return 0;
}

#ifdef KVM_CAP_IRQCHIP

int kvm_set_irq(int irq, int level, int *status)
{
    struct kvm_irq_level event;
    int r;

    if (!kvm_state->irqchip_in_kernel) {
        return 0;
    }
    event.level = level;
    event.irq = irq;
    r = kvm_vm_ioctl(kvm_state, kvm_state->irqchip_inject_ioctl,
                     &event);
    if (r < 0) {
        perror("kvm_set_irq");
    }

    if (status) {
#ifdef KVM_CAP_IRQ_INJECT_STATUS
        *status = (kvm_state->irqchip_inject_ioctl == KVM_IRQ_LINE) ?
            1 : event.status;
#else
        *status = 1;
#endif
    }

    return 1;
}

int kvm_get_irqchip(KVMState *s, struct kvm_irqchip *chip)
{
    int r;

    if (!s->irqchip_in_kernel) {
        return 0;
    }
    r = kvm_vm_ioctl(s, KVM_GET_IRQCHIP, chip);
    if (r < 0) {
        perror("kvm_get_irqchip\n");
    }
    return r;
}

int kvm_set_irqchip(KVMState *s, struct kvm_irqchip *chip)
{
    int r;

    if (!s->irqchip_in_kernel) {
        return 0;
    }
    r = kvm_vm_ioctl(s, KVM_SET_IRQCHIP, chip);
    if (r < 0) {
        perror("kvm_set_irqchip\n");
    }
    return r;
}

#endif

#ifdef KVM_CAP_DEVICE_ASSIGNMENT
int kvm_assign_pci_device(KVMState *s,
                          struct kvm_assigned_pci_dev *assigned_dev)
{
    return kvm_vm_ioctl(s, KVM_ASSIGN_PCI_DEVICE, assigned_dev);
}

static int kvm_old_assign_irq(KVMState *s,
                              struct kvm_assigned_irq *assigned_irq)
{
    return kvm_vm_ioctl(s, KVM_ASSIGN_IRQ, assigned_irq);
}

#ifdef KVM_CAP_ASSIGN_DEV_IRQ
int kvm_assign_irq(KVMState *s, struct kvm_assigned_irq *assigned_irq)
{
    int ret;

    ret = kvm_ioctl(s, KVM_CHECK_EXTENSION, KVM_CAP_ASSIGN_DEV_IRQ);
    if (ret > 0) {
        return kvm_vm_ioctl(s, KVM_ASSIGN_DEV_IRQ, assigned_irq);
    }

    return kvm_old_assign_irq(s, assigned_irq);
}

int kvm_deassign_irq(KVMState *s, struct kvm_assigned_irq *assigned_irq)
{
    return kvm_vm_ioctl(s, KVM_DEASSIGN_DEV_IRQ, assigned_irq);
}
#else
int kvm_assign_irq(KVMState *s, struct kvm_assigned_irq *assigned_irq)
{
    return kvm_old_assign_irq(s, assigned_irq);
}
#endif
#endif

#ifdef KVM_CAP_DEVICE_DEASSIGNMENT
int kvm_deassign_pci_device(KVMState *s,
                            struct kvm_assigned_pci_dev *assigned_dev)
{
    return kvm_vm_ioctl(s, KVM_DEASSIGN_PCI_DEVICE, assigned_dev);
}
#endif

int kvm_reinject_control(KVMState *s, int pit_reinject)
{
#ifdef KVM_CAP_REINJECT_CONTROL
    int r;
    struct kvm_reinject_control control;

    control.pit_reinject = pit_reinject;

    r = kvm_ioctl(s, KVM_CHECK_EXTENSION, KVM_CAP_REINJECT_CONTROL);
    if (r > 0) {
        return kvm_vm_ioctl(s, KVM_REINJECT_CONTROL, &control);
    }
#endif
    return -ENOSYS;
}

int kvm_has_gsi_routing(void)
{
    int r = 0;

#ifdef KVM_CAP_IRQ_ROUTING
    r = kvm_check_extension(kvm_state, KVM_CAP_IRQ_ROUTING);
#endif
    return r;
}

int kvm_clear_gsi_routes(void)
{
#ifdef KVM_CAP_IRQ_ROUTING
    kvm_state->irq_routes->nr = 0;
    return 0;
#else
    return -EINVAL;
#endif
}

int kvm_add_routing_entry(struct kvm_irq_routing_entry *entry)
{
#ifdef KVM_CAP_IRQ_ROUTING
    KVMState *s = kvm_state;
    struct kvm_irq_routing *z;
    struct kvm_irq_routing_entry *new;
    int n, size;

    if (s->irq_routes->nr == s->nr_allocated_irq_routes) {
        n = s->nr_allocated_irq_routes * 2;
        if (n < 64) {
            n = 64;
        }
        size = sizeof(struct kvm_irq_routing);
        size += n * sizeof(*new);
        z = realloc(s->irq_routes, size);
        if (!z) {
            return -ENOMEM;
        }
        s->nr_allocated_irq_routes = n;
        s->irq_routes = z;
    }
    n = s->irq_routes->nr++;
    new = &s->irq_routes->entries[n];
    memset(new, 0, sizeof(*new));
    new->gsi = entry->gsi;
    new->type = entry->type;
    new->flags = entry->flags;
    new->u = entry->u;

    set_gsi(s, entry->gsi);

    return 0;
#else
    return -ENOSYS;
#endif
}

int kvm_add_irq_route(int gsi, int irqchip, int pin)
{
#ifdef KVM_CAP_IRQ_ROUTING
    struct kvm_irq_routing_entry e;

    e.gsi = gsi;
    e.type = KVM_IRQ_ROUTING_IRQCHIP;
    e.flags = 0;
    e.u.irqchip.irqchip = irqchip;
    e.u.irqchip.pin = pin;
    return kvm_add_routing_entry(&e);
#else
    return -ENOSYS;
#endif
}

int kvm_del_routing_entry(struct kvm_irq_routing_entry *entry)
{
#ifdef KVM_CAP_IRQ_ROUTING
    KVMState *s = kvm_state;
    struct kvm_irq_routing_entry *e, *p;
    int i, gsi, found = 0;

    gsi = entry->gsi;

    for (i = 0; i < s->irq_routes->nr; ++i) {
        e = &s->irq_routes->entries[i];
        if (e->type == entry->type && e->gsi == gsi) {
            switch (e->type) {
            case KVM_IRQ_ROUTING_IRQCHIP:{
                    if (e->u.irqchip.irqchip ==
                        entry->u.irqchip.irqchip
                        && e->u.irqchip.pin == entry->u.irqchip.pin) {
                        p = &s->irq_routes->entries[--s->irq_routes->nr];
                        *e = *p;
                        found = 1;
                    }
                    break;
                }
            case KVM_IRQ_ROUTING_MSI:{
                    if (e->u.msi.address_lo ==
                        entry->u.msi.address_lo
                        && e->u.msi.address_hi ==
                        entry->u.msi.address_hi
                        && e->u.msi.data == entry->u.msi.data) {
                        p = &s->irq_routes->entries[--s->irq_routes->nr];
                        *e = *p;
                        found = 1;
                    }
                    break;
                }
            default:
                break;
            }
            if (found) {
                /* If there are no other users of this GSI
                 * mark it available in the bitmap */
                for (i = 0; i < s->irq_routes->nr; i++) {
                    e = &s->irq_routes->entries[i];
                    if (e->gsi == gsi)
                        break;
                }
                if (i == s->irq_routes->nr) {
                    clear_gsi(s, gsi);
                }

                return 0;
            }
        }
    }
    return -ESRCH;
#else
    return -ENOSYS;
#endif
}

int kvm_update_routing_entry(struct kvm_irq_routing_entry *entry,
                             struct kvm_irq_routing_entry *newentry)
{
#ifdef KVM_CAP_IRQ_ROUTING
    KVMState *s = kvm_state;
    struct kvm_irq_routing_entry *e;
    int i;

    if (entry->gsi != newentry->gsi || entry->type != newentry->type) {
        return -EINVAL;
    }

    for (i = 0; i < s->irq_routes->nr; ++i) {
        e = &s->irq_routes->entries[i];
        if (e->type != entry->type || e->gsi != entry->gsi) {
            continue;
        }
        switch (e->type) {
        case KVM_IRQ_ROUTING_IRQCHIP:
            if (e->u.irqchip.irqchip == entry->u.irqchip.irqchip &&
                e->u.irqchip.pin == entry->u.irqchip.pin) {
                memcpy(&e->u.irqchip, &newentry->u.irqchip,
                       sizeof e->u.irqchip);
                return 0;
            }
            break;
        case KVM_IRQ_ROUTING_MSI:
            if (e->u.msi.address_lo == entry->u.msi.address_lo &&
                e->u.msi.address_hi == entry->u.msi.address_hi &&
                e->u.msi.data == entry->u.msi.data) {
                memcpy(&e->u.msi, &newentry->u.msi, sizeof e->u.msi);
                return 0;
            }
            break;
        default:
            break;
        }
    }
    return -ESRCH;
#else
    return -ENOSYS;
#endif
}

int kvm_del_irq_route(int gsi, int irqchip, int pin)
{
#ifdef KVM_CAP_IRQ_ROUTING
    struct kvm_irq_routing_entry e;

    e.gsi = gsi;
    e.type = KVM_IRQ_ROUTING_IRQCHIP;
    e.flags = 0;
    e.u.irqchip.irqchip = irqchip;
    e.u.irqchip.pin = pin;
    return kvm_del_routing_entry(&e);
#else
    return -ENOSYS;
#endif
}

int kvm_commit_irq_routes(void)
{
#ifdef KVM_CAP_IRQ_ROUTING
    KVMState *s = kvm_state;

    s->irq_routes->flags = 0;
    return kvm_vm_ioctl(s, KVM_SET_GSI_ROUTING, s->irq_routes);
#else
    return -ENOSYS;
#endif
}

int kvm_get_irq_route_gsi(void)
{
    KVMState *s = kvm_state;
    int i, bit;
    uint32_t *buf = s->used_gsi_bitmap;

    /* Return the lowest unused GSI in the bitmap */
    for (i = 0; i < s->max_gsi / 32; i++) {
        bit = ffs(~buf[i]);
        if (!bit) {
            continue;
        }

        return bit - 1 + i * 32;
    }

    return -ENOSPC;
}

static void kvm_msi_routing_entry(struct kvm_irq_routing_entry *e,
                                  KVMMsiMessage *msg)

{
    e->gsi = msg->gsi;
    e->type = KVM_IRQ_ROUTING_MSI;
    e->flags = 0;
    e->u.msi.address_lo = msg->addr_lo;
    e->u.msi.address_hi = msg->addr_hi;
    e->u.msi.data = msg->data;
}

int kvm_msi_message_add(KVMMsiMessage *msg)
{
    struct kvm_irq_routing_entry e;
    int ret;

    ret = kvm_get_irq_route_gsi();
    if (ret < 0) {
        return ret;
    }
    msg->gsi = ret;

    kvm_msi_routing_entry(&e, msg);
    return kvm_add_routing_entry(&e);
}

int kvm_msi_message_del(KVMMsiMessage *msg)
{
    struct kvm_irq_routing_entry e;

    kvm_msi_routing_entry(&e, msg);
    return kvm_del_routing_entry(&e);
}

int kvm_msi_message_update(KVMMsiMessage *old, KVMMsiMessage *new)
{
    struct kvm_irq_routing_entry e1, e2;
    int ret;

    new->gsi = old->gsi;
    if (memcmp(old, new, sizeof(KVMMsiMessage)) == 0) {
        return 0;
    }

    kvm_msi_routing_entry(&e1, old);
    kvm_msi_routing_entry(&e2, new);

    ret = kvm_update_routing_entry(&e1, &e2);
    if (ret < 0) {
        return ret;
    }

    return 1;
}


#ifdef KVM_CAP_DEVICE_MSIX
int kvm_assign_set_msix_nr(KVMState *s, struct kvm_assigned_msix_nr *msix_nr)
{
    return kvm_vm_ioctl(s, KVM_ASSIGN_SET_MSIX_NR, msix_nr);
}

int kvm_assign_set_msix_entry(KVMState *s,
                              struct kvm_assigned_msix_entry *entry)
{
    return kvm_vm_ioctl(s, KVM_ASSIGN_SET_MSIX_ENTRY, entry);
}
#endif

#ifdef TARGET_I386
void kvm_hpet_disable_kpit(void)
{
    struct kvm_pit_state2 ps2;

    kvm_get_pit2(kvm_state, &ps2);
    ps2.flags |= KVM_PIT_FLAGS_HPET_LEGACY;
    kvm_set_pit2(kvm_state, &ps2);
}

void kvm_hpet_enable_kpit(void)
{
    struct kvm_pit_state2 ps2;

    kvm_get_pit2(kvm_state, &ps2);
    ps2.flags &= ~KVM_PIT_FLAGS_HPET_LEGACY;
    kvm_set_pit2(kvm_state, &ps2);
}
#endif

#if !defined(TARGET_I386)
int kvm_arch_init_irq_routing(void)
{
    return 0;
}
#endif

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
typedef struct KVMIOPortRegion {
    unsigned long start;
    unsigned long size;
    int status;
    QLIST_ENTRY(KVMIOPortRegion) entry;
} KVMIOPortRegion;

static QLIST_HEAD(, KVMIOPortRegion) ioport_regions;

static void do_set_ioport_access(void *data)
{
    KVMIOPortRegion *region = data;
    bool enable = region->status > 0;
    int r;

    r = kvm_arch_set_ioport_access(region->start, region->size, enable);
    if (r < 0) {
        region->status = r;
    } else {
        region->status = 1;
    }
}

int kvm_add_ioport_region(unsigned long start, unsigned long size)
{
    KVMIOPortRegion *region = qemu_mallocz(sizeof(KVMIOPortRegion));
    CPUState *env;
    int r = 0;

    region->start = start;
    region->size = size;
    region->status = 1;
    QLIST_INSERT_HEAD(&ioport_regions, region, entry);

    if (qemu_system_is_ready()) {
        for (env = first_cpu; env != NULL; env = env->next_cpu) {
            on_vcpu(env, do_set_ioport_access, region);
            if (region->status < 0) {
                r = region->status;
                kvm_remove_ioport_region(start, size);
                break;
            }
        }
    }
    return r;
}

int kvm_remove_ioport_region(unsigned long start, unsigned long size)
{
    KVMIOPortRegion *region, *tmp;
    CPUState *env;
    int r = -ENOENT;

    QLIST_FOREACH_SAFE(region, &ioport_regions, entry, tmp) {
        if (region->start == start && region->size == size) {
            region->status = 0;
        }
        if (qemu_system_is_ready()) {
            for (env = first_cpu; env != NULL; env = env->next_cpu) {
                on_vcpu(env, do_set_ioport_access, region);
            }
        }
        QLIST_REMOVE(region, entry);
        qemu_free(region);
        r = 0;
    }
    return r;
}
#endif /* CONFIG_KVM_DEVICE_ASSIGNMENT */

int kvm_update_ioport_access(CPUState *env)
{
#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
    KVMIOPortRegion *region;
    int r;

    assert(qemu_cpu_is_self(env));

    QLIST_FOREACH(region, &ioport_regions, entry) {
        bool enable = region->status > 0;

        r = kvm_arch_set_ioport_access(region->start, region->size, enable);
        if (r < 0) {
            return r;
        }
    }
#endif /* CONFIG_KVM_DEVICE_ASSIGNMENT */
    return 0;
}

int kvm_set_boot_cpu_id(KVMState *s, uint32_t id)
{
#ifdef KVM_CAP_SET_BOOT_CPU_ID
    int r = kvm_ioctl(s, KVM_CHECK_EXTENSION, KVM_CAP_SET_BOOT_CPU_ID);
    if (r > 0) {
        return kvm_vm_ioctl(s, KVM_SET_BOOT_CPU_ID, id);
    }
#endif
    return -ENOSYS;
}
