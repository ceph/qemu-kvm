#ifndef APIC_H
#define APIC_H

/* apic.c */
typedef struct APICState APICState;
void apic_deliver_irq(uint8_t dest, uint8_t dest_mode,
                             uint8_t delivery_mode,
                             uint8_t vector_num, uint8_t polarity,
                             uint8_t trigger_mode);
int apic_init(CPUState *env);
int apic_accept_pic_intr(APICState *s);
void apic_deliver_pic_intr(APICState *s, int level);
int apic_get_interrupt(APICState *s);
void apic_reset_irq_delivered(void);
int apic_get_irq_delivered(void);
void apic_set_irq_delivered(void);

int cpu_is_bsp(CPUState *env);

void cpu_set_apic_base(APICState *s, uint64_t val);
uint64_t cpu_get_apic_base(APICState *s);
void cpu_set_apic_tpr(APICState *s, uint8_t val);
#ifndef NO_CPU_IO_DEFS
uint8_t cpu_get_apic_tpr(APICState *s);
#endif

void apic_init_reset(APICState *s);
void apic_sipi(APICState *s);

#endif
