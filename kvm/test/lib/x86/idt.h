#ifndef __IDT_TEST__
#define __IDT_TEST__

void setup_idt(void);

#define ASM_TRY(catch)                                  \
    "movl $0, %%gs:4 \n\t"                              \
    ".pushsection .data.ex \n\t"                        \
    ".quad 1111f, " catch "\n\t"                        \
    ".popsection \n\t"                                  \
    "1111:"

#define UD_VECTOR   6
#define GP_VECTOR   13

unsigned exception_vector(void);
unsigned exception_error_code(void);

#endif
