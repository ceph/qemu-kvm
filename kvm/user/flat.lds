OUTPUT_FORMAT(binary)

SECTIONS
{
    . = 0;
    .text : { *(.text) }
    . = ALIGN(4K);
    .data : { *(.data) }
    .bss : { *(.bss) }
}

