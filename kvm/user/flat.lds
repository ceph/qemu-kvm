OUTPUT_FORMAT(binary)

SECTIONS
{
    . = 0;
    .text : { *(.init) *(.text) }
    . = ALIGN(4K);
    .data : { *(.data) }
    .bss : { *(.bss) }
}

