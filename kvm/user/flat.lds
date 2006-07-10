OUTPUT_FORMAT(binary)

SECTIONS
{
    . = 0;
    .text : { *(.text) }
    . = (. + 4095) & ~ 4095;
    .data : { *(.data) }
    .bss : { *(.bss) }
}

