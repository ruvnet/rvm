/*
 * RVM linker script for QEMU virt AArch64.
 *
 * QEMU -M virt loads the kernel at 0x4000_0000 (the start of RAM).
 * The layout places the boot entry point first (.text.boot), followed
 * by general code, read-only data, writable data, and BSS.
 *
 * Symbols exported:
 *   _start        - entry point (in .text.boot)
 *   __bss_start   - start of BSS section
 *   __bss_end     - end of BSS section
 *   __stack_top   - initial stack pointer (64KB stack)
 *   __page_tables - start of page table region (4KB aligned)
 */

ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x40000000, LENGTH = 128M
}

SECTIONS {
    /* Boot entry point must be at the load address. */
    .text.boot 0x40000000 : {
        KEEP(*(.text.boot))
    } > RAM

    .text : ALIGN(4) {
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    } > RAM

    .data : ALIGN(8) {
        *(.data .data.*)
    } > RAM

    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    /* 64KB hypervisor stack, growing downward. */
    . = ALIGN(4096);
    __stack_bottom = .;
    . = . + 0x10000;
    __stack_top = .;

    /* Page table region: 4KB-aligned, room for L1 + 4 L2 tables. */
    . = ALIGN(4096);
    __page_tables = .;
    . = . + (5 * 4096);

    /* Heap region (optional, for future use). */
    . = ALIGN(4096);
    __heap_start = .;

    /* Discard debug sections for release builds. */
    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
