/*
 * Bochs/QEMU ACPI DSDT ASL definition
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
DefinitionBlock (
    "acpi-dsdt.aml",    // Output Filename
    "DSDT",             // Signature
    0x01,               // DSDT Compliance Revision
    "BXPC",             // OEMID
    "BXDSDT",           // TABLE ID
    0x1                 // OEM Revision
    )
{
   Scope (\_PR)
   {
	OperationRegion( PRST, SystemIO, 0xaf00, 0x02)
	Field (PRST, ByteAcc, NoLock, WriteAsZeros)
	{
		PRU, 8,
		PRD, 8,
	}

        Processor (CPU0, 0x00, 0x0000b010, 0x06) {Method (_STA) { Return(0xF)}}
        Processor (CPU1, 0x01, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x01, 0x01, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x2)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU2, 0x02, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x02, 0x02, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x4)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU3, 0x03, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x03, 0x03, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x8)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU4, 0x04, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x04, 0x04, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x10)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU5, 0x05, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x05, 0x05, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x20)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU6, 0x06, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x06, 0x06, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x40)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU7, 0x07, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x07, 0x07, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x80)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU8, 0x08, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x08, 0x08, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x100)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPU9, 0x09, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x09, 0x09, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x200)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPUA, 0x0a, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x0A, 0x0A, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x400)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPUB, 0x0b, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x0B, 0x0B, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x800)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPUC, 0x0c, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x0C, 0x0C, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x1000)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPUD, 0x0d, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x0D, 0x0D, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x2000)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
        Processor (CPUE, 0x0e, 0x0000b010, 0x06) {
            Name (TMP, Buffer(0x8) {0x0, 0x8, 0x0E, 0x0E, 0x1, 0x0, 0x0, 0x0})
            Method(_MAT, 0) {
                If (And(\_PR.PRU, 0x4000)) { Return(TMP) }
                Else { Return(0x0) }
            }
            Method (_STA) {
                Return(0xF)
            }
        }
    }

    Scope (\)
    {
        /* CMOS memory access */
        OperationRegion (CMS, SystemIO, 0x70, 0x02)
        Field (CMS, ByteAcc, NoLock, Preserve)
        {
            CMSI,   8,
            CMSD,   8
        }
        Method (CMRD, 1, NotSerialized)
        {
            Store (Arg0, CMSI)
            Store (CMSD, Local0)
            Return (Local0)
        }

        /* Debug Output */
        OperationRegion (DBG, SystemIO, 0xb044, 0x04)
        Field (DBG, DWordAcc, NoLock, Preserve)
        {
            DBGL,   32,
        }
    }


    /* PCI Bus definition */
    Scope(\_SB) {
        Device(PCI0) {
            Name (_HID, EisaId ("PNP0A03"))
            Name (_ADR, 0x00)
            Name (_UID, 1)
            Name(_PRT, Package() {
                /* PCI IRQ routing table, example from ACPI 2.0a specification,
                   section 6.2.8.1 */
                /* Note: we provide the same info as the PCI routing
                   table of the Bochs BIOS */

                // PCI Slot 0
                Package() {0x0000ffff, 0, LNKD, 0},
                Package() {0x0000ffff, 1, LNKA, 0},
                Package() {0x0000ffff, 2, LNKB, 0},
                Package() {0x0000ffff, 3, LNKC, 0},

                // PCI Slot 1
                Package() {0x0001ffff, 0, LNKA, 0},
                Package() {0x0001ffff, 1, LNKB, 0},
                Package() {0x0001ffff, 2, LNKC, 0},
                Package() {0x0001ffff, 3, LNKD, 0},

                // PCI Slot 2
                Package() {0x0002ffff, 0, LNKB, 0},
                Package() {0x0002ffff, 1, LNKC, 0},
                Package() {0x0002ffff, 2, LNKD, 0},
                Package() {0x0002ffff, 3, LNKA, 0},

                // PCI Slot 3
                Package() {0x0003ffff, 0, LNKC, 0},
                Package() {0x0003ffff, 1, LNKD, 0},
                Package() {0x0003ffff, 2, LNKA, 0},
                Package() {0x0003ffff, 3, LNKB, 0},

                // PCI Slot 4
                Package() {0x0004ffff, 0, LNKD, 0},
                Package() {0x0004ffff, 1, LNKA, 0},
                Package() {0x0004ffff, 2, LNKB, 0},
                Package() {0x0004ffff, 3, LNKC, 0},

                // PCI Slot 5
                Package() {0x0005ffff, 0, LNKA, 0},
                Package() {0x0005ffff, 1, LNKB, 0},
                Package() {0x0005ffff, 2, LNKC, 0},
                Package() {0x0005ffff, 3, LNKD, 0},

                // PCI Slot 6
                Package() {0x0006ffff, 0, LNKB, 0},
                Package() {0x0006ffff, 1, LNKC, 0},
                Package() {0x0006ffff, 2, LNKD, 0},
                Package() {0x0006ffff, 3, LNKA, 0},

                // PCI Slot 7
                Package() {0x0007ffff, 0, LNKC, 0},
                Package() {0x0007ffff, 1, LNKD, 0},
                Package() {0x0007ffff, 2, LNKA, 0},
                Package() {0x0007ffff, 3, LNKB, 0},

                // PCI Slot 8
                Package() {0x0008ffff, 0, LNKD, 0},
                Package() {0x0008ffff, 1, LNKA, 0},
                Package() {0x0008ffff, 2, LNKB, 0},
                Package() {0x0008ffff, 3, LNKC, 0},

                // PCI Slot 9
                Package() {0x0008ffff, 0, LNKA, 0},
                Package() {0x0008ffff, 1, LNKB, 0},
                Package() {0x0008ffff, 2, LNKC, 0},
                Package() {0x0008ffff, 3, LNKD, 0},

                // PCI Slot 10
                Package() {0x000affff, 0, LNKB, 0},
                Package() {0x000affff, 1, LNKC, 0},
                Package() {0x000affff, 2, LNKD, 0},
                Package() {0x000affff, 3, LNKA, 0},

                // PCI Slot 11
                Package() {0x000bffff, 0, LNKC, 0},
                Package() {0x000bffff, 1, LNKD, 0},
                Package() {0x000bffff, 2, LNKA, 0},
                Package() {0x000bffff, 3, LNKB, 0},

                // PCI Slot 12
                Package() {0x000cffff, 0, LNKD, 0},
                Package() {0x000cffff, 1, LNKA, 0},
                Package() {0x000cffff, 2, LNKB, 0},
                Package() {0x000cffff, 3, LNKC, 0},

                // PCI Slot 13
                Package() {0x000dffff, 0, LNKA, 0},
                Package() {0x000dffff, 1, LNKB, 0},
                Package() {0x000dffff, 2, LNKC, 0},
                Package() {0x000dffff, 3, LNKD, 0},

                // PCI Slot 14
                Package() {0x000effff, 0, LNKB, 0},
                Package() {0x000effff, 1, LNKC, 0},
                Package() {0x000effff, 2, LNKD, 0},
                Package() {0x000effff, 3, LNKA, 0},

                // PCI Slot 15
                Package() {0x000fffff, 0, LNKC, 0},
                Package() {0x000fffff, 1, LNKD, 0},
                Package() {0x000fffff, 2, LNKA, 0},
                Package() {0x000fffff, 3, LNKB, 0},

                // PCI Slot 16
                Package() {0x0010ffff, 0, LNKD, 0},
                Package() {0x0010ffff, 1, LNKA, 0},
                Package() {0x0010ffff, 2, LNKB, 0},
                Package() {0x0010ffff, 3, LNKC, 0},

                // PCI Slot 17
                Package() {0x0011ffff, 0, LNKA, 0},
                Package() {0x0011ffff, 1, LNKB, 0},
                Package() {0x0011ffff, 2, LNKC, 0},
                Package() {0x0011ffff, 3, LNKD, 0},

                // PCI Slot 18
                Package() {0x0012ffff, 0, LNKB, 0},
                Package() {0x0012ffff, 1, LNKC, 0},
                Package() {0x0012ffff, 2, LNKD, 0},
                Package() {0x0012ffff, 3, LNKA, 0},

                // PCI Slot 19
                Package() {0x0013ffff, 0, LNKC, 0},
                Package() {0x0013ffff, 1, LNKD, 0},
                Package() {0x0013ffff, 2, LNKA, 0},
                Package() {0x0013ffff, 3, LNKB, 0},

                // PCI Slot 20
                Package() {0x0014ffff, 0, LNKD, 0},
                Package() {0x0014ffff, 1, LNKA, 0},
                Package() {0x0014ffff, 2, LNKB, 0},
                Package() {0x0014ffff, 3, LNKC, 0},

                // PCI Slot 21
                Package() {0x0015ffff, 0, LNKA, 0},
                Package() {0x0015ffff, 1, LNKB, 0},
                Package() {0x0015ffff, 2, LNKC, 0},
                Package() {0x0015ffff, 3, LNKD, 0},

                // PCI Slot 22
                Package() {0x0016ffff, 0, LNKB, 0},
                Package() {0x0016ffff, 1, LNKC, 0},
                Package() {0x0016ffff, 2, LNKD, 0},
                Package() {0x0016ffff, 3, LNKA, 0},

                // PCI Slot 23
                Package() {0x0017ffff, 0, LNKC, 0},
                Package() {0x0017ffff, 1, LNKD, 0},
                Package() {0x0017ffff, 2, LNKA, 0},
                Package() {0x0017ffff, 3, LNKB, 0},

                // PCI Slot 24
                Package() {0x0018ffff, 0, LNKD, 0},
                Package() {0x0018ffff, 1, LNKA, 0},
                Package() {0x0018ffff, 2, LNKB, 0},
                Package() {0x0018ffff, 3, LNKC, 0},

                // PCI Slot 25
                Package() {0x0018ffff, 0, LNKA, 0},
                Package() {0x0018ffff, 1, LNKB, 0},
                Package() {0x0018ffff, 2, LNKC, 0},
                Package() {0x0018ffff, 3, LNKD, 0},

                // PCI Slot 26
                Package() {0x001affff, 0, LNKB, 0},
                Package() {0x001affff, 1, LNKC, 0},
                Package() {0x001affff, 2, LNKD, 0},
                Package() {0x001affff, 3, LNKA, 0},

                // PCI Slot 27
                Package() {0x001bffff, 0, LNKC, 0},
                Package() {0x001bffff, 1, LNKD, 0},
                Package() {0x001bffff, 2, LNKA, 0},
                Package() {0x001bffff, 3, LNKB, 0},

                // PCI Slot 28
                Package() {0x001cffff, 0, LNKD, 0},
                Package() {0x001cffff, 1, LNKA, 0},
                Package() {0x001cffff, 2, LNKB, 0},
                Package() {0x001cffff, 3, LNKC, 0},

                // PCI Slot 29
                Package() {0x001dffff, 0, LNKA, 0},
                Package() {0x001dffff, 1, LNKB, 0},
                Package() {0x001dffff, 2, LNKC, 0},
                Package() {0x001dffff, 3, LNKD, 0},

                // PCI Slot 30
                Package() {0x001effff, 0, LNKB, 0},
                Package() {0x001effff, 1, LNKC, 0},
                Package() {0x001effff, 2, LNKD, 0},
                Package() {0x001effff, 3, LNKA, 0},

                // PCI Slot 31
                Package() {0x001fffff, 0, LNKC, 0},
                Package() {0x001fffff, 1, LNKD, 0},
                Package() {0x001fffff, 2, LNKA, 0},
                Package() {0x001fffff, 3, LNKB, 0},
            })

            Device (S1) {              // Slot 1
               Name (_ADR, 0x00010000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S2) {              // Slot 2
               Name (_ADR, 0x00020000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S3) {              // Slot 3
               Name (_ADR, 0x00030000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S4) {              // Slot 4
               Name (_ADR, 0x00040000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S5) {              // Slot 5
               Name (_ADR, 0x00050000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S6) {              // Slot 6
               Name (_ADR, 0x00060000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S7) {              // Slot 7
               Name (_ADR, 0x00070000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S8) {              // Slot 8
               Name (_ADR, 0x00080000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S9) {              // Slot 9
               Name (_ADR, 0x00090000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S10) {              // Slot 10
               Name (_ADR, 0x000A0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S11) {              // Slot 11
               Name (_ADR, 0x000B0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S12) {              // Slot 12
               Name (_ADR, 0x000C0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S13) {              // Slot 13
               Name (_ADR, 0x000D0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S14) {              // Slot 14
               Name (_ADR, 0x000E0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S15) {              // Slot 15
               Name (_ADR, 0x000F0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S16) {              // Slot 16
               Name (_ADR, 0x00100000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S17) {              // Slot 17
               Name (_ADR, 0x00110000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S18) {              // Slot 18
               Name (_ADR, 0x00120000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S19) {              // Slot 19
               Name (_ADR, 0x00130000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S20) {              // Slot 20
               Name (_ADR, 0x00140000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S21) {              // Slot 21
               Name (_ADR, 0x00150000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S22) {              // Slot 22
               Name (_ADR, 0x00160000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S23) {              // Slot 23
               Name (_ADR, 0x00170000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S24) {              // Slot 24
               Name (_ADR, 0x00180000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S25) {              // Slot 25
               Name (_ADR, 0x00190000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S26) {              // Slot 26
               Name (_ADR, 0x001A0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S27) {              // Slot 27
               Name (_ADR, 0x001B0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S28) {              // Slot 28
               Name (_ADR, 0x001C0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S29) {              // Slot 29
               Name (_ADR, 0x001D0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S30) {              // Slot 30
               Name (_ADR, 0x001E0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Device (S31) {              // Slot 31
               Name (_ADR, 0x001F0000)
               Method (_EJ0,1) { Return (0x0) }
            }

            Method (_CRS, 0, NotSerialized)
            {
            Name (MEMP, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    0x0000,             // Address Space Granularity
                    0x0000,             // Address Range Minimum
                    0x00FF,             // Address Range Maximum
                    0x0000,             // Address Translation Offset
                    0x0100,             // Address Length
                    ,, )
                IO (Decode16,
                    0x0CF8,             // Address Range Minimum
                    0x0CF8,             // Address Range Maximum
                    0x01,               // Address Alignment
                    0x08,               // Address Length
                    )
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000,             // Address Space Granularity
                    0x0000,             // Address Range Minimum
                    0x0CF7,             // Address Range Maximum
                    0x0000,             // Address Translation Offset
                    0x0CF8,             // Address Length
                    ,, , TypeStatic)
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000,             // Address Space Granularity
                    0x0D00,             // Address Range Minimum
                    0xFFFF,             // Address Range Maximum
                    0x0000,             // Address Translation Offset
                    0xF300,             // Address Length
                    ,, , TypeStatic)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                    0x00000000,         // Address Space Granularity
                    0x000A0000,         // Address Range Minimum
                    0x000BFFFF,         // Address Range Maximum
                    0x00000000,         // Address Translation Offset
                    0x00020000,         // Address Length
                    ,, , AddressRangeMemory, TypeStatic)
                DWordMemory (ResourceProducer, PosDecode, MinNotFixed, MaxFixed, NonCacheable, ReadWrite,
                    0x00000000,         // Address Space Granularity
                    0x00000000,         // Address Range Minimum
                    0xFEBFFFFF,         // Address Range Maximum
                    0x00000000,         // Address Translation Offset
                    0x00000000,         // Address Length
                    ,, MEMF, AddressRangeMemory, TypeStatic)
            })
                CreateDWordField (MEMP, \_SB.PCI0._CRS.MEMF._MIN, PMIN)
                CreateDWordField (MEMP, \_SB.PCI0._CRS.MEMF._MAX, PMAX)
                CreateDWordField (MEMP, \_SB.PCI0._CRS.MEMF._LEN, PLEN)
                /* compute available RAM */
                Add(CMRD(0x34), ShiftLeft(CMRD(0x35), 8), Local0)
                ShiftLeft(Local0, 16, Local0)
                Add(Local0, 0x1000000, Local0)
                /* update field of last region */
                Store(Local0, PMIN)
                Subtract (PMAX, PMIN, PLEN)
                Increment (PLEN)
                Return (MEMP)
            }
        }
    }

    Scope(\_SB.PCI0) {

	/* PIIX3 ISA bridge */
        Device (ISA) {
            Name (_ADR, 0x00010000)

            /* PIIX PCI to ISA irq remapping */
            OperationRegion (P40C, PCI_Config, 0x60, 0x04)

            /* Real-time clock */
            Device (RTC)
            {
                Name (_HID, EisaId ("PNP0B00"))
                Name (_CRS, ResourceTemplate ()
                {
                    IO (Decode16, 0x0070, 0x0070, 0x10, 0x02)
                    IRQNoFlags () {8}
                    IO (Decode16, 0x0072, 0x0072, 0x02, 0x06)
                })
            }

            /* Keyboard seems to be important for WinXP install */
            Device (KBD)
            {
                Name (_HID, EisaId ("PNP0303"))
                Method (_STA, 0, NotSerialized)
                {
                    Return (0x0f)
                }

                Method (_CRS, 0, NotSerialized)
                {
                     Name (TMP, ResourceTemplate ()
                     {
                    IO (Decode16,
                        0x0060,             // Address Range Minimum
                        0x0060,             // Address Range Maximum
                        0x01,               // Address Alignment
                        0x01,               // Address Length
                        )
                    IO (Decode16,
                        0x0064,             // Address Range Minimum
                        0x0064,             // Address Range Maximum
                        0x01,               // Address Alignment
                        0x01,               // Address Length
                        )
                    IRQNoFlags ()
                        {1}
                    })
                    Return (TMP)
                }
            }

	    /* PS/2 mouse */
            Device (MOU)
            {
                Name (_HID, EisaId ("PNP0F13"))
                Method (_STA, 0, NotSerialized)
                {
                    Return (0x0f)
                }

                Method (_CRS, 0, NotSerialized)
                {
                    Name (TMP, ResourceTemplate ()
                    {
                         IRQNoFlags () {12}
                    })
                    Return (TMP)
                }
            }

	    /* PS/2 floppy controller */
	    Device (FDC0)
	    {
	        Name (_HID, EisaId ("PNP0700"))
		Method (_STA, 0, NotSerialized)
		{
		    Return (0x0F)
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
                        IO (Decode16, 0x03F2, 0x03F2, 0x00, 0x04)
                        IO (Decode16, 0x03F7, 0x03F7, 0x00, 0x01)
                        IRQNoFlags () {6}
                        DMA (Compatibility, NotBusMaster, Transfer8) {2}
                    })
		    Return (BUF0)
		}
	    }

	    /* Parallel port */
	    Device (LPT)
	    {
	        Name (_HID, EisaId ("PNP0400"))
		Method (_STA, 0, NotSerialized)
		{
		    Store (\_SB.PCI0.PX13.DRSA, Local0)
		    And (Local0, 0x80000000, Local0)
		    If (LEqual (Local0, 0))
		    {
			Return (0x00)
		    }
		    Else
		    {
			Return (0x0F)
		    }
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
			IO (Decode16, 0x0378, 0x0378, 0x08, 0x08)
			IRQNoFlags () {7}
		    })
		    Return (BUF0)
		}
	    }

	    /* Serial Ports */
	    Device (COM1)
	    {
	        Name (_HID, EisaId ("PNP0501"))
		Name (_UID, 0x01)
		Method (_STA, 0, NotSerialized)
		{
		    Store (\_SB.PCI0.PX13.DRSC, Local0)
		    And (Local0, 0x08000000, Local0)
		    If (LEqual (Local0, 0))
		    {
			Return (0x00)
		    }
		    Else
		    {
			Return (0x0F)
		    }
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
			IO (Decode16, 0x03F8, 0x03F8, 0x00, 0x08)
                	IRQNoFlags () {4}
		    })
		    Return (BUF0)
		}
	    }

	    Device (COM2)
	    {
	        Name (_HID, EisaId ("PNP0501"))
		Name (_UID, 0x02)
		Method (_STA, 0, NotSerialized)
		{
		    Store (\_SB.PCI0.PX13.DRSC, Local0)
		    And (Local0, 0x80000000, Local0)
		    If (LEqual (Local0, 0))
		    {
			Return (0x00)
		    }
		    Else
		    {
			Return (0x0F)
		    }
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
			IO (Decode16, 0x02F8, 0x02F8, 0x00, 0x08)
                	IRQNoFlags () {3}
		    })
		    Return (BUF0)
		}
	    }
        }

	/* PIIX4 PM */
        Device (PX13) {
	    Name (_ADR, 0x00010003)

	    OperationRegion (P13C, PCI_Config, 0x5c, 0x24)
	    Field (P13C, DWordAcc, NoLock, Preserve)
	    {
		DRSA, 32,
		DRSB, 32,
		DRSC, 32,
		DRSE, 32,
		DRSF, 32,
		DRSG, 32,
		DRSH, 32,
		DRSI, 32,
		DRSJ, 32
	    }
	}
    }

    /* PCI IRQs */
    Scope(\_SB) {
         Field (\_SB.PCI0.ISA.P40C, ByteAcc, NoLock, Preserve)
         {
             PRQ0,   8,
             PRQ1,   8,
             PRQ2,   8,
             PRQ3,   8
         }

        Device(LNKA){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 1)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ0, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ0, 0x80, PRQ0)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ0, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ0)
                }
        }
        Device(LNKB){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 2)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ1, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ1, 0x80, PRQ1)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ1, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ1)
                }
        }
        Device(LNKC){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 3)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ2, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ2, 0x80, PRQ2)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ2, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ2)
                }
        }
        Device(LNKD){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 4)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ3, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ3, 0x80, PRQ3)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ3, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ3)
                }
        }
    }

    /* S5 = power off state */
    Name (_S5, Package (4) {
        0x00, // PM1a_CNT.SLP_TYP
        0x00, // PM2a_CNT.SLP_TYP
        0x00, // reserved
        0x00, // reserved
    })
    Scope (\_GPE)
    {
        Method(_L00) {
            /* Up status */
            If (And(\_PR.PRU, 0x2)) {
                Notify(\_PR.CPU1,1)
            }

            If (And(\_PR.PRU, 0x4)) {
                Notify(\_PR.CPU2,1)
            }

            If (And(\_PR.PRU, 0x8)) {
                Notify(\_PR.CPU3,1)
            }

            If (And(\_PR.PRU, 0x10)) {
                Notify(\_PR.CPU4,1)
            }

            If (And(\_PR.PRU, 0x20)) {
                Notify(\_PR.CPU5,1)
            }

            If (And(\_PR.PRU, 0x40)) {
                Notify(\_PR.CPU6,1)
            }

            If (And(\_PR.PRU, 0x80)) {
                Notify(\_PR.CPU7,1)
            }

            If (And(\_PR.PRU, 0x100)) {
                Notify(\_PR.CPU8,1)
            }

            If (And(\_PR.PRU, 0x200)) {
                Notify(\_PR.CPU9,1)
            }

            If (And(\_PR.PRU, 0x400)) {
                Notify(\_PR.CPUA,1)
            }

            If (And(\_PR.PRU, 0x800)) {
                Notify(\_PR.CPUB,1)
            }

            If (And(\_PR.PRU, 0x1000)) {
                Notify(\_PR.CPUC,1)
            }

            If (And(\_PR.PRU, 0x2000)) {
                Notify(\_PR.CPUD,1)
            }

            If (And(\_PR.PRU, 0x4000)) {
                Notify(\_PR.CPUE,1)
            }

            /* Down status */
            If (And(\_PR.PRD, 0x2)) {
                Notify(\_PR.CPU1,3)
            }

            If (And(\_PR.PRD, 0x4)) {
                Notify(\_PR.CPU2,3)
            }

            If (And(\_PR.PRD, 0x8)) {
                Notify(\_PR.CPU3,3)
            }

            If (And(\_PR.PRD, 0x10)) {
                Notify(\_PR.CPU4,3)
            }

            If (And(\_PR.PRD, 0x20)) {
                Notify(\_PR.CPU5,3)
            }

            If (And(\_PR.PRD, 0x40)) {
                Notify(\_PR.CPU6,3)
            }

            If (And(\_PR.PRD, 0x80)) {
                Notify(\_PR.CPU7,3)
            }

            If (And(\_PR.PRD, 0x100)) {
                Notify(\_PR.CPU8,3)
            }

            If (And(\_PR.PRD, 0x200)) {
                Notify(\_PR.CPU9,3)
            }

            If (And(\_PR.PRD, 0x400)) {
                Notify(\_PR.CPUA,3)
            }

            If (And(\_PR.PRD, 0x800)) {
                Notify(\_PR.CPUB,3)
            }

            If (And(\_PR.PRD, 0x1000)) {
                Notify(\_PR.CPUC,3)
            }

            If (And(\_PR.PRD, 0x2000)) {
                Notify(\_PR.CPUD,3)
            }

            If (And(\_PR.PRD, 0x4000)) {
                Notify(\_PR.CPUE,3)
            }

            Return(0x01)
        }
        Method(_L01) {
            Return(0x01)
        }
        Method(_L02) {
            Return(0x01)
        }
        Method(_L03) {
            Return(0x01)
        }
        Method(_L04) {
            Return(0x01)
        }
        Method(_L05) {
            Return(0x01)
        }
        Method(_L06) {
            Return(0x01)
        }
        Method(_L07) {
            Return(0x01)
        }
        Method(_L08) {
            Return(0x01)
        }
        Method(_L09) {
            Return(0x01)
        }
        Method(_L0A) {
            Return(0x01)
        }
        Method(_L0B) {
            Return(0x01)
        }
        Method(_L0C) {
            Return(0x01)
        }
        Method(_L0D) {
            Return(0x01)
        }
        Method(_L0E) {
            Return(0x01)
        }
        Method(_L0F) {
            Return(0x01)
        }
    }
}
