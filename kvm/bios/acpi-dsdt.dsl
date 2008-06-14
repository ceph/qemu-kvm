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

#define gen_processor(nr, name) 				            \
	Processor (CPU##name, nr, 0x0000b010, 0x06) {                       \
            Name (TMP, Buffer(0x8) {0x0, 0x8, nr, nr, 0x1, 0x0, 0x0, 0x0})  \
            Method(_MAT, 0) {                                               \
                If (And(\_PR.PRU, ShiftLeft(1, nr))) { Return(TMP) }        \
                Else { Return(0x0) }                                        \
            }                                                               \
            Method (_STA) {                                                 \
                Return(0xF)                                                 \
            }                                                               \
        }                                                                   \



        Processor (CPU0, 0x00, 0x0000b010, 0x06) {Method (_STA) { Return(0xF)}}
	gen_processor(1, 1)
	gen_processor(2, 2)
	gen_processor(3, 3)
	gen_processor(4, 4)
	gen_processor(5, 5)
	gen_processor(6, 6)
	gen_processor(7, 7)
	gen_processor(8, 8)
	gen_processor(9, 9)
	gen_processor(10, A)
	gen_processor(11, B)
	gen_processor(12, C)
	gen_processor(13, D)
	gen_processor(14, E)
    }

    Scope (\)
    {
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

#define prt_slot(nr, lnk0, lnk1, lnk2, lnk3) \
	Package() { nr##ffff, 0, lnk0, 0 }, \
	Package() { nr##ffff, 1, lnk1, 0 }, \
	Package() { nr##ffff, 2, lnk2, 0 }, \
	Package() { nr##ffff, 3, lnk3, 0 }

#define prt_slot0(nr) prt_slot(nr, LNKD, LNKA, LNKB, LNKC)
#define prt_slot1(nr) prt_slot(nr, LNKA, LNKB, LNKC, LNKD)
#define prt_slot2(nr) prt_slot(nr, LNKB, LNKC, LNKD, LNKA)
#define prt_slot3(nr) prt_slot(nr, LNKC, LNKD, LNKA, LNKB)

		prt_slot0(0x0000),
		prt_slot1(0x0001),
		prt_slot2(0x0002),
		prt_slot3(0x0003),
		prt_slot0(0x0004),
		prt_slot1(0x0005),
		prt_slot2(0x0006),
		prt_slot3(0x0007),
		prt_slot0(0x0008),
		prt_slot1(0x0009),
		prt_slot2(0x000a),
		prt_slot3(0x000b),
		prt_slot0(0x000c),
		prt_slot1(0x000d),
		prt_slot2(0x000e),
		prt_slot3(0x000f),
		prt_slot0(0x0010),
		prt_slot1(0x0011),
		prt_slot2(0x0012),
		prt_slot3(0x0013),
		prt_slot0(0x0014),
		prt_slot1(0x0015),
		prt_slot2(0x0016),
		prt_slot3(0x0017),
		prt_slot0(0x0018),
		prt_slot1(0x0019),
		prt_slot2(0x001a),
		prt_slot3(0x001b),
		prt_slot0(0x001c),
		prt_slot1(0x001d),
		prt_slot2(0x001e),
		prt_slot3(0x001f),
            })

            OperationRegion(PCST, SystemIO, 0xae00, 0x08)
            Field (PCST, DWordAcc, NoLock, WriteAsZeros)
	    {
		PCIU, 32,
		PCID, 32,
	    }

            OperationRegion(SEJ, SystemIO, 0xae08, 0x04)
            Field (SEJ, DWordAcc, NoLock, WriteAsZeros)
            {
                B0EJ, 32,
            }

            Device (S1) {              // Slot 1
               Name (_ADR, 0x00010000)
               Method (_EJ0,1) {
                    Store(0x2, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 1)
            }

            Device (S2) {              // Slot 2
               Name (_ADR, 0x00020000)
               Method (_EJ0,1) {
                    Store(0x4, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 2)
            }

            Device (S3) {              // Slot 3
               Name (_ADR, 0x00030000)
               Method (_EJ0,1) {
                    Store (0x8, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 3)
            }

            Device (S4) {              // Slot 4
               Name (_ADR, 0x00040000)
               Method (_EJ0,1) {
                    Store(0x10, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 4)
            }

            Device (S5) {              // Slot 5
               Name (_ADR, 0x00050000)
               Method (_EJ0,1) {
                    Store(0x20, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 5)
            }

            Device (S6) {              // Slot 6
               Name (_ADR, 0x00060000)
               Method (_EJ0,1) {
                    Store(0x40, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 6)
            }

            Device (S7) {              // Slot 7
               Name (_ADR, 0x00070000)
               Method (_EJ0,1) {
                    Store(0x80, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 7)
            }

            Device (S8) {              // Slot 8
               Name (_ADR, 0x00080000)
               Method (_EJ0,1) {
                    Store(0x100, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 8)
            }

            Device (S9) {              // Slot 9
               Name (_ADR, 0x00090000)
               Method (_EJ0,1) {
                    Store(0x200, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 9)
            }

            Device (S10) {              // Slot 10
               Name (_ADR, 0x000A0000)
               Method (_EJ0,1) {
                    Store(0x400, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 10)
            }

            Device (S11) {              // Slot 11
               Name (_ADR, 0x000B0000)
               Method (_EJ0,1) {
                    Store(0x800, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 11)
            }

            Device (S12) {              // Slot 12
               Name (_ADR, 0x000C0000)
               Method (_EJ0,1) {
                    Store(0x1000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 12)
            }

            Device (S13) {              // Slot 13
               Name (_ADR, 0x000D0000)
               Method (_EJ0,1) {
                    Store(0x2000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 13)
            }

            Device (S14) {              // Slot 14
               Name (_ADR, 0x000E0000)
               Method (_EJ0,1) {
                    Store(0x4000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 14)
            }

            Device (S15) {              // Slot 15
               Name (_ADR, 0x000F0000)
               Method (_EJ0,1) {
                    Store(0x8000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 15)
            }

            Device (S16) {              // Slot 16
               Name (_ADR, 0x00100000)
               Method (_EJ0,1) {
                    Store(0x10000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 16)
            }

            Device (S17) {              // Slot 17
               Name (_ADR, 0x00110000)
               Method (_EJ0,1) {
                    Store(0x20000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 17)
            }

            Device (S18) {              // Slot 18
               Name (_ADR, 0x00120000)
               Method (_EJ0,1) {
                    Store(0x40000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 18)
            }

            Device (S19) {              // Slot 19
               Name (_ADR, 0x00130000)
               Method (_EJ0,1) {
                    Store(0x80000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 19)
            }

            Device (S20) {              // Slot 20
               Name (_ADR, 0x00140000)
               Method (_EJ0,1) {
                    Store(0x100000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 20)
            }

            Device (S21) {              // Slot 21
               Name (_ADR, 0x00150000)
               Method (_EJ0,1) {
                    Store(0x200000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 21)
            }

            Device (S22) {              // Slot 22
               Name (_ADR, 0x00160000)
               Method (_EJ0,1) {
                    Store(0x400000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 22)
            }

            Device (S23) {              // Slot 23
               Name (_ADR, 0x00170000)
               Method (_EJ0,1) {
                    Store(0x800000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 23)
            }

            Device (S24) {              // Slot 24
               Name (_ADR, 0x00180000)
               Method (_EJ0,1) {
                    Store(0x1000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 24)
            }

            Device (S25) {              // Slot 25
               Name (_ADR, 0x00190000)
               Method (_EJ0,1) {
                    Store(0x2000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 25)
            }

            Device (S26) {              // Slot 26
               Name (_ADR, 0x001A0000)
               Method (_EJ0,1) {
                    Store(0x4000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 26)
            }

            Device (S27) {              // Slot 27
               Name (_ADR, 0x001B0000)
               Method (_EJ0,1) {
                    Store(0x8000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 27)
            }

            Device (S28) {              // Slot 28
               Name (_ADR, 0x001C0000)
               Method (_EJ0,1) {
                    Store(0x10000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 28)
            }

            Device (S29) {              // Slot 29
               Name (_ADR, 0x001D0000)
               Method (_EJ0,1) {
                    Store(0x20000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 29)
            }

            Device (S30) {              // Slot 30
               Name (_ADR, 0x001E0000)
               Method (_EJ0,1) {
                    Store(0x40000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 30)
            }

            Device (S31) {              // Slot 31
               Name (_ADR, 0x001F0000)
               Method (_EJ0,1) {
                    Store(0x80000000, B0EJ)
                    Return (0x0)
               }
               Name (_SUN, 31)
            }

            Name (_CRS, ResourceTemplate ()
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
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                    0x00000000,         // Address Space Granularity
                    0xE0000000,         // Address Range Minimum
                    0xFEBFFFFF,         // Address Range Maximum
                    0x00000000,         // Address Translation Offset
                    0x1EC00000,         // Address Length
                    ,, , AddressRangeMemory, TypeStatic)
            })
        }
    }

    Scope(\_SB.PCI0) {
        Device (VGA) {
                 Name (_ADR, 0x00020000)
                 Method (_S1D, 0, NotSerialized)
                 {
                         Return (0x00)
                 }
                 Method (_S2D, 0, NotSerialized)
                 {
                         Return (0x00)
                 }
                 Method (_S3D, 0, NotSerialized)
                 {
                         Return (0x00)
                 }
        }

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

    /*
     * S3 (suspend-to-ram), S4 (suspend-to-disk) and S5 (power-off) type codes:
     * must match piix4 emulation.
     */
    Name (\_S3, Package (0x04)
    {
        0x01,  /* PM1a_CNT.SLP_TYP */
        0x01,  /* PM1b_CNT.SLP_TYP */
        Zero,  /* reserved */
        Zero   /* reserved */
    })
    Name (\_S4, Package (0x04)
    {
        Zero,  /* PM1a_CNT.SLP_TYP */
        Zero,  /* PM1b_CNT.SLP_TYP */
        Zero,  /* reserved */
        Zero   /* reserved */
    })
    Name (\_S5, Package (0x04)
    {
        Zero,  /* PM1a_CNT.SLP_TYP */
        Zero,  /* PM1b_CNT.SLP_TYP */
        Zero,  /* reserved */
        Zero   /* reserved */
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
            /* Up status */
            If (And(\_SB.PCI0.PCIU, 0x2)) {
                Notify(\_SB.PCI0.S1, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x4)) {
                Notify(\_SB.PCI0.S2, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x8)) {
                Notify(\_SB.PCI0.S3, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x10)) {
                Notify(\_SB.PCI0.S4, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x20)) {
                Notify(\_SB.PCI0.S5, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x40)) {
                Notify(\_SB.PCI0.S6, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x80)) {
                Notify(\_SB.PCI0.S7, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x0100)) {
                Notify(\_SB.PCI0.S8, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x0200)) {
                Notify(\_SB.PCI0.S9, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x0400)) {
                Notify(\_SB.PCI0.S10, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x0800)) {
                Notify(\_SB.PCI0.S11, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x1000)) {
                Notify(\_SB.PCI0.S12, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x2000)) {
                Notify(\_SB.PCI0.S13, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x4000)) {
                Notify(\_SB.PCI0.S14, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x8000)) {
                Notify(\_SB.PCI0.S15, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x10000)) {
                Notify(\_SB.PCI0.S16, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x20000)) {
                Notify(\_SB.PCI0.S17, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x40000)) {
                Notify(\_SB.PCI0.S18, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x80000)) {
                Notify(\_SB.PCI0.S19, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x100000)) {
                Notify(\_SB.PCI0.S20, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x200000)) {
                Notify(\_SB.PCI0.S21, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x400000)) {
                Notify(\_SB.PCI0.S22, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x800000)) {
                Notify(\_SB.PCI0.S23, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x1000000)) {
                Notify(\_SB.PCI0.S24, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x2000000)) {
                Notify(\_SB.PCI0.S25, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x4000000)) {
                Notify(\_SB.PCI0.S26, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x8000000)) {
                Notify(\_SB.PCI0.S27, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x10000000)) {
                Notify(\_SB.PCI0.S28, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x20000000)) {
                Notify(\_SB.PCI0.S29, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x40000000)) {
                Notify(\_SB.PCI0.S30, 0x1)
            }

            If (And(\_SB.PCI0.PCIU, 0x80000000)) {
                Notify(\_SB.PCI0.S31, 0x1)
            }

            /* Down status */
            If (And(\_SB.PCI0.PCID, 0x2)) {
                Notify(\_SB.PCI0.S1, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x4)) {
                Notify(\_SB.PCI0.S2, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x8)) {
                Notify(\_SB.PCI0.S3, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x10)) {
                Notify(\_SB.PCI0.S4, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x20)) {
                Notify(\_SB.PCI0.S5, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x40)) {
                Notify(\_SB.PCI0.S6, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x80)) {
                Notify(\_SB.PCI0.S7, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x0100)) {
                Notify(\_SB.PCI0.S8, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x0200)) {
                Notify(\_SB.PCI0.S9, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x0400)) {
                Notify(\_SB.PCI0.S10, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x0800)) {
                Notify(\_SB.PCI0.S11, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x1000)) {
                Notify(\_SB.PCI0.S12, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x2000)) {
                Notify(\_SB.PCI0.S13, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x4000)) {
                Notify(\_SB.PCI0.S14, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x8000)) {
                Notify(\_SB.PCI0.S15, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x10000)) {
                Notify(\_SB.PCI0.S16, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x20000)) {
                Notify(\_SB.PCI0.S17, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x40000)) {
                Notify(\_SB.PCI0.S18, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x80000)) {
                Notify(\_SB.PCI0.S19, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x100000)) {
                Notify(\_SB.PCI0.S20, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x200000)) {
                Notify(\_SB.PCI0.S21, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x400000)) {
                Notify(\_SB.PCI0.S22, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x800000)) {
                Notify(\_SB.PCI0.S23, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x1000000)) {
                Notify(\_SB.PCI0.S24, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x2000000)) {
                Notify(\_SB.PCI0.S25, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x4000000)) {
                Notify(\_SB.PCI0.S26, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x8000000)) {
                Notify(\_SB.PCI0.S27, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x10000000)) {
                Notify(\_SB.PCI0.S28, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x20000000)) {
                Notify(\_SB.PCI0.S29, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x40000000)) {
                Notify(\_SB.PCI0.S30, 0x3)
            }

            If (And(\_SB.PCI0.PCID, 0x80000000)) {
                Notify(\_SB.PCI0.S31, 0x3)
            }

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
