// ============================================================================================
//  
//  Copyright (C) 2002 Jeroen Janssen
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
// 
// ============================================================================================
//  
//  This VBE is part of the VGA Bios specific to the plex86/bochs Emulated VGA card. 
//  You can NOT drive any physical vga card with it. 
//
// ============================================================================================
//  
//  This VBE Bios is based on information taken from :
//   - VESA BIOS EXTENSION (VBE) Core Functions Standard Version 3.0 located at www.vesa.org
//
// ============================================================================================


// defines available
// enable LFB support (depends upon bochs-vbe-lfb patch)
#define VBE_HAVE_LFB

// disable VESA/VBE2 check in vbe info
//#define VBE2_NO_VESA_CHECK

// dynamicly generate a mode_info list
//#define DYN_LIST


#include "vbe.h"
#include "vbetables.h"


// The current OEM Software Revision of this VBE Bios
#define VBE_OEM_SOFTWARE_REV 0x0002;

#define VBEInfoData ((VbeInfoBlock *) 0)

extern char vbebios_copyright;
extern char vbebios_vendor_name;
extern char vbebios_product_name;
extern char vbebios_product_revision;

// FIXME: find out why we cannot use the dynamic list generation (due to a bug somewhere)
//#define DYN_LIST

#ifndef DYN_LIST
extern Bit16u vbebios_mode_list;
#endif

ASM_START
// FIXME: 'merge' these (c) etc strings with the vgabios.c strings?
_vbebios_copyright:
.ascii       "Bochs/Plex86 VBE(C) 2002 Jeroen Janssen <japj@darius.demon.nl>"
.byte        0x00

_vbebios_vendor_name:
.ascii       "Bochs/Plex86 Developers"
.byte        0x00

_vbebios_product_name:
.ascii       "Bochs/Plex86 VBE Adapter"
.byte        0x00

_vbebios_product_revision:
.ascii       "$Id: vbe.c,v 1.31 2003/07/10 17:07:29 vruppert Exp $"
.byte        0x00

_vbebios_info_string:
.ascii      "Bochs VBE Display Adapter enabled"
.byte	0x0a,0x0d
.byte	0x0a,0x0d
.byte	0x00

_no_vbebios_info_string:
.ascii      "NO Bochs VBE Support available!"
.byte	0x0a,0x0d
.byte	0x0a,0x0d
.byte 0x00


#ifndef DYN_LIST
// FIXME: for each new mode add a statement here
//        at least until dynamic list creation is working
_vbebios_mode_list:

.word VBE_VESA_MODE_640X400X8
.word VBE_VESA_MODE_640X480X8
.word VBE_VESA_MODE_800X600X4
.word VBE_VESA_MODE_800X600X8
.word VBE_VESA_MODE_1024X768X8
.word VBE_VESA_MODE_640X480X1555
.word VBE_VESA_MODE_640X480X565
.word VBE_VESA_MODE_640X480X888
.word VBE_VESA_MODE_800X600X1555
.word VBE_VESA_MODE_800X600X565
.word VBE_VESA_MODE_800X600X888
.word VBE_VESA_MODE_1024X768X1555
.word VBE_VESA_MODE_1024X768X565
.word VBE_VESA_MODE_1024X768X888
.word VBE_OWN_MODE_640X480X8888
.word VBE_OWN_MODE_800X600X8888
.word VBE_OWN_MODE_1024X768X8888
.word VBE_OWN_MODE_320X200X8
.word VBE_VESA_MODE_END_OF_LIST
#endif

ASM_END

// from rombios.c
#define PANIC_PORT 0x501

ASM_START
MACRO HALT
  ;; the HALT macro is called with the line number of the HALT call.
  ;; The line number is then sent to the PANIC_PORT, causing Bochs to
  ;; print a BX_PANIC message.  This will normally halt the simulation
  ;; with a message such as "BIOS panic at rombios.c, line 4091".
  ;; However, users can choose to make panics non-fatal and continue.
  mov dx,#PANIC_PORT
  mov ax,#?1
  out dx,ax 
MEND
ASM_END

// DISPI ioport functions
// FIXME: what if no VBE host side code?
static Bit16u dispi_get_id()
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_ID);
  return inw(VBE_DISPI_IOPORT_DATA);  
}

static void dispi_set_id(id)
  Bit16u id;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_ID);
  outw(VBE_DISPI_IOPORT_DATA,id);
}

static void dispi_set_xres(xres)
  Bit16u xres;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_XRES);
  outw(VBE_DISPI_IOPORT_DATA,xres);
}

static void dispi_set_yres(yres)
  Bit16u yres;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_YRES);
  outw(VBE_DISPI_IOPORT_DATA,yres);
}

static void dispi_set_bpp(bpp)
  Bit16u bpp;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_BPP);
  outw(VBE_DISPI_IOPORT_DATA,bpp);
}

static Bit16u dispi_get_enable()
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_ENABLE);
  return inw(VBE_DISPI_IOPORT_DATA);  
}

void dispi_set_enable(enable)
  Bit16u enable;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_ENABLE);
  outw(VBE_DISPI_IOPORT_DATA,enable);
}

static void dispi_set_bank(bank)
  Bit16u bank;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_BANK);
  outw(VBE_DISPI_IOPORT_DATA,bank);
}

static Bit16u dispi_get_bank()
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_BANK);
  return inw(VBE_DISPI_IOPORT_DATA);
}

static void dispi_set_bank_farcall()
{
ASM_START
  cmp bx,#0x0100
  je dispi_set_bank_farcall_get
  or bx,bx
  jnz dispi_set_bank_farcall_error
  push dx
  mov ax,# VBE_DISPI_INDEX_BANK
  mov dx,# VBE_DISPI_IOPORT_INDEX
  out dx,ax
  pop ax
  mov dx,# VBE_DISPI_IOPORT_DATA
  out dx,ax
  retf
dispi_set_bank_farcall_get:
  mov ax,# VBE_DISPI_INDEX_BANK
  mov dx,# VBE_DISPI_IOPORT_INDEX
  out dx,ax
  mov dx,# VBE_DISPI_IOPORT_DATA
  in ax,dx
  mov dx,ax
  retf
dispi_set_bank_farcall_error:
  mov ax,#0x014F
  retf
ASM_END
}

static void dispi_set_x_offset(offset)
  Bit16u offset;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_X_OFFSET);
  outw(VBE_DISPI_IOPORT_DATA,offset);
}

static Bit16u dispi_get_x_offset()
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_X_OFFSET);
  return inw(VBE_DISPI_IOPORT_DATA);
}

static void dispi_set_y_offset(offset)
  Bit16u offset;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_Y_OFFSET);
  outw(VBE_DISPI_IOPORT_DATA,offset);
}

static Bit16u dispi_get_y_offset()
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_Y_OFFSET);
  return inw(VBE_DISPI_IOPORT_DATA);
}

static void dispi_set_virt_width(width)
  Bit16u width;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_VIRT_WIDTH);
  outw(VBE_DISPI_IOPORT_DATA,width);
}

static Bit16u dispi_get_virt_width()
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_VIRT_WIDTH);
  return inw(VBE_DISPI_IOPORT_DATA);
}
/*
static void dispi_set_virt_height(height)
  Bit16u height;
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_VIRT_HEIGHT);
  outw(VBE_DISPI_IOPORT_DATA,height);
}
*/
static Bit16u dispi_get_virt_height()
{
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_VIRT_HEIGHT);
  return inw(VBE_DISPI_IOPORT_DATA);
}


// ModeInfo helper function
static ModeInfoListItem* mode_info_find_mode(mode, using_lfb)
  Bit16u mode; Boolean using_lfb;
{
  ModeInfoListItem  *cur_info=&mode_info_list;

  while (cur_info->mode != VBE_VESA_MODE_END_OF_LIST)
  {
    if (cur_info->mode == mode)
    {
      if (!using_lfb)
      {
        return cur_info;
      }
      else if (cur_info->info.ModeAttributes & VBE_MODE_ATTRIBUTE_LINEAR_FRAME_BUFFER_MODE)
      {
        return cur_info;
      }
      else
      {
        cur_info++;
      }
    }
    else
    {
      cur_info++;
    }
  }

  return 0;
}

/** Has VBE display - Returns true if VBE display detected
 *
 */
Boolean vbe_has_vbe_display()
{
  dispi_set_id(VBE_DISPI_ID2);

  return (dispi_get_id()==VBE_DISPI_ID2);
}

/** VBE Init - Initialise the Vesa Bios Extension Code
 *
 *  This function does a sanity check on the host side display code interface.
 */
void vbe_init()
{
  Bit16u dispi_id;
  
  outw(VBE_DISPI_IOPORT_INDEX,VBE_DISPI_INDEX_ID);
  outw(VBE_DISPI_IOPORT_DATA,VBE_DISPI_ID0);
  
  dispi_id=inw(VBE_DISPI_IOPORT_DATA);
  
  if (dispi_id!=VBE_DISPI_ID0)
  {
//FIXME this results in a 'rombios.c' line panic, but it's actually a 'vbe.c' panic
ASM_START    
    HALT(__LINE__)
ASM_END    
  }
//#ifdef DEBUG
  printf("VBE Bios $Id: vbe.c,v 1.31 2003/07/10 17:07:29 vruppert Exp $\n");
//#endif  
}

/** VBE Display Info - Display information on screen about the VBE
 */
void vbe_display_info()
{
  // Check for VBE display extension in Bochs
  if (vbe_has_vbe_display())
  {
    ASM_START
     mov ax,#0xc000
     mov ds,ax
     mov si,#_vbebios_info_string
     call _display_string
    ASM_END  
  }
  else
  {
    ASM_START
     mov ax,#0xc000
     mov ds,ax
     mov si,#_no_vbebios_info_string
     call _display_string
    ASM_END  
    
  }
}  

/** Function 00h - Return VBE Controller Information
 * 
 * Input:
 *              AX      = 4F00h
 *              ES:DI   = Pointer to buffer in which to place VbeInfoBlock structure
 *                        (VbeSignature should be VBE2 when VBE 2.0 information is desired and
 *                        the info block is 512 bytes in size)
 * Output:
 *              AX      = VBE Return Status
 * 
 */
void vbe_biosfn_return_controller_information(AX, ES, DI)
Bit16u *AX;Bit16u ES;Bit16u DI;
{
        Bit16u            ss=get_SS();
        VbeInfoBlock      vbe_info_block;
        Bit16u            status;
        Bit16u            result;
        Bit16u            vbe2_info;
#ifdef DYN_LIST
        Bit16u            *video_mode_list;
#endif
        Bit16u            cur_mode=0;
        ModeInfoListItem  *cur_info=&mode_info_list;
        
        status = read_word(ss, AX);
        
#ifdef DEBUG
        printf("VBE vbe_biosfn_return_vbe_info ES%x DI%x AX%x\n",ES,DI,status);
#endif

        vbe2_info = 0;
#ifdef VBE2_NO_VESA_CHECK
#else
        // get vbe_info_block into local variable
        memcpyb(ss, &vbe_info_block, ES, DI, sizeof(vbe_info_block));

        // check for VBE2 signature
        if (((vbe_info_block.VbeSignature[0] == 'V') &&
             (vbe_info_block.VbeSignature[1] == 'B') &&
             (vbe_info_block.VbeSignature[2] == 'E') &&
             (vbe_info_block.VbeSignature[3] == '2')) ||
             
            ((vbe_info_block.VbeSignature[0] == 'V') &&
             (vbe_info_block.VbeSignature[1] == 'E') &&
             (vbe_info_block.VbeSignature[2] == 'S') &&
             (vbe_info_block.VbeSignature[3] == 'A')) )
        {
                vbe2_info = 1;
#ifdef DEBUG
                printf("VBE correct VESA/VBE2 signature found\n");
#endif
        }
#endif
                
        // VBE Signature
        vbe_info_block.VbeSignature[0] = 'V';
        vbe_info_block.VbeSignature[1] = 'E';
        vbe_info_block.VbeSignature[2] = 'S';
        vbe_info_block.VbeSignature[3] = 'A';
        
        // VBE Version supported
        vbe_info_block.VbeVersion = 0x0200;
        
        // OEM String
        vbe_info_block.OemStringPtr_Seg = 0xc000;
        vbe_info_block.OemStringPtr_Off = &vbebios_copyright;
        
        // Capabilities
        vbe_info_block.Capabilities[0] = 0;
        vbe_info_block.Capabilities[1] = 0;
        vbe_info_block.Capabilities[2] = 0;
        vbe_info_block.Capabilities[3] = 0;

#ifdef DYN_LIST
        // FIXME: This doesn't work correctly somehow?
        // VBE Video Mode Pointer (dynamicly generated from the mode_info_list)
        vbe_info_block.VideoModePtr_Seg= ES ;//0xc000;
        vbe_info_block.VideoModePtr_Off= DI + 34;//&(VBEInfoData->Reserved);//&vbebios_mode_list;
#else
        // VBE Video Mode Pointer (staticly in rom)
        vbe_info_block.VideoModePtr_Seg = 0xc000;
        vbe_info_block.VideoModePtr_Off = &vbebios_mode_list;

#endif

#ifdef DYN_LIST

//      video_mode_list=(Bit16u*)&(vbe_info_block.Reserved);

        do
        {
#ifdef DEBUG
                printf("VBE found mode %x => %x\n", cur_info->mode,cur_mode);
#endif
//              *video_mode_list=cur_info->mode;
                vbe_info_block.Reserved[cur_mode] = cur_info->mode;
                
                cur_info++;
                //video_mode_list++;
                cur_mode++;
        } while (cur_info->mode != VBE_VESA_MODE_END_OF_LIST);
        
        // Add vesa mode list terminator
        vbe_info_block.Reserved[cur_mode] = VBE_VESA_MODE_END_OF_LIST;
#endif

        // VBE Total Memory (in 64b blocks)
        vbe_info_block.TotalMemory = VBE_TOTAL_VIDEO_MEMORY_DIV_64K;

        if (vbe2_info)
	{
                // OEM Stuff
                vbe_info_block.OemSoftwareRev = VBE_OEM_SOFTWARE_REV;
                vbe_info_block.OemVendorNamePtr_Seg = 0xc000;
                vbe_info_block.OemVendorNamePtr_Off = &vbebios_vendor_name;
                vbe_info_block.OemProductNamePtr_Seg = 0xc000;
                vbe_info_block.OemProductNamePtr_Off = &vbebios_product_name;
                vbe_info_block.OemProductRevPtr_Seg = 0xc000;
                vbe_info_block.OemProductRevPtr_Off = &vbebios_product_revision;

                // copy updates in vbe_info_block back
                memcpyb(ES, DI, ss, &vbe_info_block, sizeof(vbe_info_block));
        }
	else
	{
                // copy updates in vbe_info_block back (VBE 1.x compatibility)
                memcpyb(ES, DI, ss, &vbe_info_block, 256);
	}
                
        result = 0x4f;

        write_word(ss, AX, result);
}


/** Function 01h - Return VBE Mode Information
 * 
 * Input:
 *              AX      = 4F01h
 *              CX      = Mode Number
 *              ES:DI   = Pointer to buffer in which to place ModeInfoBlock structure
 * Output:
 *              AX      = VBE Return Status
 * 
 */
void vbe_biosfn_return_mode_information(AX, CX, ES, DI)
Bit16u *AX;Bit16u CX; Bit16u ES;Bit16u DI;
{
        Bit16u            result=0x0100;
        Bit16u            ss=get_SS();
        ModeInfoBlock     info;
        ModeInfoListItem  *cur_info;
        Boolean           using_lfb;

#ifdef DEBUG
        printf("VBE vbe_biosfn_return_mode_information ES%x DI%x CX%x\n",ES,DI,CX);
#endif

        using_lfb=((CX & VBE_MODE_LINEAR_FRAME_BUFFER) == VBE_MODE_LINEAR_FRAME_BUFFER);
        
        CX = (CX & 0x1ff);
        
        cur_info = mode_info_find_mode(CX, using_lfb, &cur_info);

        if (cur_info != 0)
        {
#ifdef DEBUG
                printf("VBE found mode %x\n",CX);
#endif        
                memsetb(ss, &info, 0, sizeof(ModeInfoBlock));
                memcpyb(ss, &info, 0xc000, &(cur_info->info), sizeof(ModeInfoBlockCompact));
                if (info.WinAAttributes & VBE_WINDOW_ATTRIBUTE_RELOCATABLE) {
                  info.WinFuncPtr = 0xC0000000UL;
                  *(Bit16u *)&(info.WinFuncPtr) = (Bit16u)(dispi_set_bank_farcall);
                }
                
                result = 0x4f;
        }
        else
        {
#ifdef DEBUG
                printf("VBE *NOT* found mode %x\n",CX);
#endif
                result = 0x100;
        }
        
        if (result == 0x4f)
        {
                // copy updates in mode_info_block back
                memcpyb(ES, DI, ss, &info, sizeof(info));
        }

        write_word(ss, AX, result);
}

/** Function 02h - Set VBE Mode
 * 
 * Input:
 *              AX      = 4F02h
 *              BX      = Desired Mode to set
 *              ES:DI   = Pointer to CRTCInfoBlock structure
 * Output:
 *              AX      = VBE Return Status
 * 
 */
void vbe_biosfn_set_mode(AX, BX, ES, DI)
Bit16u *AX;Bit16u BX; Bit16u ES;Bit16u DI;
{
        Bit16u            ss = get_SS();
        Bit16u            result;
        ModeInfoListItem  *cur_info;
        Boolean           using_lfb;
        Bit8u             no_clear;

        using_lfb=((BX & VBE_MODE_LINEAR_FRAME_BUFFER) == VBE_MODE_LINEAR_FRAME_BUFFER);
        no_clear=((BX & VBE_MODE_PRESERVE_DISPLAY_MEMORY) == VBE_MODE_PRESERVE_DISPLAY_MEMORY)?VBE_DISPI_NOCLEARMEM:0;

        BX = (BX & 0x1ff);

        //result=read_word(ss,AX);
        
        // check for non vesa mode
        if (BX<VBE_MODE_VESA_DEFINED)
        {
                Bit8u   mode;
                
                dispi_set_enable(VBE_DISPI_DISABLED);
                // call the vgabios in order to set the video mode
                // this allows for going back to textmode with a VBE call (some applications expect that to work)
                
                mode=(BX & 0xff);
                biosfn_set_video_mode(mode);
                result = 0x4f;
        }
        
        cur_info = mode_info_find_mode(BX, using_lfb, &cur_info);

        if (cur_info != 0)
        {
#ifdef DEBUG
                printf("VBE found mode %x, setting:\n", BX);
                printf("\txres%x yres%x bpp%x\n",
                        cur_info->info.XResolution,
                        cur_info->info.YResolution,
                        cur_info->info.BitsPerPixel);
#endif
                
                // first disable current mode (when switching between vesa modi)
                dispi_set_enable(VBE_DISPI_DISABLED);

                if (cur_info->mode == VBE_VESA_MODE_800X600X4)
                {
                  biosfn_set_video_mode(0x6a);
                }

                dispi_set_xres(cur_info->info.XResolution);
                dispi_set_yres(cur_info->info.YResolution);
                dispi_set_bpp(cur_info->info.BitsPerPixel);
                dispi_set_bank(0);
                dispi_set_enable(VBE_DISPI_ENABLED | no_clear);

                  // FIXME: store current mode in BIOS data area
  
                result = 0x4f;                  
        }
        else
        {
#ifdef DEBUG
                printf("VBE *NOT* found mode %x\n" , BX);
#endif        
                result = 0x100;
                
                // FIXME: redirect non VBE modi to normal VGA bios operation
                //        (switch back to VGA mode
                if (BX == 3)
                        result = 0x4f;
        }

        write_word(ss, AX, result);
}

/** Function 03h - Return Current VBE Mode
 * 
 * Input:
 *              AX      = 4F03h
 * Output:
 *              AX      = VBE Return Status
 *              BX      = Current VBE Mode
 * 
 */
void vbe_biosfn_return_current_mode(AX, BX)
Bit16u *AX;Bit16u *BX;
{
        Bit16u ss=get_SS();
	Bit16u mode=0xffff;

#ifdef DEBUG
        printf("VBE vbe_biosfn_return_current_mode\n");
#endif
        
        if(dispi_get_enable())
        {
		// FIXME: get current mode from BIOS data area
	}
	else
	{
		mode=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE);
	}
        write_word(ss, AX, 0x4f);
        write_word(ss, BX, mode);
}


/** Function 04h - Save/Restore State
 * 
 * Input:
 *              AX      = 4F04h
 *              DL      = 00h Return Save/Restore State buffer size
 *                        01h Save State
 *                        02h Restore State
 *              CX      = Requested states
 *              ES:BX   = Pointer to buffer (if DL <> 00h)
 * Output:
 *              AX      = VBE Return Status
 *              BX      = Number of 64-byte blocks to hold the state buffer (if DL=00h)
 * 
 */
void vbe_biosfn_save_restore_state(AX, DL, CX, ES, BX)
{
}


/** Function 05h - Display Window Control
 * 
 * Input:
 *              AX      = 4F05h
 *     (16-bit) BH      = 00h Set memory window
 *                      = 01h Get memory window
 *              BL      = Window number
 *                      = 00h Window A
 *                      = 01h Window B
 *              DX      = Window number in video memory in window
 *                        granularity units (Set Memory Window only)
 * Note:
 *              If this function is called while in a linear frame buffer mode,
 *              this function must fail with completion code AH=03h
 * 
 * Output:
 *              AX      = VBE Return Status
 *              DX      = Window number in window granularity units
 *                        (Get Memory Window only)
 */
void vbe_biosfn_display_window_control(AX,BX,DX)
Bit16u *AX;Bit16u BX;Bit16u *DX;
{
        Bit16u            ss = get_SS();
        Bit16u            window = read_word(ss, DX);
        Bit16u            result = 0x014f;
        
        if (BX==0x0000)
        {
                dispi_set_bank(window);
                result = 0x4f;
        }
        else if (BX==0x0100)
        {
                window = dispi_get_bank();
                write_word(ss, DX, result);
                result = 0x4f;
        }
        write_word(ss, AX, result);
}


/** Function 06h - Set/Get Logical Scan Line Length
 *
 * Input:
 *              AX      = 4F06h
 *              BL      = 00h Set Scan Line Length in Pixels
 *                      = 01h Get Scan Line Length
 *                      = 02h Set Scan Line Length in Bytes
 *                      = 03h Get Maximum Scan Line Length
 *              CX      = If BL=00h Desired Width in Pixels
 *                        If BL=02h Desired Width in Bytes
 *                        (Ignored for Get Functions)
 * 
 * Output: 
 *              AX      = VBE Return Status
 *              BX      = Bytes Per Scan Line
 *              CX      = Actual Pixels Per Scan Line
 *                        (truncated to nearest complete pixel)
 *              DX      = Maximum Number of Scan Lines 
 */
void vbe_biosfn_set_get_logical_scan_line_length(AX,BX,CX,DX)
Bit16u *AX;Bit16u *BX;Bit16u *DX;Bit16u *DX;
{
	Bit16u ss=get_SS();
	Bit16u result=0x100;
	Bit16u width = read_word(ss, CX);
	Bit16u cmd = read_word(ss, BX);
	
	// check bl
	if ( ((cmd & 0xff) == 0x00) || ((cmd & 0xff) == 0x02) )
	{
		// set scan line lenght in pixels(0x00) or bytes (0x00)
		Bit16u new_width;
		Bit16u new_height;
		
		dispi_set_virt_width(width);
		new_width=dispi_get_virt_width();
		new_height=dispi_get_virt_height();
		
		if (new_width!=width)
		{
#ifdef DEBUG
                printf("* VBE width adjusted\n");
#endif
			
			// notify width adjusted
			result=0x024f;
		}
		else
		{
			result=0x4f;
		}
		
		// FIXME: adjust for higher bpp (in bytes)
		write_word(ss,BX,new_width);
		write_word(ss,CX,new_width);
		write_word(ss,DX,new_height);
	}

	write_word(ss, AX, result);	
}


/** Function 07h - Set/Get Display Start
 * 
 * Input(16-bit):
 *              AX      = 4F07h
 *              BH      = 00h Reserved and must be 00h
 *              BL      = 00h Set Display Start
 *                      = 01h Get Display Start
 *                      = 02h Schedule Display Start (Alternate)
 *                      = 03h Schedule Stereoscopic Display Start
 *                      = 04h Get Scheduled Display Start Status
 *                      = 05h Enable Stereoscopic Mode
 *                      = 06h Disable Stereoscopic Mode
 *                      = 80h Set Display Start during Vertical Retrace
 *                      = 82h Set Display Start during Vertical Retrace (Alternate)
 *                      = 83h Set Stereoscopic Display Start during Vertical Retrace
 *              ECX     = If BL=02h/82h Display Start Address in bytes
 *                        If BL=03h/83h Left Image Start Address in bytes
 *              EDX     = If BL=03h/83h Right Image Start Address in bytes
 *              CX      = If BL=00h/80h First Displayed Pixel In Scan Line
 *              DX      = If BL=00h/80h First Displayed Scan Line
 *
 * Output:
 *              AX      = VBE Return Status
 *              BH      = If BL=01h Reserved and will be 0
 *              CX      = If BL=01h First Displayed Pixel In Scan Line
 *                        If BL=04h 0 if flip has not occurred, not 0 if it has
 *              DX      = If BL=01h First Displayed Scan Line
 *
 * Input(32-bit): 
 *              BH      = 00h Reserved and must be 00h
 *              BL      = 00h Set Display Start
 *                      = 80h Set Display Start during Vertical Retrace
 *              CX      = Bits 0-15 of display start address
 *              DX      = Bits 16-31 of display start address
 *              ES      = Selector for memory mapped registers 
 */
void vbe_biosfn_set_get_display_start(AX,BX,CX,DX)
Bit16u *AX;Bit16u BX;Bit16u CX;Bit16u DX;
{
	Bit16u ss=get_SS();
	Bit16u result=0x100;
#ifdef DEBUG
 //       printf("VBE vbe_biosfn_set_get_display_start\n");
#endif
	
	// check for set display start
	if ((GET_BL()==0x00) || (GET_BL()==0x80))
	{
	  // 0x80 is during vertical retrace - is also used by sdd vbetest during multibuffering
#ifdef DEBUG
//        printf("VBE vbe_biosfn_set_get_display_start CX%x DX%x\n",CX,DX);
#endif
		
		dispi_set_x_offset(CX);
		dispi_set_y_offset(DX);
		result = 0x4f;
	}
	
	write_word(ss, AX, result);	
}


/** Function 08h - Set/Get Dac Palette Format
 * 
 * Input:
 *              AX      = 4F08h
 * Output:
 *              AX      = VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_set_get_dac_palette_format(AX)
{
}


/** Function 09h - Set/Get Palette Data
 * 
 * Input:
 *              AX      = 4F09h
 * Output:
 *              AX      = VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_set_get_palette_data(AX)
{
}

/** Function 0Ah - Return VBE Protected Mode Interface
 * 
 * Input:
 *              AX      = 4F0Ah
 * Output:
 *              AX      = VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_return_protected_mode_interface(AX)
{
}
