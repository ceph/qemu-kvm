// ============================================================================================
/*
 * vgabios.c
 */
// ============================================================================================
//  
//  Copyright (C) 2001 Christophe Bothamy
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
//  This VGA Bios is specific to the plex86/bochs Emulated VGA card. 
//  You can NOT drive any physical vga card with it. 
//     
// ============================================================================================
//  
//  This file contains code ripped from :
//   - rombios.c of plex86 
//
//  This VGA Bios contains fonts from :
//   - fntcol16.zip (c) by Joseph Gil avalable at :
//      ftp://ftp.simtel.net/pub/simtelnet/msdos/screen/fntcol16.zip
//     These fonts are public domain 
//
//  This VGA Bios is based on information taken from :
//   - Kevin Lawton's vga card emulation for bochs/plex86
//   - Ralf Brown's interrupts list available at http://www.cs.cmu.edu/afs/cs/user/ralf/pub/WWW/files.html
//   - Finn Thogersons' VGADOC4b available at http://home.worldonline.dk/~finth/
//   - Michael Abrash's Graphics Programming Black Book
//   - Francois Gervais' book "programmation des cartes graphiques cga-ega-vga" edited by sybex
//   - DOSEMU 1.0.1 source code for several tables values and formulas
//
// Thanks for patches, comments and ideas to :
//   - techt@pikeonline.net
//
// ============================================================================================

#include "vgabios.h"

#ifdef VBE
#include "vbe.h"
#endif

/* Declares */
static Bit8u          read_byte();
static Bit16u         read_word();
static void           write_byte();
static void           write_word();
static Bit8u          inb();
static Bit16u         inw();
static void           outb();
static void           outw();

static Bit16u         get_SS();

// Output
static void           printf();
static void           unimplemented();
static void           unknown();

static void init_vga_card();
static void init_bios_area();

static Bit8u find_vga_entry();

static void memsetb();
static void memsetw();
static void memcpyb();
static void memcpyw();

static void biosfn_set_video_mode();
static void biosfn_set_cursor_shape();
static void biosfn_set_cursor_pos();
static void biosfn_get_cursor_pos();
static void biosfn_set_active_page();
static void biosfn_scroll();
static void biosfn_read_char_attr();
static void biosfn_write_char_attr();
static void biosfn_write_char_only();
static void biosfn_set_border_color();
static void biosfn_set_palette();
static void biosfn_write_pixel();
static void biosfn_read_pixel();
static void biosfn_write_teletype();
static void biosfn_get_video_mode();
static void biosfn_set_single_palette_reg();
static void biosfn_set_overscan_border_color();
static void biosfn_set_all_palette_reg();
static void biosfn_toggle_intensity();
static void biosfn_get_single_palette_reg();
static void biosfn_read_overscan_border_color();
static void biosfn_get_all_palette_reg();
static void biosfn_set_single_dac_reg();
static void biosfn_set_all_dac_reg();
static void biosfn_select_video_dac_color_page();
static void biosfn_read_single_dac_reg();
static void biosfn_read_all_dac_reg();
static void biosfn_set_pel_mask();
static void biosfn_read_pel_mask();
static void biosfn_read_video_dac_state();
static void biosfn_perform_gray_scale_summing();
static void biosfn_load_text_user_pat();
static void biosfn_load_text_8_14_pat();
static void biosfn_load_text_8_8_pat();
static void biosfn_set_text_block_specifier();
static void biosfn_load_text_8_16_pat();
static void biosfn_load_gfx_8_8_chars();
static void biosfn_load_gfx_user_chars();
static void biosfn_load_gfx_8_14_chars();
static void biosfn_load_gfx_8_8_dd_chars();
static void biosfn_load_gfx_8_16_chars();
static void biosfn_get_font_info();
static void biosfn_get_ega_info();
static void biosfn_alternate_prtsc();
static void biosfn_select_vert_res();
static void biosfn_enable_default_palette_loading();
static void biosfn_enable_video_addressing();
static void biosfn_enable_grayscale_summing();
static void biosfn_enable_cursor_emulation();
static void biosfn_switch_video_interface();
static void biosfn_enable_video_refresh_control();
static void biosfn_write_string();
static void biosfn_read_display_code();
static void biosfn_set_display_code();
static void biosfn_read_state_info();
static void biosfn_read_video_state_size();
static void biosfn_save_video_state();
static void biosfn_restore_video_state();

#asm
.text
.rom
.org 0

vgabios_start:
.byte	0x55, 0xaa	/* BIOS signature, required for BIOS extensions */

.byte	0x40		/* BIOS extension length in units of 512 bytes */


vgabios_entry_point:
           
  JMPL(vgabios_init_func)

vgabios_name:
.ascii	"Plex86/Bochs VGABios"
.byte	0x00

// Info from Bart Oldeman
.org 0x1e
.ascii  "IBM"
.byte   0x00

vgabios_version:
.ascii	"v0.3a"
.byte	0x00

vgabios_date:
.ascii  VGABIOS_DATE
.byte	0x00

vgabios_copyright:
.ascii	"(C) 2001 Christophe Bothamy <cbothamy@free.fr>"
.byte	0x00

vgabios_license:
.ascii	"This VGA Bios is released under the GNU LGPL"
.byte	0x00

vgabios_website:
.ascii	"Please visit :"
.byte	0x0a,0x0d
.ascii  " . http://www.plex86.org"
.byte	0x0a,0x0d
.ascii	" . http://bochs.sourceforge.net"
.byte	0x0a,0x0d
.ascii	" . http://cbothamy.free.fr/projects/vgabios"
.byte	0x00
 

;; ============================================================================================
;;
;; Init Entry point
;;
;; ============================================================================================
vgabios_init_func:

;; init vga card
  call _init_vga_card

;; init basic bios vars
  call _init_bios_area

#ifdef VBE  
;; init vbe functions
  call _vbe_init  
#endif

;; set int10 vect
  SET_INT_VECTOR(0x10, #0xC000, #vgabios_int10_handler)

;; display splash screen
  call _display_splash_screen

;; init video mode and clear the screen
  mov ax,#0x0003
  int #0x10

;; show info
  call _display_info

#ifdef VBE  
;; show vbe info
  call _vbe_display_info  
#endif


  retf
#endasm

/*
 *  int10 handled here
 */
#asm
vgabios_int10_handler:
  pushf
  push es
  push ds
  pusha

;; We have to set ds to access the right data segment
  mov   bx, #0xc000
  mov   ds, bx
  call _int10_func

  popa
  pop ds
  pop es
  popf
  iret
#endasm

#include "vgatables.h"
#include "vgafonts.h"

/*
 * Boot time harware inits 
 */
static void init_vga_card()
{
#asm
;; switch to color mode and enable CPU access 480 lines
  mov dx, #0x3C2
  mov al, #0xC3
  outb dx,al

;; more than 64k 3C4/04
  mov dx, #0x3C4
  mov al, #0x04
  outb dx,al

;;
  mov dx, #0x3C5
  mov al, #0x02
  outb dx,al

#endasm
}

// --------------------------------------------------------------------------------------------
/*
 *  Boot time bios area inits 
 */
static void init_bios_area()
{
  // init detected hardware BIOS Area 
  write_word(BIOSMEM_SEG,BIOSMEM_INITIAL_MODE,read_word(BIOSMEM_SEG,BIOSMEM_INITIAL_MODE)&0xFFCF);

  // Just for the first int10 find its children

  // the default chat height
  write_byte(BIOSMEM_SEG,BIOSMEM_CHAR_HEIGHT,16);

  // Clear the screen 
  write_byte(BIOSMEM_SEG,BIOSMEM_VIDEO_CTL,0x60);

  // Set the basic screen we have
  write_byte(BIOSMEM_SEG,BIOSMEM_SWITCHES,0xF9);

  // Set the basic modeset options
  write_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL,0x51);

  // Set the  default MSR
  write_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MSR,0x09);
}

// --------------------------------------------------------------------------------------------
/*
 *  Boot time Splash screen
 */
static void display_splash_screen()
{
}

// --------------------------------------------------------------------------------------------
/*
 *  Tell who we are
 */

#asm
crlf:
 .byte 0x0a,0x0d,0x00
space:
 .ascii " "
 .byte 0x00
#endasm

static void display_info()
{
#asm
 mov ax,#0xc000
 mov ds,ax
 mov si,#vgabios_name
 call _display_string
 mov si,#space
 call _display_string
 mov si,#vgabios_version
 call _display_string
 mov si,#space
 call _display_string
 mov si,#vgabios_date
 call _display_string
 mov si,#crlf
 call _display_string
 mov si,#vgabios_copyright
 call _display_string
 mov si,#crlf
 call _display_string

 mov si,#vgabios_license
 call _display_string
 mov si,#crlf
 call _display_string
 mov si,#crlf
 call _display_string
 mov si,#vgabios_website
 call _display_string
 mov si,#crlf
 call _display_string
 mov si,#crlf
 call _display_string
#endasm
}

static void display_string()
{
 // Get length of string
#asm
 mov ax,ds
 mov es,ax
 mov di,si
 xor cx,cx
 not cx
 xor al,al
 cld
 repne 
  scasb
 not cx
 dec cx
 push cx

 mov ax,#0x0300
 mov bx,#0x0000
 int #0x10
 
 pop cx
 mov ax,#0x1301
 mov bx,#0x000b
 mov bp,si
 int #0x10
#endasm
}

// --------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------
/*
 * int10 main dispatcher
 */
static void int10_func(DI, SI, BP, SP, BX, DX, CX, AX, DS, ES, FLAGS)
  Bit16u DI, SI, BP, SP, BX, DX, CX, AX, ES, DS, FLAGS;
{
#ifdef DEBUG
 // 0E is write char...
 if(GET_AH()!=0x0E)
  printf("vgabios call ah%02x al%02x bx%04x cx%04x dx%04x\n",GET_AH(),GET_AL(),BX,CX,DX);
#endif

 // BIOS functions
 switch(GET_AH())
  {
   case 0x00:
     biosfn_set_video_mode(GET_AL());
     switch(GET_AL()&0x7F)
      {case 6: 
        SET_AL(0x3F);
        break;
       case 0:
       case 1:
       case 2:
       case 3:
       case 4:
       case 5:
       case 7:
        SET_AL(0x30);
        break;
      default:
        SET_AL(0x20);
      }
     break;
   case 0x01:
     biosfn_set_cursor_shape(GET_CH(),GET_CL());
     break;
   case 0x02:
     biosfn_set_cursor_pos(GET_BH(),DX);
     break;
   case 0x03:
     biosfn_get_cursor_pos(GET_BH(),&CX,&DX);
     break;
   case 0x04:
     // Read light pen pos (unimplemented)
#ifdef DEBUG
     unimplemented();
#endif
     AX=0x00;
     BX=0x00;
     CX=0x00;
     DX=0x00;
     break;
   case 0x05:
     biosfn_set_active_page(GET_AL());
     break;
   case 0x06:
     biosfn_scroll(GET_AL(),GET_BH(),GET_CH(),GET_CL(),GET_DH(),GET_DL(),0xFF,SCROLL_UP);
     break;
   case 0x07:
     biosfn_scroll(GET_AL(),GET_BH(),GET_CH(),GET_CL(),GET_DH(),GET_DL(),0xFF,SCROLL_DOWN);
     break;
   case 0x08:
     biosfn_read_char_attr(GET_BH(),&AX);
     break;
   case 0x09:
     biosfn_write_char_attr(GET_AL(),GET_BH(),GET_BL(),CX);
     break;
   case 0x0A:
     biosfn_write_char_only(GET_AL(),GET_BH(),GET_BL(),CX);
     break;
   case 0x0B:
     if(GET_BH()==0x00)
      biosfn_set_border_color(GET_BL());
     else
      biosfn_set_palette(GET_BL());
     break;
   case 0x0C:
     biosfn_write_pixel(GET_BH(),GET_AL(),CX,DX);
     break;
   case 0x0D:
     biosfn_read_pixel(GET_BH(),CX,DX,&AX);
     break;
   case 0x0E:
     // Ralf Brown Interrupt list is WRONG on bh(page)
     // We do output only on the current page !
     biosfn_write_teletype(GET_AL(),0xff,GET_BL(),NO_ATTR);
     break;
   case 0x0F:
     biosfn_get_video_mode(&AX,&BX);
     break;
   case 0x10:
     switch(GET_AL())
      {
       case 0x00:
        biosfn_set_single_palette_reg(GET_BL(),GET_BH());
        break;
       case 0x01:
        biosfn_set_overscan_border_color(GET_BH());
        break;
       case 0x02:
        biosfn_set_all_palette_reg(ES,DX);
        break;
       case 0x03:
        biosfn_toggle_intensity(GET_BL());
        break;
       case 0x07:
        biosfn_get_single_palette_reg(GET_BL(),&BX);
        break;
       case 0x08:
        biosfn_read_overscan_border_color(&BX);
        break;
       case 0x09:
        biosfn_get_all_palette_reg(ES,DX);
        break;
       case 0x10:
        biosfn_set_single_dac_reg(BX,GET_CH(),GET_CL(),GET_DL());
        break;
       case 0x12:
        biosfn_set_all_dac_reg(BX,CX,ES,DX);
        break;
       case 0x13:
        biosfn_select_video_dac_color_page(GET_BL(),GET_BH());
        break;
       case 0x15:
        biosfn_read_single_dac_reg(GET_BL(),&DX,&CX);
        break;
       case 0x17:
        biosfn_read_all_dac_reg(BX,CX,ES,DX);
        break;
       case 0x18:
        biosfn_set_pel_mask(GET_BL());
        break;
       case 0x19:
        biosfn_read_pel_mask(&BX);
        break;
       case 0x1A:
        biosfn_read_video_dac_state(&BX);
        break;
       case 0x1B:
        biosfn_perform_gray_scale_summing(BX,CX);
        break;
#ifdef DEBUG
       default:
        unknown();
#endif
      }
     break;
   case 0x11:
     switch(GET_AL())
      {
       case 0x00:
       case 0x10:
        biosfn_load_text_user_pat(GET_AL(),ES,BP,CX,DX,GET_BL(),GET_BH());
        break;
       case 0x01:
       case 0x11:
        biosfn_load_text_8_14_pat(GET_AL(),GET_BL());
        break;
       case 0x02:
       case 0x12:
        biosfn_load_text_8_8_pat(GET_AL(),GET_BL());
        break;
       case 0x03:
        biosfn_set_text_block_specifier(GET_BL());
        break;
       case 0x04:
       case 0x14:
        biosfn_load_text_8_16_pat(GET_AL(),GET_BL());
        break;
       case 0x20:
        biosfn_load_gfx_8_8_chars(ES,BP);
        break;
       case 0x21:
        biosfn_load_gfx_user_chars(ES,BP,CX,GET_BL(),GET_DL());
        break;
       case 0x22:
        biosfn_load_gfx_8_14_chars(GET_BL());
        break;
       case 0x23:
        biosfn_load_gfx_8_8_dd_chars(GET_BL());
        break;
       case 0x24:
        biosfn_load_gfx_8_16_chars(GET_BL());
        break;
       case 0x30:
        biosfn_get_font_info(GET_BH(),&ES,&BP,&CX,&DX);
        break;
#ifdef DEBUG
       default:
        unknown();
#endif
      }
     
     break;
   case 0x12:
     switch(GET_BL())
      {
       case 0x10:
        biosfn_get_ega_info(&BX,&CX);
        break;
       case 0x20:
        biosfn_alternate_prtsc();
        break;
       case 0x30:
        biosfn_select_vert_res(GET_AL());
        SET_AL(0x12);
        break;
       case 0x31:
        biosfn_enable_default_palette_loading(GET_AL());
        SET_AL(0x12);
        break;
       case 0x32:
        biosfn_enable_video_addressing(GET_AL());
        SET_AL(0x12);
        break;
       case 0x33:
        biosfn_enable_grayscale_summing(GET_AL());
        SET_AL(0x12);
        break;
       case 0x34:
        biosfn_enable_cursor_emulation(GET_AL());
        SET_AL(0x12);
        break;
       case 0x35:
        biosfn_switch_video_interface(GET_AL(),ES,DX);
        SET_AL(0x12);
        break;
       case 0x36:
        biosfn_enable_video_refresh_control(GET_AL());
        SET_AL(0x12);
        break;
#ifdef DEBUG
       default:
        unknown();
#endif
      }
     break;
   case 0x13:
     biosfn_write_string(GET_AL(),GET_BH(),GET_BL(),CX,GET_DH(),GET_DL(),ES,BP);
     break;
   case 0x1A:
     switch(GET_AL())
      {
       case 0x00:
        biosfn_read_display_code(&BX);
        break;
       case 0x01:
        biosfn_set_display_code(GET_BL(),GET_BH());
        break;
#ifdef DEBUG
       default:
        unknown();
#endif
      }
     SET_AL(0x1A);
     break;
   case 0x1B:
     biosfn_read_state_info(BX,ES,DI);
     SET_AL(0x1B);
     break;
   case 0x1C:
     switch(GET_AL())
      {
       case 0x00:
        biosfn_read_video_state_size(CX,&BX);
        break;
       case 0x01:
        biosfn_save_video_state(CX,ES,BX);
        break;
       case 0x02:
        biosfn_restore_video_state(CX,ES,BX);
        break;
#ifdef DEBUG
       default:
        unknown();
#endif
      }
     SET_AL(0x1C);
     break;

#ifdef VBE 
   case 0x4f:
     switch(GET_AL())
     {
       case 0x00:
        vbe_biosfn_return_controller_information(&AX,ES,DI);
        break;
       case 0x01:
        vbe_biosfn_return_mode_information(&AX,CX,ES,DI);
        break;
       case 0x02:
        vbe_biosfn_set_mode(&AX,BX,ES,DI);
        break;
       case 0x03:
        vbe_biosfn_return_current_mode(&AX,&BX);
        break;
       case 0x04:
        //FIXME
#ifdef DEBUG
        unimplemented();
#endif
        break;
       case 0x05:
        vbe_biosfn_display_window_control(&AX,BX,&DX);
        break;
       case 0x06:
        //FIXME
#ifdef DEBUG
        unimplemented();
#endif
        break;
       case 0x07:
        //FIXME
#ifdef DEBUG   
        unimplemented();
#endif
        break;
       case 0x08:
        //FIXME
#ifdef DEBUG
        unimplemented();
#endif
        break;
       case 0x09:
        //FIXME
#ifdef DEBUG
        unimplemented();
#endif
        break;
       case 0x0A:
        //FIXME
#ifdef DEBUG
        unimplemented();
#endif
        break;
#ifdef DEBUG
       default:
        unknown();
#endif   		 
        }
        break;
#endif

#ifdef DEBUG
   default:
     unknown();
#endif
  }
}

// ============================================================================================
// 
// BIOS functions
// 
// ============================================================================================

static void biosfn_set_video_mode(mode) Bit8u mode; 
{// mode: Bit 7 is 1 if no clear screen

 // Should we clear the screen ?
 Bit8u noclearmem=mode&0x80;
 Bit8u line,*palette;
 Bit16u i,twidth,theight,cheight;
 Bit8u modeset_ctl,video_ctl,vga_switches;
 Bit16u crtc_addr;
 
 
 #asm
 // FIXME: how to to do this nicely?
 // bochs vbe code disable video mode
 push dx
 push ax
 mov dx, #VBE_DISPI_IOPORT_INDEX

 // disable video mode
 mov ax, #VBE_DISPI_INDEX_ENABLE
 out dx, ax
 inc dx
 mov ax, #VBE_DISPI_DISABLED
 out dx, ax
 pop ax
 pop dx

 #endasm
 
 
 // The real mode
 mode=mode&0x7f;

 // find the entry in the video modes
 line=find_vga_entry(mode);

#ifdef DEBUG
 printf("mode search %02x found line %02x\n",mode,line);
#endif

 if(line==0xFF)
  return;

 twidth=vga_modes[line].twidth;
 theight=vga_modes[line].theight;
 cheight=vga_modes[line].cheight;
 
 // Read the bios vga control
 video_ctl=read_byte(BIOSMEM_SEG,BIOSMEM_VIDEO_CTL);

 // Read the bios vga switches
 vga_switches=read_byte(BIOSMEM_SEG,BIOSMEM_SWITCHES);

 // Read the bios mode set control
 modeset_ctl=read_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL);

 // Then we know the number of lines
// FIXME

 // if palette loading (bit 3 of modeset ctl = 0)
 if((modeset_ctl&0x08)==0)
  {// Set the PEL mask
   outb(VGAREG_PEL_MASK,vga_modes[line].pelmask);

   // Set the whole dac always, from 0
   outb(VGAREG_DAC_WRITE_ADDRESS,0x00);

   // From which palette
   switch(vga_modes[line].dacmodel)
    {case 0:
      palette=&palette0;
      break;
     case 1:
      palette=&palette1;
      break;
     case 2:
      palette=&palette2;
      break;
     case 3:
      palette=&palette3;
      break;
    }
  }

 // Always 256*3 values
 for(i=0;i<0x0100;i++)
  {if(i<=dac_regs[vga_modes[line].dacmodel])
    {outb(VGAREG_DAC_DATA,palette[(i*3)+0]);
     outb(VGAREG_DAC_DATA,palette[(i*3)+1]);
     outb(VGAREG_DAC_DATA,palette[(i*3)+2]);
    }
   else
    {outb(VGAREG_DAC_DATA,0);
     outb(VGAREG_DAC_DATA,0);
     outb(VGAREG_DAC_DATA,0);
    }
  }

 // Set Attribute Ctl
 for(i=0;i<=ACTL_MAX_REG;i++)
  {outb(VGAREG_ACTL_ADDRESS,i);
   outb(VGAREG_ACTL_WRITE_DATA,actl_regs[vga_modes[line].actlmodel][i]);
  }

 // Set Sequencer Ctl
 for(i=0;i<=SEQU_MAX_REG;i++)
  {outb(VGAREG_SEQU_ADDRESS,i);
   outb(VGAREG_SEQU_DATA,sequ_regs[vga_modes[line].sequmodel][i]);
  }

 // Set Grafx Ctl
 for(i=0;i<=GRDC_MAX_REG;i++)
  {outb(VGAREG_GRDC_ADDRESS,i);
   outb(VGAREG_GRDC_DATA,grdc_regs[vga_modes[line].grdcmodel][i]);
  }

 // Set CRTC address VGA or MDA 
 crtc_addr=vga_modes[line].memmodel==MTEXT?VGAREG_MDA_CRTC_ADDRESS:VGAREG_VGA_CRTC_ADDRESS;

 // Set CRTC regs
 for(i=0;i<=CRTC_MAX_REG;i++)
  {outb(crtc_addr,i);
   outb(crtc_addr+1,crtc_regs[vga_modes[line].crtcmodel][i]);
  }

 // Set the misc register
 outb(VGAREG_WRITE_MISC_OUTPUT,vga_modes[line].miscreg);

 // Enable video
 outb(VGAREG_ACTL_ADDRESS,0x20);
 inb(VGAREG_ACTL_RESET);

 if(noclearmem==0x00)
  {if(vga_modes[line].class==TEXT)
    {
     memsetw(vga_modes[line].sstart,0,0x0720,0x4000); // 32k
    }
   else
    {// FIXME should handle gfx mode
    }
  }

 // Set the BIOS mem
 write_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE,mode|noclearmem);
 write_word(BIOSMEM_SEG,BIOSMEM_NB_COLS,twidth);
 write_word(BIOSMEM_SEG,BIOSMEM_PAGE_SIZE,vga_modes[line].slength);
 write_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS,crtc_addr);
 write_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS,theight-1);
 write_word(BIOSMEM_SEG,BIOSMEM_CHAR_HEIGHT,cheight);
 write_byte(BIOSMEM_SEG,BIOSMEM_VIDEO_CTL,(0x60|noclearmem));
 write_byte(BIOSMEM_SEG,BIOSMEM_SWITCHES,0xF9);
 write_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL,read_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL)&0x7f);

 // FIXME We nearly have the good tables. to be reworked
 write_byte(BIOSMEM_SEG,BIOSMEM_DCC_INDEX,0x08);    // 8 is VGA should be ok for now
 write_word(BIOSMEM_SEG,BIOSMEM_VS_POINTER,0x00);
 write_word(BIOSMEM_SEG,BIOSMEM_VS_POINTER+2,0x00);

 // FIXME
 write_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MSR,0x00); // Unavailable on vanilla vga, but...
 write_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_PAL,0x00); // Unavailable on vanilla vga, but...
 
 // Set cursor shape
 if(vga_modes[line].class==TEXT)
  {biosfn_set_cursor_shape(0x06,0x07);
  }

 // Set cursor pos for page 0..7
 for(i=0;i<8;i++)
  biosfn_set_cursor_pos(i,0x0000);

 // Set active page 0
 biosfn_set_active_page(0x00);

 // Write the fonts in memory
// FIXME

 // Set the ints 0x1F and 0x43
#asm
 SET_INT_VECTOR(0x1f, #0xC000, #vgafont8+128*8)
#endasm

  switch(cheight)
   {case 8:
#asm
     SET_INT_VECTOR(0x43, #0xC000, #vgafont8)
#endasm
     break;
    case 14:
#asm
     SET_INT_VECTOR(0x43, #0xC000, #vgafont14)
#endasm
     break;
    case 16:
#asm
     SET_INT_VECTOR(0x43, #0xC000, #vgafont16)
#endasm
     break;
   }
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_cursor_shape (CH,CL) 
Bit8u CH;Bit8u CL; 
{Bit16u curs;

 CH&=0x3f;
 CL&=0x1f;

 // FIXME should remap to vga settings in case of 14/16 lines
 curs=(CH<<8)+CL;
 write_word(BIOSMEM_SEG,BIOSMEM_CURSOR_TYPE,curs);

 // CTRC regs 0x0a and 0x0b
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS),0x0a);
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS)+1,CH);
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS),0x0b);
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS)+1,CL);
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_cursor_pos (page, cursor) 
Bit8u page;Bit16u cursor;
{
 Bit8u xcurs,ycurs,current;
 Bit16u nbcols,nbrows,address;

 // Should not happen...
 if(page>7)return;

 // Bios cursor pos
 write_word(BIOSMEM_SEG, BIOSMEM_CURSOR_POS+2*page, cursor);

 // Set the hardware cursor
 current=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_PAGE);
 if(page==current)
  {
   // Get the dimensions
   nbcols=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);
   nbrows=read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS)+1;

   xcurs=cursor&0x00ff;ycurs=(cursor&0xff00)>>8;
 
   // Calculate the address knowing nbcols nbrows and page num
   address=SCREEN_IO_START(nbcols,nbrows,page)+xcurs+ycurs*nbcols;
   
   // CRTC regs 0x0e and 0x0f
   outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS),0x0e);
   outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS)+1,(address&0xff00)>>8);
   outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS),0x0f);
   outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS)+1,address&0x00ff);
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_get_cursor_pos (page,shape, pos) 
Bit8u page;Bit16u *shape;Bit16u *pos;
{
 Bit16u ss=get_SS();

 // Default
 write_word(ss, shape, 0);
 write_word(ss, pos, 0);

 if(page>7)return;
 // FIXME should handle VGA 14/16 lines
 write_word(ss,shape,read_word(BIOSMEM_SEG,BIOSMEM_CURSOR_TYPE));
 write_word(ss,pos,read_word(BIOSMEM_SEG,BIOSMEM_CURSOR_POS+page*2));
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_active_page (page) 
Bit8u page;
{
 Bit16u cursor,dummy;
 Bit16u nbcols,nbrows,address;

 if(page>7)return;

 // Get pos curs pos for the right page 
 biosfn_get_cursor_pos(page,&dummy,&cursor);

 // Get the dimensions
 nbcols=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);
 nbrows=read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS)+1;
 
 // Calculate the address knowing nbcols nbrows and page num
 address=SCREEN_MEM_START(nbcols,nbrows,page);
 write_word(BIOSMEM_SEG,BIOSMEM_CURRENT_START,address);

 // Start address
 address=SCREEN_IO_START(nbcols,nbrows,page);

 // CRTC regs 0x0c and 0x0d
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS),0x0c);
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS)+1,(address&0xff00)>>8);
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS),0x0d);
 outb(read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS)+1,address&0x00ff);

 // And change the BIOS page
 write_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_PAGE,page);

#ifdef DEBUG
 printf("Set active page %02x address %04x\n",page,address);
#endif

 // Display the cursor, now the page is active
 biosfn_set_cursor_pos(page,cursor);
}

// --------------------------------------------------------------------------------------------
static void biosfn_scroll (nblines,attr,rul,cul,rlr,clr,page,dir)
Bit8u nblines;Bit8u attr;Bit8u rul;Bit8u cul;Bit8u rlr;Bit8u clr;Bit8u page;Bit8u dir;
{
 // page == 0xFF if current

 Bit8u mode,line;
 Bit16u nbcols,nbrows,i;
 Bit16u address;

 if(rul>rlr)return;
 if(cul>clr)return;

 // Get the mode
 mode=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE);
 line=find_vga_entry(mode);
 if(line==0xFF)return;

 // Get the dimensions
 nbrows=read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS)+1;
 nbcols=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);

 // Get the current page
 if(page==0xFF)
  page=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_PAGE);

 // Compute the address
 address=SCREEN_MEM_START(nbcols,nbrows,page);
#ifdef DEBUG
 printf("Scroll, address %04x (%04x %04x %02x)\n",address,nbrows,nbcols,page);
#endif

 if(rlr>=nbrows)rlr=nbrows-1;
 if(clr>=nbcols)clr=nbcols-1;
 if(nblines>nbrows)nblines=0;

 if(nblines==0&&rul==0&&cul==0&&rlr==nbrows-1&&clr==nbcols-1)
  {
   memsetw(vga_modes[line].sstart,address,(Bit16u)attr*0x100+' ',nbrows*nbcols);
  }
 else
  {// if Scroll up
   if(dir==SCROLL_UP)
    {for(i=rul;i<=rlr;i++)
      {
       if((i+nblines>rlr)||(nblines==0))
        memsetw(vga_modes[line].sstart,address+(i*nbcols+cul)*2,(Bit16u)attr*0x100+' ',clr-cul+1);
       else
        memcpyw(vga_modes[line].sstart,address+(i*nbcols+cul)*2,vga_modes[line].sstart,((i+nblines)*nbcols+cul)*2,clr-cul+1);
      }
    }
   else
    {for(i=rlr;i>=rul;i--)
      {
       if((i<rul+nblines)||(nblines==0))
        memsetw(vga_modes[line].sstart,address+(i*nbcols+cul)*2,(Bit16u)attr*0x100+' ',clr-cul+1);
       else
        memcpyw(vga_modes[line].sstart,address+(i*nbcols+cul)*2,vga_modes[line].sstart,((i-nblines)*nbcols+cul)*2,clr-cul+1);
      }
    }
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_char_attr (page,car) 
Bit8u page;Bit16u *car;
{Bit16u ss=get_SS();
 Bit8u xcurs,ycurs,mode,line;
 Bit16u nbcols,nbrows,address;
 Bit16u cursor,dummy;

 // FIXME gfx mode

 // Get the mode
 mode=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE);
 line=find_vga_entry(mode);
 if(line==0xFF)return;

 // Get the cursor pos for the page
 biosfn_get_cursor_pos(page,&dummy,&cursor);
 xcurs=cursor&0x00ff;ycurs=(cursor&0xff00)>>8;

 // Get the dimensions
 nbrows=read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS)+1;
 nbcols=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);

 // Compute the address
 address=SCREEN_MEM_START(nbcols,nbrows,page)+(xcurs+ycurs*nbcols)*2;

 write_word(ss,car,read_word(vga_modes[line].sstart,address));
}

// --------------------------------------------------------------------------------------------
static void biosfn_write_char_attr (car,page,attr,count) 
Bit8u car;Bit8u page;Bit8u attr;Bit16u count;
{
 Bit8u xcurs,ycurs,mode,line;
 Bit16u nbcols,nbrows,address;
 Bit16u cursor,dummy;

 // FIXME gfx mode

 // Get the mode
 mode=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE);
 line=find_vga_entry(mode);
 if(line==0xFF)return;

 // Get the cursor pos for the page
 biosfn_get_cursor_pos(page,&dummy,&cursor);
 xcurs=cursor&0x00ff;ycurs=(cursor&0xff00)>>8;

 // Get the dimensions
 nbrows=read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS)+1;
 nbcols=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);

 // Compute the address
 address=SCREEN_MEM_START(nbcols,nbrows,page)+(xcurs+ycurs*nbcols)*2;

 dummy=((Bit16u)attr<<8)+car;
 memsetw(vga_modes[line].sstart,address,dummy,count);
}

// --------------------------------------------------------------------------------------------
static void biosfn_write_char_only (car,page,attr,count)
Bit8u car;Bit8u page;Bit8u attr;Bit16u count;
{
 Bit8u xcurs,ycurs,mode,line;
 Bit16u nbcols,nbrows,address;
 Bit16u cursor,dummy;

 // FIXME gfx mode

 // Get the mode
 mode=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE);
 line=find_vga_entry(mode);
 if(line==0xFF)return;

 // Get the cursor pos for the page
 biosfn_get_cursor_pos(page,&dummy,&cursor);
 xcurs=cursor&0x00ff;ycurs=(cursor&0xff00)>>8;

 // Get the dimensions
 nbrows=read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS)+1;
 nbcols=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);

 // Compute the address
 address=SCREEN_MEM_START(nbcols,nbrows,page)+(xcurs+ycurs*nbcols)*2;

 while(count-->0)
  {write_byte(vga_modes[line].sstart,address,car);
   address+=2;
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_border_color (BL) Bit8u BL;
// FIXME anybody using this function ?
{
#ifdef DEBUG
 unimplemented();
#endif
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_palette (BL) Bit8u BL;
// FIXME anybody using this function ?
{
#ifdef DEBUG
 unimplemented();
#endif
}

// --------------------------------------------------------------------------------------------
static void biosfn_write_pixel (BH,AL,CX,DX) Bit8u BH;Bit8u AL;Bit16u CX;Bit16u DX;
// FIXME anybody using this function ?
{
#ifdef DEBUG
 unimplemented();
#endif
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_pixel (BH,CX,DX,AX) Bit8u BH;Bit16u CX;Bit16u DX;Bit16u *AX;
// FIXME anybody using this function ?
{
#ifdef DEBUG
 unimplemented();
#endif
}

// --------------------------------------------------------------------------------------------
static void biosfn_write_teletype (car, page, attr, flag) 
Bit8u car;Bit8u page;Bit8u attr;Bit8u flag;
{// flag = WITH_ATTR / NO_ATTR

 Bit8u xcurs,ycurs,mode,line;
 Bit16u nbcols,nbrows,address;
 Bit16u cursor,dummy;

 // special case if page is 0xff, use current page
 if(page==0xff)
  page=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_PAGE);

 // FIXME gfx mode

 // Get the mode
 mode=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE);
 line=find_vga_entry(mode);
 if(line==0xFF)return;

 // Get the cursor pos for the page
 biosfn_get_cursor_pos(page,&dummy,&cursor);
 xcurs=cursor&0x00ff;ycurs=(cursor&0xff00)>>8;

 // Get the dimensions
 nbrows=read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS)+1;
 nbcols=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);

 switch(car)
  {
   case 7:
    //FIXME should beep
    break;

   case 8:
    if(xcurs>0)xcurs--;
    break;

   case '\r':
    xcurs=0;
    break;

   case '\n':
    xcurs=0;
    ycurs++;
    break;

   case '\t':
    do
     {
      biosfn_write_teletype(' ',page,attr,flag);
      biosfn_get_cursor_pos(page,&dummy,&cursor);
      xcurs=cursor&0x00ff;ycurs=(cursor&0xff00)>>8;
     }while(xcurs%8==0);
    break;

   default:
    // Compute the address  
    address=SCREEN_MEM_START(nbcols,nbrows,page)+(xcurs+ycurs*nbcols)*2;

    // Write the char 
    write_byte(vga_modes[line].sstart,address,car);

    if(flag==WITH_ATTR)
     write_byte(vga_modes[line].sstart,address+1,attr);

    xcurs++;
  }

 // Do we need to wrap ?
 if(xcurs==nbcols)
  {xcurs=0;
   ycurs++;
  }

 // Do we need to scroll ?
 if(ycurs==nbrows)
  {biosfn_scroll(0x01,0x07,0,0,nbrows-1,nbcols-1,page,SCROLL_UP);
   ycurs-=1;
  }
 
 // Set the cursor for the page
 cursor=ycurs; cursor<<=8; cursor+=xcurs;
 biosfn_set_cursor_pos(page,cursor);
}

// --------------------------------------------------------------------------------------------
static void biosfn_get_video_mode (AX,BX) 
Bit16u *AX;Bit16u *BX;
{Bit16u ss=get_SS();
 Bit8u  mode,page;
 Bit16u nbcars;

 page=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_PAGE);
 mode=read_byte(BIOSMEM_SEG,BIOSMEM_CURRENT_MODE);
 nbcars=read_word(BIOSMEM_SEG,BIOSMEM_NB_COLS);

 write_word(ss,AX,(nbcars<<8)+mode);
 write_word(ss,BX,((Bit16u)page)<<8);
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_single_palette_reg (reg,value) 
Bit8u reg;Bit8u value;
{
 if(reg<=ACTL_MAX_REG)
  {
   inb(VGAREG_ACTL_RESET);
   outb(VGAREG_ACTL_ADDRESS,reg);
   outb(VGAREG_ACTL_WRITE_DATA,value);
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_overscan_border_color (value) 
Bit8u value;
{
 inb(VGAREG_ACTL_RESET);
 outb(VGAREG_ACTL_ADDRESS,0x11);
 outb(VGAREG_ACTL_WRITE_DATA,value);
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_all_palette_reg (seg,offset) 
Bit16u seg;Bit16u offset;
{
 Bit8u i;

 inb(VGAREG_ACTL_RESET);
 // First the colors
 for(i=0;i<=0x10;i++)
  {
   outb(VGAREG_ACTL_ADDRESS,i);
   outb(VGAREG_ACTL_WRITE_DATA,read_byte(seg,offset));
   offset++;
  }

 // Then the border
 outb(VGAREG_ACTL_ADDRESS,0x11);
 outb(VGAREG_ACTL_WRITE_DATA,read_byte(seg,offset));
}

// --------------------------------------------------------------------------------------------
static void biosfn_toggle_intensity (state) 
Bit8u state;
{Bit8u value;
 state&=0x01;
 inb(VGAREG_ACTL_RESET);

 outb(VGAREG_ACTL_ADDRESS,0x10);
 value=inb(VGAREG_ACTL_READ_DATA);
 value&=0xf7;
 value|=state<<3;

 inb(VGAREG_ACTL_RESET);
 outb(VGAREG_ACTL_ADDRESS,0x10);
 outb(VGAREG_ACTL_WRITE_DATA,value);
}

// --------------------------------------------------------------------------------------------
static void biosfn_get_single_palette_reg (reg,value) 
Bit8u reg;Bit16u *value;
{Bit16u ss=get_SS();
 
 if(reg<=ACTL_MAX_REG)
  {
   inb(VGAREG_ACTL_RESET);
   outb(VGAREG_ACTL_ADDRESS,reg);
   write_word(ss,value,((Bit16u)inb(VGAREG_ACTL_READ_DATA))<<8);
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_overscan_border_color (value) 
Bit16u *value;
{Bit16u ss=get_SS();
 
 inb(VGAREG_ACTL_RESET);
 outb(VGAREG_ACTL_ADDRESS,0x11);
 write_word(ss,value,((Bit16u)inb(VGAREG_ACTL_READ_DATA))<<8);
}

// --------------------------------------------------------------------------------------------
static void biosfn_get_all_palette_reg (seg,offset) Bit16u seg;Bit16u offset;
{
 Bit8u i;

 inb(VGAREG_ACTL_RESET);
 // First the colors
 for(i=0;i<=0x10;i++)
  {
   outb(VGAREG_ACTL_ADDRESS,i);
   write_byte(seg,offset,inb(VGAREG_ACTL_READ_DATA));
   offset++;
  }

 // Then the border
 outb(VGAREG_ACTL_ADDRESS,0x11);
 write_byte(seg,offset,inb(VGAREG_ACTL_READ_DATA));
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_single_dac_reg (reg,g,b,r) 
Bit16u reg;Bit8u g;Bit8u b;Bit8u r;
{
 outb(VGAREG_DAC_WRITE_ADDRESS,reg);
 outb(VGAREG_DAC_DATA,r);
 outb(VGAREG_DAC_DATA,g);
 outb(VGAREG_DAC_DATA,b);
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_all_dac_reg (start,count,seg,offset) 
Bit16u start;Bit16u count;Bit16u seg;Bit16u offset;
{Bit8u i;
 outb(VGAREG_DAC_WRITE_ADDRESS,start);
 for(i=0;i<count;i++)
  {outb(VGAREG_DAC_DATA,read_byte(seg,offset++));
   outb(VGAREG_DAC_DATA,read_byte(seg,offset++));
   outb(VGAREG_DAC_DATA,read_byte(seg,offset++));
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_select_video_dac_color_page (function,page) 
Bit8u function;
{Bit8u value;

 inb(VGAREG_ACTL_RESET);
 outb(VGAREG_ACTL_ADDRESS,0x10);

 value=inb(VGAREG_ACTL_READ_DATA);
 function&=0x01;
 if(function==0)
  {// 4 of 64
   value&=0x7f;
   value|=function<<7;

   inb(VGAREG_ACTL_RESET);
   outb(VGAREG_ACTL_ADDRESS,0x10);
   outb(VGAREG_ACTL_WRITE_DATA,value);
  }
 else
  {// 16 of 16
   inb(VGAREG_ACTL_RESET);
   outb(VGAREG_ACTL_ADDRESS,0x14);
   if(value&0x80)
     outb(VGAREG_ACTL_WRITE_DATA,page&0x0f);
   else
     outb(VGAREG_ACTL_WRITE_DATA,(page&0x03)<<2);
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_single_dac_reg (reg,tor,togb) 
Bit8u reg;Bit16u *tor;Bit16u *togb;
{Bit16u ss=get_SS();
 Bit8u r,g,b;

 outb(VGAREG_DAC_READ_ADDRESS,reg);
 r=inb(VGAREG_DAC_DATA);
 g=inb(VGAREG_DAC_DATA);
 b=inb(VGAREG_DAC_DATA);
 write_word(ss,tor,((Bit16u)r)<<8);
 write_word(ss,togb,(((Bit16u)g)<<8)+b);
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_all_dac_reg (start,count,seg,offset) 
Bit16u start;Bit16u count;Bit16u seg;Bit16u offset;
{Bit8u i;
 outb(VGAREG_DAC_READ_ADDRESS,start);
 for(i=0;i<count;i++)
  {write_byte(seg,offset++,inb(VGAREG_DAC_DATA));
   write_byte(seg,offset++,inb(VGAREG_DAC_DATA));
   write_byte(seg,offset++,inb(VGAREG_DAC_DATA));
  }
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_pel_mask (mask) 
Bit8u mask;
{
 outb(VGAREG_PEL_MASK,mask);
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_pel_mask (mask) 
Bit16u *mask;
{Bit16u ss=get_SS();
 
 write_word(ss,mask,inb(VGAREG_PEL_MASK));
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_video_dac_state (state) Bit16u *state;
{Bit16u ss=get_SS();
 Bit8u mcr,csr;

 inb(VGAREG_ACTL_RESET);
 outb(VGAREG_ACTL_ADDRESS,0x10);
 mcr=(inb(VGAREG_ACTL_READ_DATA)>>7)&0x01;
 inb(VGAREG_ACTL_RESET);
 outb(VGAREG_ACTL_ADDRESS,0x14);
 csr=inb(VGAREG_ACTL_READ_DATA)&0x0f;
 if(mcr==0)(csr>>2)&0x03;

 write_word(ss,state,(mcr<<8)+csr);
}

// --------------------------------------------------------------------------------------------
static void biosfn_perform_gray_scale_summing (start,count) 
Bit16u start;Bit16u count;
{Bit8u index,r,g,b,d;
 Bit16u i,m;

 inb(VGAREG_ACTL_RESET);
 outb(VGAREG_ACTL_ADDRESS,0x10);
 d=(inb(VGAREG_ACTL_READ_DATA)>>6)&0x01;

 // depth is 8 or 6 bits
 if(d==0)m=0x3f;
 else m=0xff;
 

 // We start overwriting at
 outb(VGAREG_DAC_READ_ADDRESS,start);
 outb(VGAREG_DAC_WRITE_ADDRESS,start);

 for( index = 0; index < count; index++ ) 
  {
   // get 6-bit wide RGB data values
   r=inb( VGAREG_DAC_DATA );
   g=inb( VGAREG_DAC_DATA );
   b=inb( VGAREG_DAC_DATA );

   // intensity = ( 0.3 * Red ) + ( 0.59 * Green ) + ( 0.11 * Blue )
   i = ( ( 77*r + 151*g + 28*b ) + 0x80 ) >> 8;

   if(i>m)i=m;
 
   // write new intensity value
   outb( VGAREG_DAC_DATA, i&0xff );
   outb( VGAREG_DAC_DATA, i&0xff );
   outb( VGAREG_DAC_DATA, i&0xff );
  }  
}

// --------------------------------------------------------------------------------------------
static void biosfn_load_text_user_pat (AL,ES,BP,CX,DX,BL,BH) Bit8u AL;Bit16u ES;Bit16u BP;Bit16u CX;Bit16u DX;Bit8u BL;Bit8u BH;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_text_8_14_pat (AL,BL) Bit8u AL;Bit8u BL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_text_8_8_pat (AL,BL) Bit8u AL;Bit8u BL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_set_text_block_specifier (BL) Bit8u BL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_text_8_16_pat (AL,BL) Bit8u AL;Bit8u BL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_gfx_8_8_chars (ES,BP) Bit16u ES;Bit16u BP;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_gfx_user_chars (ES,BP,CX,BL,DL) Bit16u ES;Bit16u BP;Bit16u CX;Bit8u BL;Bit8u DL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_gfx_8_14_chars (BL) Bit8u BL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_gfx_8_8_dd_chars (BL) Bit8u BL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_load_gfx_8_16_chars (BL) Bit8u BL;
{
#ifdef DEBUG
 unimplemented();
#endif
}
// --------------------------------------------------------------------------------------------
static void biosfn_get_font_info (BH,ES,BP,CX,DX) 
Bit8u BH;Bit16u *ES;Bit16u *BP;Bit16u *CX;Bit16u *DX;
{Bit16u ss=get_SS();
 
 switch(BH)
  {case 0x00:
    write_word(ss,ES,read_word(0x00,0x1f*4));
    write_word(ss,BP,read_word(0x00,(0x1f*4)+2));
    break;
   case 0x01:
    write_word(ss,ES,read_word(0x00,0x43*4));
    write_word(ss,BP,read_word(0x00,(0x43*4)+2));
    break;
   case 0x02:
    write_word(ss,ES,0xC000);
    write_word(ss,BP,vgafont14);
    break;
   case 0x03:
    write_word(ss,ES,0xC000);
    write_word(ss,BP,vgafont8);
    break;
   case 0x04:
    write_word(ss,ES,0xC000);
    write_word(ss,BP,vgafont8+128*8);
    break;
   case 0x05:
    write_word(ss,ES,0xC000);
    write_word(ss,BP,vgafont14alt);
    break;
   case 0x06:
    write_word(ss,ES,0xC000);
    write_word(ss,BP,vgafont16);
    break;
   case 0x07:
    write_word(ss,ES,0xC000);
    write_word(ss,BP,vgafont16alt);
    break;
   default:
    #ifdef DEBUG
     printf("Get font info BH(%02x) was discarded\n",BH);
    #endif
    return;
  }
 // Set byte/char of on screen font
 write_word(ss,DX,(Bit16u)read_byte(BIOSMEM_SEG,BIOSMEM_CHAR_HEIGHT));

 // Set Highest char row
 write_word(ss,DX,(Bit16u)read_byte(BIOSMEM_SEG,BIOSMEM_NB_ROWS));
}

// --------------------------------------------------------------------------------------------
static void biosfn_get_ega_info (BX,CX) 
Bit16u *BX;Bit16u *CX;
{Bit16u ss=get_SS();
 Bit16u crtc;
 Bit8u switches;

 crtc=read_word(BIOSMEM_SEG,BIOSMEM_CRTC_ADDRESS);
 if(crtc==VGAREG_MDA_CRTC_ADDRESS)
  write_word(ss,BX,(1<<8)+0x0003);
 else
  write_word(ss,BX,0x0003);

 switches=read_byte(BIOSMEM_SEG,BIOSMEM_SWITCHES);
 write_word(ss,CX,(switches&0x0f));
}

// --------------------------------------------------------------------------------------------
static void biosfn_alternate_prtsc()
{
#ifdef DEBUG
 unimplemented();
#endif
}

// --------------------------------------------------------------------------------------------
static void biosfn_select_vert_res (res) 
Bit8u res;
{// res : 00 200 lines, 01 350 lines, 02 400 lines
 Bit8u modeset,switches;

 modeset=read_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL);
 switches=read_byte(BIOSMEM_SEG,BIOSMEM_SWITCHES);
 switch(res)
  {case 0x00:
    // set modeset ctl bit 7 and reset bit 4
    // set switches bit 3-0 to 0x08
    modeset|=0x80;modeset&=0xef;
    switches&=0xf0;switches|=0x08;
    break;
   case 0x01:
    // reset modeset ctl bit 7 and bit 4
    // set switches bit 3-0 to 0x09
    modeset&=0x6f;
    switches&=0xf0;switches|=0x09;
    break;
   case 0x02:
    // reset modeset ctl bit 7 and set bit 4
    // set switches bit 3-0 to 0x09
    modeset|=0x10;modeset&=0x7f;
    switches&=0xf0;switches|=0x09;
    break;
   default:
    #ifdef DEBUG
     printf("Select vert res (%02x) was discarded\n",res);
    #endif
    return;
  }
 write_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL,modeset);
 write_byte(BIOSMEM_SEG,BIOSMEM_SWITCHES,switches);
}

// --------------------------------------------------------------------------------------------
static void biosfn_enable_default_palette_loading (disable) 
Bit8u disable;
{
 Bit8u modeset;

 modeset=read_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL);

 // Bit 3
 if(disable!=0x00)modeset|=0x08;
 else modeset&=0xf7;

 write_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL,modeset);
}

// --------------------------------------------------------------------------------------------
static void biosfn_enable_video_addressing (disable) 
Bit8u disable;
{
 Bit8u misc;

 misc=inb(VGAREG_READ_MISC_OUTPUT);
 // bit 1, 0 disable
 if(disable!=0x00) misc&=0xfd;
 else misc|=0x02;
 outb(VGAREG_WRITE_MISC_OUTPUT,misc);
}

// --------------------------------------------------------------------------------------------
static void biosfn_enable_grayscale_summing (disable)
Bit8u disable;
{
 Bit8u modeset;

 modeset=read_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL);

 // Bit 1 set if disable=0
 if(disable==0x00)modeset|=0x02;
 else modeset&=0xfd;

 write_byte(BIOSMEM_SEG,BIOSMEM_MODESET_CTL,modeset);
}

// --------------------------------------------------------------------------------------------
static void biosfn_enable_cursor_emulation (disable)
Bit8u disable;
{
 Bit8u videoctl;

 videoctl=read_byte(BIOSMEM_SEG,BIOSMEM_VIDEO_CTL);

 // Bit 0 set if disable!=0
 if(disable!=0x00)videoctl|=0x01;
 else videoctl&=0xfe;

 write_byte(BIOSMEM_SEG,BIOSMEM_VIDEO_CTL,videoctl);
}

// --------------------------------------------------------------------------------------------
static void biosfn_switch_video_interface (AL,ES,DX) Bit8u AL;Bit16u ES;Bit16u DX;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_enable_video_refresh_control (AL) Bit8u AL;
{
#ifdef DEBUG
 unimplemented();
#endif
}

// --------------------------------------------------------------------------------------------
static void biosfn_write_string (flag,page,attr,count,row,col,seg,offset) 
Bit8u flag;Bit8u page;Bit8u attr;Bit16u count;Bit8u row;Bit8u col;Bit16u seg;Bit16u offset;
{
 Bit16u newcurs,oldcurs,dummy;
 Bit8u car,carattr;

 // Read curs info for the page
 biosfn_get_cursor_pos(page,&dummy,&oldcurs);

 // if row=0xff special case : use current cursor position
 if(row==0xff)
  {col=oldcurs&0x00ff;
   row=(oldcurs&0xff00)>>8;
  }

 newcurs=row; newcurs<<=8; newcurs+=col;
 biosfn_set_cursor_pos(page,newcurs);
 
 while(count--!=0)
  {
   car=read_byte(seg,offset++);
   if((flag&0x02)!=0)
    attr=read_byte(seg,offset++);

   biosfn_write_teletype(car,page,attr,WITH_ATTR);
  }
 
 // Set back curs pos 
 if((flag&0x01)==0)
  biosfn_set_cursor_pos(page,oldcurs);
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_display_code (BX) 
Bit16u *BX;
{
 Bit16u ss=get_SS();
 write_word(ss,BX,(Bit16u)read_byte(BIOSMEM_SEG,BIOSMEM_DCC_INDEX));
}

// --------------------------------------------------------------------------------------------
static void biosfn_set_display_code (BL,BH) 
Bit8u BL;Bit8u BH;
{
 write_byte(BIOSMEM_SEG,BIOSMEM_DCC_INDEX,BL);

#ifdef DEBUG
 printf("Alternate Display code (%02x) was discarded\n",BH);
#endif
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_state_info (BX,ES,DI) 
Bit16u BX;Bit16u ES;Bit16u DI;
{
 // Address of static functionality table
 write_word(ES,DI+0x00,&static_functionality);
 write_word(ES,DI+0x02,0xC000);

 // Hard coded copy from BIOS area. Should it be cleaner ?
 memcpyb(ES,DI+0x04,BIOSMEM_SEG,0x49,30);
 memcpyb(ES,DI+0x22,BIOSMEM_SEG,0x84,3);
 
 write_byte(ES,DI+0x25,read_byte(BIOSMEM_SEG,BIOSMEM_DCC_INDEX));
 write_byte(ES,DI+0x26,0);
 write_byte(ES,DI+0x27,16);
 write_byte(ES,DI+0x28,0);
 write_byte(ES,DI+0x29,8);
 write_byte(ES,DI+0x2a,2);
 write_byte(ES,DI+0x2b,0);
 write_byte(ES,DI+0x2c,0);
 write_byte(ES,DI+0x31,3);
 write_byte(ES,DI+0x32,0);
 
 memsetb(ES,DI+0x33,0,13);
}

// --------------------------------------------------------------------------------------------
static void biosfn_read_video_state_size (CX,ES,BX) Bit16u CX;Bit16u ES;Bit16u BX;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_save_video_state (CX,ES,BX) Bit16u CX;Bit16u ES;Bit16u BX;
{
#ifdef DEBUG
 unimplemented();
#endif
}
static void biosfn_restore_video_state (CX,ES,BX) Bit16u CX;Bit16u ES;Bit16u BX;
{
#ifdef DEBUG
 unimplemented();
#endif
}

// ============================================================================================
//
// Video Utils
//
// ============================================================================================
 
// --------------------------------------------------------------------------------------------
static Bit8u find_vga_entry(mode) 
Bit8u mode;
{
 Bit8u i,line=0xFF;
 for(i=0;i<=MODE_MAX;i++)
  if(vga_modes[i].svgamode==mode)
   {line=i;
    break;
   }
 return line;
}

/* =========================================================== */
/*
 * Misc Utils
*/
/* =========================================================== */

// --------------------------------------------------------------------------------------------
static void memsetb(seg,offset,value,count)
  Bit16u seg;
  Bit16u offset;
  Bit16u value;
  Bit16u count;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push cx
    push es
    push di

    mov  cx, 10[bp] ; count
    cmp  cx, #0x00
    je   memsetb_end
    mov  ax, 4[bp] ; segment
    mov  es, ax
    mov  ax, 6[bp] ; offset
    mov  di, ax
    mov  al, 8[bp] ; value
    cld
    rep
     stosb

memsetb_end:
    pop di
    pop es
    pop cx
    pop ax

  pop bp
#endasm
}

// --------------------------------------------------------------------------------------------
static void memsetw(seg,offset,value,count)
  Bit16u seg;
  Bit16u offset;
  Bit16u value;
  Bit16u count;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push cx
    push es
    push di

    mov  cx, 10[bp] ; count
    cmp  cx, #0x00
    je   memsetw_end
    mov  ax, 4[bp] ; segment
    mov  es, ax
    mov  ax, 6[bp] ; offset
    mov  di, ax
    mov  ax, 8[bp] ; value
    cld
    rep
     stosw

memsetw_end:
    pop di
    pop es
    pop cx
    pop ax

  pop bp
#endasm
}

// --------------------------------------------------------------------------------------------
static void memcpyb(dseg,doffset,sseg,soffset,count)
  Bit16u dseg;
  Bit16u doffset;
  Bit16u sseg;
  Bit16u soffset;
  Bit16u count;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push cx
    push es
    push di
    push ds
    push si

    mov  cx, 12[bp] ; count
    cmp  cx, #0x0000
    je   memcpyb_end
    mov  ax, 4[bp] ; dsegment
    mov  es, ax
    mov  ax, 6[bp] ; doffset
    mov  di, ax
    mov  ax, 8[bp] ; ssegment
    mov  ds, ax
    mov  ax, 10[bp] ; soffset
    mov  si, ax
    cld
    rep
     movsb

memcpyb_end:
    pop si
    pop ds
    pop di
    pop es
    pop cx
    pop ax

  pop bp
#endasm
}

// --------------------------------------------------------------------------------------------
static void memcpyw(dseg,doffset,sseg,soffset,count)
  Bit16u dseg;
  Bit16u doffset;
  Bit16u sseg;
  Bit16u soffset;
  Bit16u count;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push cx
    push es
    push di
    push ds
    push si

    mov  cx, 12[bp] ; count
    cmp  cx, #0x0000
    je   memcpyw_end
    mov  ax, 4[bp] ; dsegment
    mov  es, ax
    mov  ax, 6[bp] ; doffset
    mov  di, ax
    mov  ax, 8[bp] ; ssegment
    mov  ds, ax
    mov  ax, 10[bp] ; soffset
    mov  si, ax
    cld
    rep
     movsw

memcpyw_end:
    pop si
    pop ds
    pop di
    pop es
    pop cx
    pop ax

  pop bp
#endasm
}

/* =========================================================== */
/*
 * These functions where ripped from Kevin's rombios.c
*/
/* =========================================================== */

// --------------------------------------------------------------------------------------------
static Bit8u
read_byte(seg, offset)
  Bit16u seg;
  Bit16u offset;
{
#asm
  push bp
  mov  bp, sp

    push bx
    push ds
    mov  ax, 4[bp] ; segment
    mov  ds, ax
    mov  bx, 6[bp] ; offset
    mov  al, [bx]
    ;; al = return value (byte)
    pop  ds
    pop  bx

  pop  bp
#endasm
}

// --------------------------------------------------------------------------------------------
static Bit16u
read_word(seg, offset)
  Bit16u seg;
  Bit16u offset;
{
#asm
  push bp
  mov  bp, sp

    push bx
    push ds
    mov  ax, 4[bp] ; segment
    mov  ds, ax
    mov  bx, 6[bp] ; offset
    mov  ax, [bx]
    ;; ax = return value (word)
    pop  ds
    pop  bx

  pop  bp
#endasm
}

// --------------------------------------------------------------------------------------------
static void
write_byte(seg, offset, data)
  Bit16u seg;
  Bit16u offset;
  Bit8u  data;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push bx
    push ds
    mov  ax, 4[bp] ; segment
    mov  ds, ax
    mov  bx, 6[bp] ; offset
    mov  al, 8[bp] ; data byte
    mov  [bx], al  ; write data byte
    pop  ds
    pop  bx
    pop  ax

  pop  bp
#endasm
}

// --------------------------------------------------------------------------------------------
static void
write_word(seg, offset, data)
  Bit16u seg;
  Bit16u offset;
  Bit16u data;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push bx
    push ds
    mov  ax, 4[bp] ; segment
    mov  ds, ax
    mov  bx, 6[bp] ; offset
    mov  ax, 8[bp] ; data word
    mov  [bx], ax  ; write data word
    pop  ds
    pop  bx
    pop  ax

  pop  bp
#endasm
}

// --------------------------------------------------------------------------------------------
 Bit8u
inb(port)
  Bit16u port;
{
#asm
  push bp
  mov  bp, sp

    push dx
    mov  dx, 4[bp]
    in   al, dx
    pop  dx

  pop  bp
#endasm
}

  Bit16u
inw(port)
  Bit16u port;
{
#asm
  push bp
  mov  bp, sp

    push dx
    mov  dx, 4[bp]
    in   ax, dx
    pop  dx

  pop  bp
#endasm
}

// --------------------------------------------------------------------------------------------
  void
outb(port, val)
  Bit16u port;
  Bit8u  val;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push dx
    mov  dx, 4[bp]
    mov  al, 6[bp]
    out  dx, al
    pop  dx
    pop  ax

  pop  bp
#endasm
}

// --------------------------------------------------------------------------------------------
  void
outw(port, val)
  Bit16u port;
  Bit16u  val;
{
#asm
  push bp
  mov  bp, sp

    push ax
    push dx
    mov  dx, 4[bp]
    mov  ax, 6[bp]
    out  dx, ax
    pop  dx
    pop  ax

  pop  bp
#endasm
}

Bit16u get_SS()
{
#asm
  mov  ax, ss
#endasm
}

#ifdef DEBUG
void unimplemented()
{
 printf("--> Unimplemented\n");
}

void unknown()
{
 printf("--> Unknown int10\n");
}
#endif

#ifdef DEBUG
// --------------------------------------------------------------------------------------------
void printf(s)
  Bit8u *s;
{
  Bit8u c, format_char;
  Boolean  in_format;
  unsigned format_width, i;
  Bit16u  *arg_ptr;
  Bit16u   arg_seg, arg, digit, nibble, shift_count;

  arg_ptr = &s;
  arg_seg = get_SS();

  in_format = 0;
  format_width = 0;

  while (c = read_byte(0xc000, s)) {
    if ( c == '%' ) {
      in_format = 1;
      format_width = 0;
      }
    else if (in_format) {
      if ( (c>='0') && (c<='9') ) {
        format_width = (format_width * 10) + (c - '0');
        }
      else if (c == 'x') {
        arg_ptr++; // increment to next arg
        arg = read_word(arg_seg, arg_ptr);
        if (format_width == 0)
          format_width = 4;
        i = 0;
        digit = format_width - 1;
        for (i=0; i<format_width; i++) {
          nibble = (arg >> (4 * digit)) & 0x000f;
          if (nibble <= 9)
            outb(0xfff0, nibble + '0');
          else
            outb(0xfff0, (nibble - 10) + 'A');
          digit--;
          }
        in_format = 0;
        }
      //else if (c == 'd') {
      //  in_format = 0;
      //  }
      }
    else {
      outb(0xfff0, c);
      }
    s ++;
    }
}
#endif

#ifdef VBE
#include "vbe.c"
#endif

// --------------------------------------------------------------------------------------------

#asm 
;; DATA_SEG_DEFS_HERE
#endasm

#asm
.ascii "vgabios ends here"
.byte  0x00
vgabios_end:
.byte 0xCB
;; BLOCK_STRINGS_BEGIN
#endasm

