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

#include "vbe.h"
#include "vbetables.h"


#define VBEInfoData ((VbeInfoBlock *) 0)

extern char vbebios_copyright;
extern char vbebios_vendor_name;
extern char vbebios_product_name;
extern char vbebios_product_revision;

//#define DYN_LIST

#ifndef DYN_LIST
extern Bit16u vbebios_mode_list;
#endif

#asm
_vbebios_copyright:
.ascii	"Bochs/Plex86 VBE(C) 2002 Jeroen Janssen <japj@darius.demon.nl>"
.byte	0x00

_vbebios_vendor_name:
.ascii "Bochs/Plex86 Developers"
.byte	0x00

_vbebios_product_name:
.ascii "Bochs/Plex86 VBE Adapter"
.byte	0x00

_vbebios_product_revision:
.ascii "$Id: vbe.c,v 1.1 2002/02/18 16:55:49 japj Exp $"
.byte	0x00

#ifndef DYN_LIST
_vbebios_mode_list:
.word VBE_VESA_MODE_640X400X8
.word VBE_VESA_MODE_640X480X8
.word VBE_VESA_MODE_640X480X565
.word VBE_VESA_MODE_800X600X565
.word VBE_VESA_MODE_640X480X888
.word VBE_VESA_MODE_800X600X888
.word VBE_OWN_MODE_800X600X8888
.word VBE_OWN_MODE_1024X768X8888
.word VBE_VESA_MODE_END_OF_LIST
#endif

#endasm

/** Function 00h - Return VBE Controller Information
 * 
 * Input:
 * 		AX	= 4F00h
 * 		ES:DI	= Pointer to buffer in which to place VbeInfoBlock structure
 * 			  (VbeSignature should be VBE2 when VBE 2.0 information is desired and
 * 			   the info block is 512 bytes in size)
 * Output:
 * 		AX	= VBE Return Status
 * 
 */
void vbe_biosfn_return_controller_information(AX, ES, DI)
Bit16u *AX;Bit16u ES;Bit16u DI;
{
	Bit16u ss=get_SS();
	VbeInfoBlock	vbe_info_block;
	Bit16u status;
	Bit16u result;
	//Bit16u *video_mode_list;
	Bit16u cur_mode=0;
	ModeInfoListItem *cur_info=&mode_info_list;	
	
	status=read_word(ss,AX);
	
#ifdef DEBUG		
	printf("VBE vbe_biosfn_return_vbe_info ES%x DI%x AX%x\n",ES,DI,status);
#endif
	// get vbe_info_block into local variable
	memcpyb(ss,&vbe_info_block,ES,DI,sizeof(vbe_info_block));

	// check for VBE2 signature
	if ( (vbe_info_block.VbeSignature[0] == 'V') &&
	     (vbe_info_block.VbeSignature[1] == 'B') &&
	     (vbe_info_block.VbeSignature[2] == 'E') &&
	     (vbe_info_block.VbeSignature[3] == '2') )
	{
#ifdef DEBUG		
		printf("VBE correct VBE2 signature found\n");
#endif
		// VBE Signature
		vbe_info_block.VbeSignature[0]='V';
		vbe_info_block.VbeSignature[1]='E';
		vbe_info_block.VbeSignature[2]='S';
		vbe_info_block.VbeSignature[3]='A';
		
		// VBE Version supported
		vbe_info_block.VbeVersion=0x0200;
		
		// OEM String
		vbe_info_block.OemStringPtr_Seg=0xc000;
		vbe_info_block.OemStringPtr_Off=&vbebios_copyright;
		
		// Capabilities
		vbe_info_block.Capabilities[0]=0;
		vbe_info_block.Capabilities[1]=0;
		vbe_info_block.Capabilities[2]=0;
		vbe_info_block.Capabilities[3]=0;

#ifdef DYN_LIST
		// VBE Video Mode Pointer (dynamicly generated from the mode_info_list)
		vbe_info_block.VideoModePtr_Seg=ES;//0xc000;
		vbe_info_block.VideoModePtr_Off=DI+ 34;//&(VBEInfoData->Reserved);//&vbebios_mode_list;
#else
		// VBE Video Mode Pointer (staticly in rom)
		vbe_info_block.VideoModePtr_Seg=0xc000;
		vbe_info_block.VideoModePtr_Off=&vbebios_mode_list;

#endif
	
#ifdef DYN_LIST
		
//		video_mode_list=(Bit16u*)&(vbe_info_block.Reserved);

		do
		{
	#ifdef DEBUG		
			printf("VBE found mode %x => %x\n",cur_info->mode,cur_mode);
	#endif
//			*video_mode_list=cur_info->mode;
			vbe_info_block.Reserved[cur_mode]=cur_info->mode;
			
			cur_info++;
			//video_mode_list++;
			cur_mode++;
		} while (cur_info->mode!=VBE_VESA_MODE_END_OF_LIST);
		
		// Add vesa mode list terminator
		vbe_info_block.Reserved[cur_mode]=VBE_VESA_MODE_END_OF_LIST;
#endif				

		// VBE Total Memory (in 64b blocks)
		vbe_info_block.TotalMemory=VBE_TOTAL_VIDEO_MEMORY_DIV_64K;

		// OEM Stuff
		vbe_info_block.OemSoftwareRev=0x0002;
		vbe_info_block.OemVendorNamePtr_Seg=0xc000;
		vbe_info_block.OemVendorNamePtr_Off=&vbebios_vendor_name;
		vbe_info_block.OemProductNamePtr_Seg=0xc000;
		vbe_info_block.OemProductNamePtr_Off=&vbebios_product_name;
		vbe_info_block.OemProductRevPtr_Seg=0xc000;
		vbe_info_block.OemProductRevPtr_Off=&vbebios_product_revision;

		// copy updates in vbe_info_block back
		memcpyb(ES,DI,ss,&vbe_info_block,sizeof(vbe_info_block));
		
		result=0x4f;
	}
	else
	{
#ifdef DEBUG		
		printf("VBE failed VBE2 signature check\n");
#endif
		result=0x0100;
	}
	
	write_word(ss,AX,result);  
}

/** Function 01h - Return VBE Mode Information
 * 
 * Input:
 * 		AX	= 4F01h
 * 		CX	= Mode Number
 * 		ES:DI	= Pointer to buffer in which to place ModeInfoBlock structure
 * Output:
 * 		AX	= VBE Return Status
 * 
 */
void vbe_biosfn_return_mode_information(AX, CX, ES, DI)
Bit16u *AX;Bit16u CX; Bit16u ES;Bit16u DI;
{
	Bit16u result=0x0100;
	Bit16u ss=get_SS();
	ModeInfoBlock	info;
	ModeInfoListItem	*cur_info=&mode_info_list;
	Boolean	found=0;
	

#ifdef DEBUG		
	printf("VBE vbe_biosfn_return_mode_information ES%x DI%x CX%x\n",ES,DI,CX);
#endif

	while ((cur_info->mode!=VBE_VESA_MODE_END_OF_LIST) && (!found))
	{
		if (cur_info->mode==CX)
		{
			found=1;		
		}
		else
		{
			cur_info++;
		}
	}
	
	if (found)
	{
#ifdef DEBUG		
		printf("VBE found mode %x\n",CX);
#endif	
		memsetb(ss,&info,0,sizeof(ModeInfoBlock));
		memcpyb(ss,&info,0xc000,&(cur_info->info),sizeof(ModeInfoBlockCompact));
		
		result=0x4f;	
	}
	else
	{
#ifdef DEBUG		
		printf("VBE *NOT* found mode %x\n",CX);
#endif		
		result=0x100;
	}
	
	if (result==0x4f)
	{
		// copy updates in mode_info_block back
		memcpyb(ES,DI,ss,&info,sizeof(info));
	}	

	write_word(ss,AX,result);
}

/** Function 02h - Set VBE Mode
 * 
 * Input:
 * 		AX	= 4F02h
 * 		BX	= Desired Mode to set
 *		ES:DI	= Pointer to CRTCInfoBlock structure
 * Output:
 * 		AX	= VBE Return Status
 * 
 */
void vbe_biosfn_set_mode(AX, BX, ES, DI)
Bit16u *AX;Bit16u BX; Bit16u ES;Bit16u DI;
{
	Bit16u ss=get_SS();
	Bit16u result;
	ModeInfoListItem *cur_info=&mode_info_list;	
	Boolean	found=0;
	Boolean using_lfb;
	
	using_lfb=((BX & VBE_MODE_LINEAR_FRAME_BUFFER) == VBE_MODE_LINEAR_FRAME_BUFFER);
	BX=(BX & 0x1ff);
	
	//result=read_word(ss,AX);
	
	while ((cur_info->mode!=VBE_VESA_MODE_END_OF_LIST) && (!found))
	{
		if (cur_info->mode==BX)
		{
			found=1;		
		}
		else
		{
			cur_info++;
		}
	}
	if (found)
	{
#ifdef DEBUG		
		printf("VBE found mode %x, setting:\n",BX);
		printf("\txres%x yres%x bpp%x\n",
			cur_info->info.XResolution,
			cur_info->info.YResolution,
			cur_info->info.BitsPerPixel);
#endif	
		
		result=0x4f;
	}
	else
	{
#ifdef DEBUG		
		printf("VBE *NOT* found mode %x\n",BX);
#endif	
		result=0x100;
		
		if (BX==3)
			result=0x4f;
	}
		
	write_word(ss,AX,result);
}

/** Function 03h - Return Current VBE Mode
 * 
 * Input:
 * 		AX	= 4F03h
 * Output:
 * 		AX	= VBE Return Status
 *		BX	= Current VBE Mode
 * 
 */
void vbe_biosfn_return_current_mode(AX, BX)
Bit16u *AX;Bit16u *BX;
{
	Bit16u ss=get_SS();

#ifdef DEBUG		
	printf("VBE vbe_biosfn_return_current_mode\n");
#endif
	
	write_word(ss,AX,0x4f);
	write_word(ss,BX,0x3);
}

/** Function 04h - Save/Restore State
 * 
 * Input:
 * 		AX	= 4F04h
 *		DL	= 00h Return Save/Restore State buffer size
 *			  01h Save State
 *			  02h Restore State
 *		CX	= Requested states
 *		ES:BX	= Pointer to buffer (if DL <> 00h)
 * Output:
 * 		AX	= VBE Return Status
 *		BX	= Number of 64-byte blocks to hold the state buffer (if DL=00h)
 * 
 */
void vbe_biosfn_save_restore_state(AX, DL, CX, ES, BX); 

/** Function 05h - Display Window Control
 * 
 * Input:
 * 		AX	= 4F05h
 * Note:
 *		If this function is called while in a linear frame buffer mode,
 *		this function must fail with completion code AH=03h
 * 
 * Output:
 * 		AX	= VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_display_window_control(AX); 

/** Function 06h - Set/Get Logical Scan Line Length
 * 
 * Input:
 * 		AX	= 4F06h
 * Output:
 * 		AX	= VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_set_get_logical_scan_line_length(AX); 

/** Function 07h - Set/Get Display Start
 * 
 * Input:
 * 		AX	= 4F07h
 * Output:
 * 		AX	= VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_set_get_display_start(AX);

/** Function 08h - Set/Get Dac Palette Format
 * 
 * Input:
 * 		AX	= 4F08h
 * Output:
 * 		AX	= VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_set_get_dac_palette_format(AX); 

/** Function 09h - Set/Get Palette Data
 * 
 * Input:
 * 		AX	= 4F09h
 * Output:
 * 		AX	= VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_set_get_palette_data(AX);

/** Function 0Ah - Return VBE Protected Mode Interface
 * 
 * Input:
 * 		AX	= 4F0Ah
 * Output:
 * 		AX	= VBE Return Status
 *
 * FIXME: incomplete API description, Input & Output
 */
void vbe_biosfn_return_protected_mode_interface(AX);
