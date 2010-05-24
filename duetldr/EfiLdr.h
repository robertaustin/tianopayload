/*++

Copyright (c) 2006, Intel Corporation                                                         
All rights reserved. This program and the accompanying materials                          
are licensed and made available under the terms and conditions of the BSD License         
which accompanies this distribution.  The full text of the license may be found at        
http://opensource.org/licenses/bsd-license.php                                            
                                                                                          
THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

Module Name:
  EfiLdr.c

Abstract:

Revision History:

--*/

#ifndef _DUET_EFI_LOADER_H_
#define _DUET_EFI_LOADER_H_

#define INT15_E820_AddressRangeMemory   1
#define INT15_E820_AddressRangeReserved 2
#define INT15_E820_AddressRangeACPI     3
#define INT15_E820_AddressRangeNVS      4

#define EFI_MAX_MEMORY_DESCRIPTORS 64

#pragma pack(4)
typedef struct {          
  uint64_t       BaseAddress;
  uint64_t       Length;
  uint32_t       Type;
} BIOS_MEMORY_MAP_ENTRY;
#pragma pack()

typedef struct {          
  uint32_t                MemoryMapSize;
  BIOS_MEMORY_MAP_ENTRY MemoryMapEntry[1];
} BIOS_MEMORY_MAP;

#endif //_DUET_EFI_LOADER_H_
