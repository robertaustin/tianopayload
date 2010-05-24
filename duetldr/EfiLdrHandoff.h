/*++

Copyright (c) 2006, Intel Corporation                                                         
All rights reserved. This program and the accompanying materials                          
are licensed and made available under the terms and conditions of the BSD License         
which accompanies this distribution.  The full text of the license may be found at        
http://opensource.org/licenses/bsd-license.php                                            
                                                                                          
THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

Module Name:
  EfiLdrHandoff.h

Abstract:

Revision History:

--*/

#ifndef _EFILDR_HANDOFF_H_
#define _EFILDR_HANDOFF_H_

typedef struct {
    uint32_t       CheckSum;
    uint32_t       Offset;
    uint32_t       Length;
    uint8_t        FileName[52];
} EFILDR_IMAGE;

typedef struct {          
    uint32_t       Signature;     
    uint32_t       HeaderCheckSum;
    uint32_t       FileLength;
    uint32_t       NumberOfImages;
} EFILDR_HEADER;

#endif
