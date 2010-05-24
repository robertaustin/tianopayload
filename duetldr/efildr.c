/*
 *
 * Copyright (c) 2009, Islam M. Ahmed Zaid.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <libpayload-config.h>
#include <libpayload.h>
#include <coreboot_tables.h>

#include "EfildrHandoff.h"
#include "PeImage.h"
#include "Efildr.h"

#ifdef DEBUG
#define dprintf(x...) printf(x)
#else
#define dprintf(x...)
#endif

int EfiLdrGetPeImageInfo(void *FHand, uint64_t *EntryPoint)
{
	EFI_IMAGE_DOS_HEADER			*DosHdr;
	EFI_IMAGE_OPTIONAL_HEADER_UNION	*PeHdr;
	EFI_IMAGE_SECTION_HEADER		*Section;
	uint32_t						AddressOfEntryPoint;
	uint64_t						ImageBase;
	uint16_t						SectionCount;

	DosHdr = FHand;
	if (DosHdr->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return -1;

	PeHdr = FHand + DosHdr->e_lfanew;
	if (PeHdr->Pe32.Signature != EFI_IMAGE_NT_SIGNATURE)
		return -1;

	SectionCount = PeHdr->Pe32.FileHeader.NumberOfSections;

	EFI_IMAGE_FILE_HEADER *FileHeader = &PeHdr->Pe32.FileHeader;

	Section = FHand + DosHdr->e_lfanew + sizeof(PeHdr->Pe32.Signature) + 
		sizeof(PeHdr->Pe32.FileHeader) + FileHeader->SizeOfOptionalHeader;

	if (PeHdr->Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		ImageBase = (uint32_t)PeHdr->Pe32.OptionalHeader.ImageBase;
	}
	else if (PeHdr->Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		ImageBase = PeHdr->Pe32Plus.OptionalHeader.ImageBase;
	}
	else
		return -1;
	if (ImageBase == 0)
		ImageBase = 0x10000;
	dprintf("ImageBase: 0x%016llx\n", ImageBase);

	AddressOfEntryPoint = PeHdr->Pe32.OptionalHeader.AddressOfEntryPoint;
	dprintf("AddressOfEntryPoint: 0x%08x\n", AddressOfEntryPoint);

	uint16_t i;
	for (i = 0; i < SectionCount; i++, Section++)
	{
#if DEBUG_PE
		dprintf("%s\n", Section->Name);
		dprintf("  VirtualAddress: 0x%016llx\n", ImageBase + Section->VirtualAddress);
		dprintf("  SizeOfRawData: 0x%x\n", Section->SizeOfRawData);
		dprintf("  PointerToRawData: 0x%x\n", Section->PointerToRawData);
#endif
		memcpy((void *)(uint32_t)ImageBase + Section->VirtualAddress,
			FHand + Section->PointerToRawData, 
			Section->SizeOfRawData);
	}

	*EntryPoint = ImageBase + AddressOfEntryPoint;

	return 0;
}

/* parts copied from libpayload */
int get_coreboot_mmap(void *addr, int len, BIOS_MEMORY_MAP **mmap)
{
	struct cb_header *header;
	unsigned char *ptr = (unsigned char *)addr;
	int i;

	for (i = 0; i < len; i += 16, ptr += 16) {
		header = (struct cb_header *)ptr;
		if (!strncmp((const char *)header->signature, "LBIO", 4))
			break;
	}

	/* We walked the entire space and didn't find anything. */
	if (i >= len)
		return -1;

	if (!header->table_bytes)
		return 0;

	/* Make sure the checksums match. */
	if (ipchksum((u16 *) header, sizeof(*header)) != 0)
		return -1;

	if (ipchksum((u16 *) (ptr + sizeof(*header)),
		     header->table_bytes) != header->table_checksum)
		return -1;

	/* Now, walk the tables. */
	ptr += header->header_bytes;

	for (i = 0; i < header->table_entries; i++) {
		struct cb_record *rec = (struct cb_record *)ptr;

		/* We only care about a few tags here (maybe more later). */
		if (rec->tag == CB_TAG_FORWARD)
		{
			struct cb_forward *cb_forward = (struct cb_forward *)ptr;
			return get_coreboot_mmap(phys_to_virt(cb_forward->forward), 0x1000, mmap);
		}

		if (rec->tag == CB_TAG_MEMORY)
		{
			struct cb_memory *cb_mmap = (struct cb_memory *)ptr;
			dprintf("CB_MEMORY_MAP  @ 0x%x", (uint32_t)cb_mmap);
			*mmap = (BIOS_MEMORY_MAP *)(ptr + sizeof(cb_mmap->tag)); /* skip cb_memory.tag */
			dprintf(", INT15_E820 memory map @ 0x%x\n", (uint32_t)*mmap);

			int memrange_count = MEM_RANGE_COUNT(cb_mmap);
			dprintf("MEM_RANGE_COUNT: %d\n", memrange_count);

			/* convert to INT15_E820 memory map structure */
			cb_mmap->size = memrange_count * sizeof(struct cb_memory_range);

			int i;
			for (i = 0; i < memrange_count; i++)
			{
				struct cb_memory_range *cb_memrange = (struct cb_memory_range *)MEM_RANGE_PTR(cb_mmap, i);

				/* HACK: fix the case where HobGeneration processes regions above 1MB */
				if (cb_memrange->size.lo > 0x100000) // is this safe? (i.e. >4GB)
					if (cb_memrange->start.lo < 0x100000)
					{
						cb_memrange->size.lo -= 0x100000 - cb_memrange->start.lo;
						cb_memrange->start.lo = 0x100000;
					}
				/* change CB_MEM_TABLE to E820_AddressRange */
				if (cb_memrange->type == CB_MEM_TABLE)
					cb_memrange->type = INT15_E820_AddressRangeReserved;

				dprintf("MEM_RANGE: %d\n", i);
				dprintf("  start @ 0x%x\n", cb_memrange->start.lo);
				dprintf("  size:   0x%x\n", cb_memrange->size.lo);
				dprintf("  type:   %d\n", cb_memrange->type);
			}
			return 1;
		}
		ptr += rec->size;
	}

	return -1;
}

extern unsigned char Efildr32[];
typedef void (*EfiLoader_ptr)(uint32_t BiosMemoryMapBaseAddress, uint64_t Efildr32);

int main(void)
{
	dprintf("\n### START OF EFILDR PAYLOAD ###\n\n");

	BIOS_MEMORY_MAP *MemoryMap = 0;
	int ret = get_coreboot_mmap(phys_to_virt(0x00000000), 0x1000, &MemoryMap);

	if (ret != 1)
		ret = get_coreboot_mmap(phys_to_virt(0x000f0000), 0x1000, &MemoryMap);

	/* Efivar.bin doesn't exist */
	*((uint8_t *)0x19004) = 1;

	EFILDR_IMAGE *Efildr = (EFILDR_IMAGE *)((void *)Efildr32 + sizeof(EFILDR_HEADER));
	dprintf("\nEfildr32 @ 0x%x\n", (uint32_t)Efildr32);

	uint64_t EntryPoint = 0;
	if (EfiLdrGetPeImageInfo((void *)Efildr32 + Efildr->Offset, &EntryPoint) == -1)
	{
		printf("EfiLdrGetPeImageInfo: error\n");
		goto out;
	}
	dprintf("\nEntryPoint @ 0x%016llx\n", EntryPoint);
	dprintf("MemoryMap  @ 0x%x\n", (uint32_t)MemoryMap);
	EfiLoader_ptr EfiLoader = (EfiLoader_ptr)(uint32_t)EntryPoint;

	dprintf("\n### POINT OF NO RETURN! ###\n\n");
	/* clear the screen before the jump! */
	video_console_clear();

	if (EfiLoader && MemoryMap)
		EfiLoader((uint32_t)MemoryMap, (uint32_t)Efildr32);

out:
	printf("Halt!\n");
	halt();
	return 0;
}
