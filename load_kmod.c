#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>

#include "load_kmod.h"
#include "stubs.h"

struct map_info
{
	int fd;
	void *base;
	size_t length;
};

static struct map_info map_info;

static size_t calcsize(int fd)
{
	off_t ret = lseek(fd, 0, SEEK_END);
	assert(ret > 0);
	return ret;
}

static void *map_file(struct map_info *info, const char *filename)
{
	info->fd = open(filename, O_RDONLY);
	assert(info->fd != -1);

	info->length = calcsize(info->fd);

	info->base = mmap(NULL, info->length, PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE, info->fd, 0);
	assert(info->base != (void *)-1);

	return info->base;
}

#if 0
static void unmap_file(struct map_info *info)
{
	int ret = munmap(info->base, info->length);
	assert(ret == 0);
	ret = close(info->fd);
	assert(ret == 0);
}
#endif

static void check_file(char *base)
{
	assert(memcmp(base, ELFMAG, 4) == 0);
	assert(base[EI_DATA] == ELFDATA2LSB);
	assert(base[EI_CLASS] == ELFCLASS32);
}

static int find_section(void *base, const char *secname, size_t *secsize)
{
	Elf32_Ehdr *ehdr = base;
	Elf32_Shdr *secnames = base + ehdr->e_shoff +
		ehdr->e_shstrndx * sizeof(Elf32_Shdr);
	int i;

	for (i = 1; i < ehdr->e_shnum; i++) {
		Elf32_Shdr *sechdr = base + ehdr->e_shoff +
			i * sizeof(Elf32_Shdr);
		if (strcmp(base + secnames->sh_offset + sechdr->sh_name, secname) == 0) {
			*secsize = sechdr->sh_size;
			return sechdr->sh_offset;
		}
	}

	return -1;
}

static void load_strings(void *base, const char *secname)
{
	size_t secsize;
	int offset = find_section(base, secname, &secsize);
	int idx;

	assert(offset != -1);
	idx = offset;
	while (idx < offset + secsize) {
		char *string = (char *)base + idx;
		if (string[0] != '\0')
			fprintf(stderr, "%s: %s\n", secname, string);
		idx += strlen(string) + 1;
	}
}

static void *resolve_symbol(const char *name)
{
	int i;
	struct symbol_table *ptr;

	for (i = 0, ptr = symtable; ptr->name; i++, ptr = symtable + i) {
		if (strcmp(ptr->name, name) == 0)
			return ptr->func;
	}

	return NULL;
}

static Elf32_Shdr *simplify_symbols(void *base)
{
	int i, j;
	Elf32_Ehdr *ehdr = base;

	for (i = 1; i < ehdr->e_shnum; i++) {
		Elf32_Shdr *shdr = base + ehdr->e_shoff +
			i * sizeof(Elf32_Shdr);
		if (shdr->sh_type == SHT_SYMTAB) {
			for (j = 1; j < shdr->sh_size / sizeof(Elf32_Sym); j++) {
				Elf32_Sym *sym = base + shdr->sh_offset +
					j * sizeof(Elf32_Sym);
				Elf32_Shdr *strtab = base + ehdr->e_shoff +
					shdr->sh_link * sizeof(Elf32_Shdr);
				char *name = base + strtab->sh_offset + sym->st_name;
				Elf32_Shdr *sec;
				switch (sym->st_shndx) {
				case SHN_COMMON:
					fprintf(stderr, "Common symbol: %s\n", name);
					break;
				case SHN_ABS:
					fprintf(stderr, "Absolute symbol: 0x%08lx (%s)\n",
						(long)sym->st_value, name);
					break;
				case SHN_UNDEF:
					sym->st_value = (long)resolve_symbol(name);
					fprintf(stderr, "Undefined symbol: %s (%#lx)\n", name, (long)sym->st_value);
					break;
				default:
					sec = base + ehdr->e_shoff +
						sym->st_shndx * sizeof(Elf32_Shdr);
					sym->st_value += (long)base + sec->sh_offset;
				}
			}
			return shdr;
		}
	}

	return NULL;
}

static void apply_relocations(void *base)
{
	int i, j;
	Elf32_Ehdr *ehdr = base;

	Elf32_Shdr *symtab = simplify_symbols(base);
	for (i = 1; i < ehdr->e_shnum; i++) {
		Elf32_Shdr *sinfo, *shdr;
		shdr = base + ehdr->e_shoff + i * sizeof(Elf32_Shdr);
		if (shdr->sh_type == SHT_NOBITS) {
			fprintf(stderr, "Zeroing section %d\n", i);
			memset(base + shdr->sh_offset, 0, shdr->sh_size);
			continue;
		}
		if (shdr->sh_info >= ehdr->e_shnum)
			continue;
		sinfo = base + ehdr->e_shoff + shdr->sh_info * sizeof(Elf32_Shdr);
		if (!(sinfo->sh_flags & SHF_ALLOC))
			continue;
		if (shdr->sh_type == SHT_REL) {
			fprintf(stderr, "Applying relocate section %d to section %d\n",
				i, shdr->sh_info);
			for (j = 0; j < shdr->sh_size / sizeof(Elf32_Rel); j++) {
				Elf32_Rel *rel = base + shdr->sh_offset +
					j * sizeof(Elf32_Rel);
				long *location = base + sinfo->sh_offset +
					rel->r_offset;
				Elf32_Sym *sym = base + symtab->sh_offset +
					ELF32_R_SYM(rel->r_info) * sizeof(Elf32_Sym);

				switch (ELF32_R_TYPE(rel->r_info)) {
				case R_386_32:
					*location += sym->st_value;
					break;
				case R_386_PC32:
					*location += sym->st_value - (long)location;
					break;
				default:
					fprintf(stderr, "Unknown relocation type: %d\n",
						ELF32_R_TYPE(rel->r_info));
					continue;
				}
			}
		}
	}
}

void load_module(const char *path)
{
	size_t secsize;
	void *addr;
	int offset, i;

	addr = map_file(&map_info, path);
	check_file(addr);
	load_strings(addr, ".modinfo");

	apply_relocations(addr);

	offset = find_section(addr, ".init.text", &secsize);
	assert(offset > 0);
	init_module = addr + offset;

	offset = find_section(addr, ".exit.text", &secsize);
	assert(offset > 0);
	cleanup_module = addr + offset;

	offset = find_section(addr, ".ctors", &secsize);
	if (offset > 0) {
		for (i = 0; i < secsize; i += sizeof(void *)) {
			void (*ctor)() = (void *)*(long *)(addr + offset + i);
			fprintf(stderr, "*** calling constructor at %p ***\n",
					ctor);
			ctor();
		}
	} else
		fprintf(stderr, "WARNING: .ctors section not found\n");
}
