/*
Copyright (c) 2017. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stddef.h>
#include <stdint.h>
#include <yara.h>

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <dirent.h>

/////MELKOR Declares/////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#define VERSION "v1.0"

#define SWAP32(v) ((((v) & 0x000000ff) << 24) | \
                   (((v) & 0x0000ff00) <<  8) | \
                   (((v) & 0x00ff0000) >>  8) | \
                   (((v) & 0xff000000) >> 24))

/* FUZZING MODES */
#define	AUTO	(1 <<  0) // Autodetect (based on e_type)
#define	HDR	(1 <<  1) // Elf Header
#define	SHT	(1 <<  2) // Section Header Table
#define	PHT	(1 <<  3) // Program Header Table
#define	SYM	(1 <<  4) // Symbols Table
#define DYN	(1 <<  5) // Dynamic info
#define REL	(1 <<  6) // Relocation data
#define NOTE	(1 <<  7) // Notes section
#define STRS	(1 <<  8) // Strings in the file
#define ALL	(HDR | SHT | PHT | SYM | DYN | REL | NOTE | STRS)
#define ALLB	(SHT | PHT | SYM | DYN | REL | NOTE | STRS)


/* -DDEBUG was deleted from CFLAGS in Makefile.
   Add -DDEBUG if you want to print extra info.
*/
#ifdef DEBUG
#define debug(...) if(!quiet) printf(__VA_ARGS__)
#else
#define debug(...) //
#endif


/* Function pointer type 'func_ptr'. 
   It will be used to create arrays of function pointers in fuzz_*.c 
*/
typedef int (*func_ptr)(void);

extern int PAGESIZE = 4096; // Set at runtime with getpagesize() in melkor.c

#ifndef PT_GNU_STACK
#define PT_GNU_STACK 0x6474e551 // Indicates executable stack
#endif

#ifndef PT_GNU_RELRO
#define PT_GNU_RELRO 0x6474e552 // Read-only after relocation
#endif

#ifndef PT_PAX_FLAGS
#define PT_PAX_FLAGS 0x65041580 // PAX Flags
#endif

// SHT_GNU_*
#ifndef SHT_GNU_ATTRIBUTES
#define SHT_GNU_ATTRIBUTES 0x6ffffff5
#endif

#ifndef SHT_GNU_HASH
#define SHT_GNU_HASH 0x6ffffff6
#endif

#ifndef SHT_GNU_LIBLIST
#define SHT_GNU_LIBLIST 0x6ffffff7
#endif

#ifndef SHT_GNU_verdef
#define SHT_GNU_verdef 0x6ffffffd
#endif

#ifndef SHT_GNU_verneed
#define SHT_GNU_verneed 0x6ffffffe
#endif

#ifndef SHT_GNU_versym
#define SHT_GNU_versym 0x6fffffff
#endif

/* ELF STUFF */
/*** 32 - 64 BITS COMPAT ***/
#if defined(__i386__)           /**** x86 ****/
// Data Types
#define Elf_Half Elf32_Half
#define Elf_Word Elf32_Word
#define Elf_Sword Elf32_Sword
#define Elf_Xword Elf32_Xword
#define Elf_Sxword Elf32_Sxword
#define Elf_Addr Elf32_Addr
#define Elf_Off Elf32_Off
#define Elf_Section Elf32_Section

// Data Structs
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define Elf_Phdr Elf32_Phdr
#define Elf_Dyn Elf32_Dyn
#define Elf_Nhdr Elf32_Nhdr

// Macros
#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_INFO ELF32_ST_INFO
#define ELF_ST_VISIBILITY ELF32_ST_VISIBILITY
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_INFO ELF32_R_INFO

#define HEX "%.8x"

#elif defined(__x86_64__)       /**** x86_64 ****/
// Data Types
#define Elf_Half Elf64_Half
#define Elf_Word Elf64_Word
#define Elf_Sword Elf64_Sword
#define Elf_Xword Elf64_Xword
#define Elf_Sxword Elf64_Sxword
#define Elf_Addr Elf64_Addr
#define Elf_Off Elf64_Off
#define Elf_Section Elf64_Section

// Data Structs
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rel
#define Elf_Rela Elf64_Rela
#define Elf_Phdr Elf64_Phdr
#define Elf_Dyn Elf64_Dyn
#define Elf_Nhdr Elf64_Nhdr

// Macros
#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_INFO ELF64_ST_INFO
#define ELF_ST_VISIBILITY ELF64_ST_VISIBILITY
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_INFO ELF64_R_INFO

#define HEX "%.16lx"
#else
#error  "Unsupported arch !"
#endif


/* PROTOTYPES */
void usage(const char *);
void banner();
int  elf_identification(int);
void verifySHT(void);
void verifyPHT(void);

FILE *start_logger(char *logfname, char *elfname){
	FILE* logfp = fopen(logfname, "a"); // Open file for appending
    if (logfp == NULL) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }

    if (elfname != NULL) {
        fprintf(logfp, "ELF Name: %s\n", elfname); // Log the ELF name
    }

    return logfp;
}

void stop_logger(FILE* logfp) {
    if (logfp != NULL) {
        fclose(logfp); // Close the log file
    }
}

void fuzz_hdr(void);
void fuzz_sht(void);
void fuzz_pht(void);
void fuzz_sym(void);
void fuzz_dyn(void);
void fuzz_rel(void);
void fuzz_note(void);
void fuzz_strs(void);

unsigned int getseed(void);
Elf_Addr getElf_Addr(void);
Elf_Off getElf_Off(void);
Elf_Word getElf_Word(void);
Elf_Xword getElf_Xword(void);
Elf_Half getElf_Half(void);
Elf_Section getElf_Section(void);
char *get_fmt_str(void);
char *get_fuzzed_path(void);

Elf_Section findSectionIndexByName(char *);
void fuzzName(void);
void fuzzSize(void);
void fuzzEntSize(void);
void fuzzFlags(void);
void fuzzAddrAlign(void);

Elf_Addr get_d_ptr_by_d_tag(Elf_Sword);
Elf_Word get_d_val_by_d_tag(Elf_Sword);

/* GLOBAL VARS */
FILE		*logfp;
struct stat	elfstatinfo;
// unsigned int 	AUTO = 0;
unsigned int	mode = 0;   // Metadata to fuzz (parameters)
unsigned int	orcn = 0;   // OrcN inside the for() loop. fuzz_* modules will use it through different loops
unsigned int	n = 100;   // Default for option -n
unsigned int	quiet = 1;  // For quiet mode (-q). Default is quiet [debug() output]
unsigned int	likelihood = 10; // Likelihood given in % of the execution of each rule in the main for() loop in fuzz_*.c. Default 10%
unsigned int	like_a = 10, like_b = 1; // Based upon the likelihood, these will be used for: rand() % like_a < like_b. Default values for 10%
unsigned int	secnum = 0; // Used in loops here but refered in fuzz_*.c as the section number
unsigned int	entry  = 0; // Used in loops here but refered in fuzz_*.c as the entry number inside a section (for DYN, SYM, REL)
char		*dirname_orcfname;
char		*elfptr, *orcptr;
char		*elfSTRS, *orcSTRS;
Elf_Ehdr	*elfHDR, *orcHDR;
Elf_Shdr	*elfSHT, *orcSHT;
Elf_Phdr	*elfPHT, *orcPHT;
Elf_Sym		*elfSYM, *orcSYM;
Elf_Dyn		*elfDYN, *orcDYN;
Elf_Rel		*elfREL, *orcREL;
Elf_Rela	*elfRELA, *orcRELA;
Elf_Nhdr	*elfNOTE, *orcNOTE;
Elf_Off		elfshstrtab_offset = 0, orcshstrtab_offset = 0, linkstrtab_offset = 0;
Elf_Shdr	*orcOrigSHT;
Elf_Phdr	*orcOrigPHT;
Elf_Dyn		*elfOrigDYN;

extern int errno;
// extern int PAGESIZE = 4096;

YR_RULES* rules = NULL;


extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{

    YR_COMPILER* compiler;
    YR_RULES* rules;
    const char* rules_dir = "generated_rules"; // Specify your rules directory here
    struct dirent* entry;
    DIR* dp;

    if (yr_initialize() != ERROR_SUCCESS)
        return 0;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        return 0;

    dp = opendir(rules_dir);
    if (dp == NULL) {
        perror("Failed to open rules directory");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 0;
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) { // Check if it is a regular file
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/%s", rules_dir, entry->d_name);
            
            FILE* rule_file = fopen(filepath, "r");
            if (rule_file == NULL) {
                perror("Failed to open rule file");
                continue;
            }
             // Determine the file size
            fseek(rule_file, 0, SEEK_END);
            long file_size = ftell(rule_file);
            fseek(rule_file, 0, SEEK_SET);

            // Allocate memory for the file content
            char* file_content = (char*)malloc(file_size + 1);
            if (file_content == NULL) {
                perror("Failed to allocate memory for file content");
                fclose(rule_file);
                continue;
            }

            // Read the file content
            fread(file_content, 1, file_size, rule_file);
            file_content[file_size] = '\0'; // Null-terminate the string

            fclose(rule_file);

            // Add the file content as a string to the compiler
            int errors = yr_compiler_add_string(compiler, file_content, NULL);
            free(file_content);

            if (errors != 0) {
                fprintf(stderr, "Error loading rules from %s\n", filepath);
            }
        }
    }
    closedir(dp);

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get compiled rules\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 0;
    }

    yr_compiler_destroy(compiler);

  return 0;

}

int callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  return CALLBACK_CONTINUE;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) 
{
    int		opt, elffd, orcfd, fuzzed_flag = 0, k = 0;
	char        *elfname;
	Elf_Shdr	elfshstrtab_section, orcshstrtab_section, linkstrtab_section;

	if(likelihood < 1 || likelihood > 100){
		fprintf(stderr, "[!] Likelihood (-l) is given in %% and must be between 1 and 100\n");
		exit(EXIT_FAILURE);
	}

	if(data == NULL){
		fprintf(stderr, "[!] <ELF file template> not supplied !\n");
		exit(EXIT_FAILURE);
	}
    /* Separate the filename from the dirname. The same as basename() */
	
	elfname  = strrchr((char*)data, '/');
	if(!elfname)
		elfname = (char*)data;
	else
		elfname = strrchr((char*)data, '/') + 1;

    if((elffd = open((char*)data, O_RDONLY)) == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	if(!elf_identification(elffd)){
		fprintf(stderr, "[!] '%s' is not an ELF file. Invalid magic number !\n", elfname);
		close(elffd);
		exit(EXIT_FAILURE);
	}

	if(fstat(elffd, &elfstatinfo) == -1){
		perror("stat");
		close(elffd);
		exit(EXIT_FAILURE);
	}

	if((elfptr = (char *) mmap(NULL, elfstatinfo.st_size, PROT_READ, MAP_SHARED, elffd, 0)) == MAP_FAILED){
		perror("mmap");
		close(elffd);
		exit(EXIT_FAILURE);
	}

	close(elffd);
    
	elfHDR = (Elf_Ehdr *) (elfptr);
	elfSHT = (Elf_Shdr *) (elfptr + elfHDR->e_shoff);
	elfPHT = (Elf_Phdr *) (elfptr + elfHDR->e_phoff);
	elfshstrtab_section = *(Elf_Shdr *) (elfSHT + elfHDR->e_shstrndx);
	elfshstrtab_offset  = elfshstrtab_section.sh_offset;

	char dirname[strlen("orcs_") + strlen(elfname) + 1];
	char orcfname[strlen("orc_") + 16];
	char logfname[strlen("Report_") + strlen(elfname) + 5];
	const char *ext = "";
	if(strcmp(elfname + strlen(elfname) - 2, ".o") == 0)
		ext = ".o";
	if(strcmp(elfname + strlen(elfname) - 3, ".so") == 0)
		ext = ".so";

	char* dirname_orcfname = (char*)malloc(sizeof(dirname) + sizeof(orcfname) + 2);

	snprintf(dirname, sizeof(dirname), "orcs_%s", elfname);
	snprintf(logfname, sizeof(logfname), "Report_%s.txt", elfname);

	if(mkdir(dirname, 0775) == -1)
		if(errno == EEXIST)
			printf("[!] Dir '%s' already exists. Files inside will be overwritten !\n", dirname);

    // printf("%s", elf_ascii[0]);
	// // printf(elf_ascii[1], argv[optind]);
	// printf("%s", elf_ascii[2]);
	// printf(elf_ascii[3], n);
	// printf("%s", elf_ascii[4]);

	if(mode & AUTO){
		printf("[+] Automatic mode\n");
		printf("[+] ELF type detected: ");

		switch(elfHDR->e_type){
			case ET_NONE:
				printf("ET_NONE");
				break;
			case ET_REL:
				printf("ET_REL");
				break;
			case ET_EXEC:
				printf("ET_EXEC");
				break;
			case ET_DYN:
				printf("ET_DYN");
				break;
			case ET_CORE:
				printf("ET_CORE");
				break;
			default:
				printf("Unknown e_type !\n");
				printf("[+] All the metadata (except) the header will be fuzzed\n\n");
		}

		if(elfHDR->e_type > 0 && elfHDR->e_type < 5){
			printf("\n[+] Selecting the metadata to fuzz\n\n");

			int metadata_by_e_type[5][8] = {
						/* HDR  SHT  PHT  SYM  DYN  REL  NOTE  STRS */
				/* ET_NONE */    {  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,   0   }, // Untouched
				/* ET_REL  */    {  0 , SHT,  0 , SYM,  0 , REL,  0 ,  STRS },
				/* ET_EXEC */    {  0 , SHT, PHT, SYM, DYN, REL, NOTE, STRS },
				/* ET_DYN  */    {  0 , SHT, PHT, SYM, DYN, REL, NOTE, STRS },
				/* ET_CORE */    {  0 ,  0 , PHT,  0 ,  0 ,  0 ,  0  ,  0   },
			};

			for(k = 0; k < 8; k++)
				mode |= metadata_by_e_type[elfHDR->e_type][k];
		} else {
			mode = ALLB; // All except the ELF header
		}
	}

	printf("[+] Detailed log for this session: '%s/%s' \n\n", dirname, logfname);

	printf("[+] The Likelihood of execution of each rule is: ");
	printf("Aprox. %d %% (rand() %% %d < %d)\n\n", likelihood, like_a, like_b);

	if ( !quiet )
	{
		printf("[+] Press any key to start the fuzzing process...\n");
		getchar();
	}

	chdir(dirname);

	logfp = start_logger(logfname, elfname);

	srand(seed);
	PAGESIZE = getpagesize();

	for(orcn = 1; orcn <= n; orcn++){
		snprintf(orcfname, sizeof(orcfname), "orc_%.4d%s", orcn, ext);
		snprintf(dirname_orcfname, sizeof(dirname) + sizeof(orcfname) + 2, "%s/%s", dirname, orcfname);

		if((orcfd = creat(orcfname, elfstatinfo.st_mode)) == -1){
			perror("creat");
			continue;
		}

		if(write(orcfd, elfptr, elfstatinfo.st_size) == -1){
			perror("write");
			continue;
		}

		close(orcfd);

		if((orcfd = open(orcfname, O_RDWR)) == -1){
			perror("open");
			continue;
		}

		if((orcptr = (char *) mmap(NULL, elfstatinfo.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, orcfd, 0)) == MAP_FAILED){
			perror("mmap");
			close(orcfd);
			continue;
		}


		orcHDR = (Elf_Ehdr *) (orcptr);
		orcOrigSHT = (Elf_Shdr *) (orcptr + orcHDR->e_shoff);
		orcOrigPHT = (Elf_Phdr *) (orcptr + orcHDR->e_phoff);
		orcshstrtab_section = *(Elf_Shdr *) (orcOrigSHT + orcHDR->e_shstrndx);
		orcshstrtab_offset  = orcshstrtab_section.sh_offset;

		printf("\n=================================================================================\n");
		printf("[+] Malformed ELF '%s':\n", orcfname);
		fprintf(logfp, "\n=================================================================================\n\n");
		fprintf(logfp, "[+] Malformed ELF: '%s':\n\n", orcfname);

		if(mode & REL){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_REL && orcSHT->sh_type != SHT_RELA)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				if(orcSHT->sh_type == SHT_REL){
					orcREL =  (Elf_Rel *)  (orcptr + orcSHT->sh_offset);
				} else {
					orcRELA = (Elf_Rela *) (orcptr + orcSHT->sh_offset);
				}

				printf("\n[+] Fuzzing the relocations section %s with %d %s entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize),
					orcSHT->sh_type == SHT_REL ? "SHT_REL" : "SHT_RELA");
				fprintf(logfp, "\n[+] Fuzzing the relocations section %s with %d %s entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize),
					orcSHT->sh_type == SHT_REL ? "SHT_REL" : "SHT_RELA");

				for(entry = 0; entry < orcSHT->sh_size / orcSHT->sh_entsize; entry++){
					// fuzz_rel();

					fuzzed_flag = 1;

					if(orcSHT->sh_type == SHT_REL)
						orcREL++;
					else
						orcRELA++;
				}
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_REL nor SHT_RELA sections found!\n");
				fprintf(logfp, "\n[!] No SHT_REL nor SHT_RELA sections found!\n");
			}
		}

		if(mode & SYM){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_SYMTAB && orcSHT->sh_type != SHT_DYNSYM)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				linkstrtab_section = *(Elf_Shdr *) (orcptr + orcHDR->e_shoff + (orcSHT->sh_link * sizeof(Elf_Shdr)));
				linkstrtab_offset  = linkstrtab_section.sh_offset;

				elfSYM = (Elf_Sym *) (elfptr + orcSHT->sh_offset);
				orcSYM = (Elf_Sym *) (orcptr + orcSHT->sh_offset);

				printf("\n[+] Fuzzing the Symbol Table %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));
				fprintf(logfp, "\n[+] Fuzzing the Symbol Table %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));

				for(entry = 0; entry < orcSHT->sh_size / orcSHT->sh_entsize; entry++, elfSYM++, orcSYM++){
					// fuzz_sym();

					fuzzed_flag = 1;
				}
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_SYMTAB nor SHT_DYNSYM sections found!\n");
				fprintf(logfp, "\n[!] No SHT_SYMTAB nor SHT_DYNSYM sections found!\n");
			}
		}

		if(mode & DYN){
			verifyPHT();
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_DYNAMIC)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				linkstrtab_section = *(Elf_Shdr *) (orcptr + orcHDR->e_shoff + (orcSHT->sh_link * sizeof(Elf_Shdr)));
				linkstrtab_offset  = linkstrtab_section.sh_offset;

				elfOrigDYN = (Elf_Dyn *) (elfptr + orcSHT->sh_offset);
				elfDYN = elfOrigDYN;
				orcDYN = (Elf_Dyn *) (orcptr + orcSHT->sh_offset);

				printf("\n[+] Fuzzing the Dynamic section %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));
				fprintf(logfp, "\n[+] Fuzzing the Dynamic section %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));

				for(entry = 0; entry < orcSHT->sh_size / orcSHT->sh_entsize; entry++, elfDYN++, orcDYN++){
					// fuzz_dyn();

					fuzzed_flag = 1;

					if(elfDYN->d_tag == DT_NULL)// End of _DYNAMIC[]. Trust in elfDYN, orcDYN->d_tag = NULL might have been changed
						break;
				}
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_DYNAMIC section found!\n");
				fprintf(logfp, "\n[!] No SHT_DYNAMIC section found!\n");
			}
		}

		if(mode & NOTE){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_NOTE)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				printf("\n[+] Fuzzing the Note section %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);
				fprintf(logfp, "\n[+] Fuzzing the Note section %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);

				elfNOTE = (Elf_Nhdr *) (elfptr + orcSHT->sh_offset);
				orcNOTE = (Elf_Nhdr *) (orcptr + orcSHT->sh_offset);

				// fuzz_note();

				fuzzed_flag = 1;
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_NOTE section found!\n");
				fprintf(logfp, "\n[!] No SHT_NOTE section found!\n");
			}
		}

		if(mode & STRS){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_STRTAB)
					continue;

				// Metadata dependencies
				if(secnum == orcHDR->e_shstrndx)
					if(mode & (SHT | NOTE | DYN | SYM | REL))
						if(rand() % 3 < 2)
							continue;

				if(orcSHT->sh_size == 0)
					continue;

				printf("\n[+] Fuzzing the String Table %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);
				fprintf(logfp, "\n[+] Fuzzing the String Table %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);

				orcSTRS = (char *) (orcptr + orcSHT->sh_offset);

				// fuzz_strs();

				fuzzed_flag = 1;
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_STRTAB section found!\n");
				fprintf(logfp, "\n[!] No SHT_STRTAB section found!\n");
			}
		}

		if(mode & SHT){
			verifySHT();
			orcSHT = orcOrigSHT;

			printf("\n[+] Fuzzing the Section Header Table with %d entries\n", orcHDR->e_shnum);
			fprintf(logfp, "\n[+] Fuzzing the Section Header Table with %d entries\n", orcHDR->e_shnum);

			// fuzz_sht();
		}

		if(mode & PHT){
			verifyPHT();
			orcPHT = orcOrigPHT;

			printf("\n[+] Fuzzing the Program Header Table with %d entries\n", orcHDR->e_phnum);
			fprintf(logfp, "\n[+] Fuzzing the Program Header Table with %d entries\n", orcHDR->e_phnum);

			// fuzz_pht();
		}

		if(mode & HDR){
			printf("\n[+] Fuzzing the Elf Header\n");
			fprintf(logfp, "\n[+] Fuzzing the Elf Header\n");

			// fuzz_hdr();
		}

		// Reflect the changes in filesystem
		if(msync(orcptr, 0, MS_SYNC) == -1){
			perror("msync");
			munmap(orcptr, elfstatinfo.st_size);
			close(orcfd);
			continue;
		}

		munmap(orcptr, elfstatinfo.st_size);

		close(orcfd);

		usleep(20000);
	}

	stop_logger(logfp);

	printf("\n[+] Fuzzing process finished\n");
	printf("[+] Orcs (malformed ELFs) saved in '%s/'\n", dirname);
	printf("[+] Detailed fuzzing report: '%s/%s'\n", dirname, logfname);

	munmap(elfptr, elfstatinfo.st_size);

	exit(EXIT_SUCCESS);
    

}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (rules == NULL)
    return 0;

  yr_rules_scan_mem(
      rules, data, size, SCAN_FLAGS_NO_TRYCATCH, callback, NULL, 0);

  return 0;
}


int elf_identification(int fd)
{
	Elf_Ehdr	header;

	if(read(fd, &header, sizeof(header)) == -1){
		perror("elf_identification: read");
		return 0;
	}

	return memcmp(&header.e_ident[EI_MAG0], ELFMAG, SELFMAG) == 0;
}

void verifySHT()
{
	if(elfHDR->e_shoff == 0 || elfHDR->e_shnum == 0){
		printf("[-] No Section Header Table found (necessary for fuzzing) !\n");
		printf("[-] Quitting...\n");
		munmap(elfptr, elfstatinfo.st_size);
		exit(EXIT_FAILURE);
	}
}

void verifyPHT()
{
	if(elfHDR->e_phoff == 0 || elfHDR->e_phnum == 0){
		printf("[-] No Program Header Table found (necessary for fuzzing) !\n");
		printf("[-] Quitting...\n");
		munmap(elfptr, elfstatinfo.st_size);
		exit(EXIT_FAILURE);
	}
}
