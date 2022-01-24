#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "elf64.h"
#include "find_symbol.h"


bool is_elf(FILE* fd){
    char* magic_num = malloc(sizeof(char) * 5);

    if(fread(magic_num, 1,4, fd) <4){
        fclose(fd);
        return false;
    }
    magic_num[4] = '\0';
    if(strcmp(magic_num +1 , "ELF") != 0){
        free(magic_num);
        return false;
    }
    free(magic_num);
    return true;
}

long find_symbol(char* symbol_name, char* exe_file_name, unsigned int* local_count){
    FILE* exe_file = fopen(exe_file_name, "r");

    if(!is_elf(exe_file)){
        fclose(exe_file);
        return NOT_EXECUTABLE;
    }
    fclose(exe_file);

    int fd = open(exe_file_name, O_RDONLY);
    void *elf = mmap(NULL, lseek(fd, 0, SEEK_END),PROT_READ, MAP_PRIVATE, fd, 0);

    Elf64_Ehdr* header = (Elf64_Ehdr*)elf; 
    // Set position to section header(beginning of file + offset)
    Elf64_Shdr* section_headers = (Elf64_Shdr*)((char*)elf + header->e_shoff);
   
    // Find string table and symbol table
    Elf64_Shdr section_header_string_table_header = section_headers[header->e_shstrndx];
    Elf64_Sym *symbol_table;
    int symbol_table_index;
    char *str_table;

    char *section_header_string_table = (char *)elf + section_header_string_table_header.sh_offset;

    for(int i = 0; i < header->e_shnum; i++){
        char* section_name = section_header_string_table + section_headers[i].sh_name;
        if(strcmp(".symtab", section_name) == 0|| section_headers[i].sh_type == SHT_SYMTAB){
            symbol_table = (Elf64_Sym*)((char *)elf + section_headers[i].sh_offset);
            symbol_table_index = i;
        }
        if((strcmp(".strtab", section_name) == 0 || section_headers[i].sh_type == SHT_STRTAB)
        && (char*)elf + section_headers[i].sh_offset != section_header_string_table){
            str_table = (char*)elf + section_headers[i].sh_offset;
        }
    }
    // Count
    int count = 0;
    int symbol_num = section_headers[symbol_table_index].sh_size / section_headers[symbol_table_index].sh_entsize;
    for(int i = 0; i < symbol_num; i++){
        char* current_symbol = str_table + symbol_table[i].st_name;
        if(current_symbol != NULL && strcmp(symbol_name, current_symbol) == 0){
            if(ELF64_ST_BIND(symbol_table[i].st_info) == GLOBAL){
                close(fd);
                return symbol_table[i].st_value;
            } else {
                count++;
            }
        }
    }

   close(fd);
   if(count == 0){
       return NOT_FOUND;
   }
   *local_count = count;
   return LOCAL_SYMBOL;
}