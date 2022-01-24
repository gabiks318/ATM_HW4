#ifndef FIND_SYMBOL_H
#define FIND_SYMBOL_H

#define ET_EXEC 2     // Executable
#define SHT_SYMTAB 2  // Symbol Table
#define SHT_STRTAB 3  // String Table
#define GLOBAL 1
#define NOT_EXECUTABLE -3
#define NOT_FOUND -1
#define LOCAL_SYMBOL -2

bool is_elf(FILE* fd);
long find_symbol(char* symbol_name, char* exe_file_name, unsigned int* local_count);
#endif