
// headers.h:
//    definitions used in most of the program are found here
//

#ifndef HEADERS_H
#define HEADERS_H


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pe_header.h"

// functions to read little endian data (strings and integers)
char     *read_str(FILE *in, int count);
uint8_t   read8_le(FILE *in);
uint16_t  read16_le(FILE *in);
uint32_t  read32_le(FILE *in);
uint64_t  read64_le(FILE *in);


// functions that perform high level tasks 
void load_file(int argc, char *argv[]);
void print_headers(dos_header_t *dosHeader);
void print_dataTables(dos_header_t *dosHeader);
void print_sections(dos_header_t *dosHeader);


#endif