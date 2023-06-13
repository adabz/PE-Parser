// main.c:
//    main block of PErser program

#include "headers.h"

int main(int argc, char *argv[])
{
  if( argc < 2 )
  {
    printf("please supply at least One valid PE file\n");
    exit(1);
  }

  load_file(argc, argv);
  return 0;
}