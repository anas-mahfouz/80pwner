/* 80PWNER sample — intentionally vulnerable C program.
   by Anas Mahfouz (The 80) — for educational/CTF use on binaries you own.

   Contains: gets() (unbounded read), strcpy() (no bounds check) and
   printf(buf) (format-string bug). Built variants prove the checksec panel:
   --none      : no protections at all
   --partial   : compiler defaults (PIE+canary+partial RELRO on modern distros)
   --full      : every mitigation enabled
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void win(void) {
    puts("[80PWNER] win() reached — flag{the80_checksec_demo}");
    system("/bin/sh");
}

int main(int argc, char **argv) {
    char buf[64];
    (void)argc; (void)argv;
    printf("** 80PWNER sample **\nEnter input: ");
    gets(buf);              /* critical: unbounded stack read      */
    strcpy(buf, buf);       /* high: redundant unsafe copy         */
    printf(buf);            /* medium: format-string usage         */
    puts(win == NULL ? "" : "");
    return 0;
}
