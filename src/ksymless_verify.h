/*
 * ksymless_verify.h
 */

#ifndef CKSU_KSYMLESS_VERIFY_H
#define CKSU_KSYMLESS_VERIFY_H

unsigned long resolve(const char *name);
void verify_sct(void);
void verify_kallsyms(void);
void dump_kallsyms_layout(void);

#endif
