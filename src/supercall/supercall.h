// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_SUPERCALL_H
#define CKSU_SUPERCALL_H

#define CKSU_HELLO          0x0001
#define CKSU_GET_CHALLENGE  0x1000
#define CKSU_GRANT_ROOT     0x1001
#define CKSU_ADD_UID        0x1002
#define CKSU_REMOVE_UID     0x1003
#define CKSU_GET_LIST       0x1004
#define CKSU_SET_KEY        0x1005

#define CKSU_VERSION        0x0200

int cksu_supercall_init(void);
void cksu_supercall_exit(void);

#endif
