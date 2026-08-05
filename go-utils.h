// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright 2026 The Inspektor Gadget authors

#ifndef __GO_UTILS_H__
#define __GO_UTILS_H__

#if defined(__TARGET_ARCH_x86)

#define GO_PARAM2(x) ((void *)(x)->bx)
#define GO_PARAM4(x) ((void *)(x)->di)
#define GO_PARAM5(x) ((void *)(x)->si)
#define GO_PARAM6(x) ((void *)(x)->r8)
#define GO_PARAM7(x) ((void *)(x)->r9)
#define GO_PARAM9(x) ((void *)(x)->r11)
#define GOROUTINE_PTR(x) ((void *)(x)->r14)

#elif defined(__TARGET_ARCH_arm64)

struct pt_regs;
#define PT_REGS_ARM64 const volatile struct user_pt_regs

#define GO_PARAM2(x) ((void *)((PT_REGS_ARM64 *)(x))->regs[1])
#define GO_PARAM4(x) ((void *)((PT_REGS_ARM64 *)(x))->regs[3])
#define GO_PARAM5(x) ((void *)((PT_REGS_ARM64 *)(x))->regs[4])
#define GO_PARAM6(x) ((void *)((PT_REGS_ARM64 *)(x))->regs[5])
#define GO_PARAM7(x) ((void *)((PT_REGS_ARM64 *)(x))->regs[6])
#define GO_PARAM9(x) ((void *)((PT_REGS_ARM64 *)(x))->regs[8])
#define GOROUTINE_PTR(x) ((void *)((PT_REGS_ARM64 *)(x))->regs[28])

#else
#error Undefined architecture
#endif

#endif /* __GO_UTILS_H__ */
