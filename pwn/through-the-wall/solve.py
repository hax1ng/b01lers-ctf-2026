#!/usr/bin/env python3
"""
throughthewall exploit
Kernel UAF + OOB write -> pipe_buffer ops hijack -> pt_regs ROP -> commit_creds
"""
import pexpect
import sys
import time
import os
import struct

os.chdir('/home/kali/CTF/b01lers CTF 2026/pwn/throughthewall')

# Kernel addresses (KASLR = 0, confirmed empirically)
COMMIT_CREDS        = 0xffffffff81097b80
PREPARE_KERNEL_CRED = 0xffffffff81097e30
INIT_CRED           = 0xffffffff82850e80
MODPROBE_PATH       = 0xffffffff828518c0
SWAPGS_RESTORE      = 0xffffffff81e00f89  # swapgs_restore_regs_and_return_to_usermode
# Need to find actual swapgs restore function
POP_RDI_RET         = None  # find below
IRETQ               = None

# Gadgets for ROP:
# 1. add rsp, 0xd8 ; jmp ret  (pivot to pt_regs)
# We'll try 0xd8 first (calculated), adjust if needed
# No exact 0xd8, so chain: add rsp, 0xb8 -> but that pops from kernel stack...
# Actually: chain add rsp, 0xc8 and see what pt_regs[8] = r14 has

# Strategy: 
# ops->release -> "add rsp, 0xd8; ret" BUT 0xd8 doesn't exist
# Try: set ops->release = add_rsp_c8_gadget = 0xffffffff8116cf97
# r15 = ? (this will be popped as rip after add rsp, 0xc8)
# Actually at add rsp, 0xc8 from our depth 0xd8: rsp ends up 0x10 bytes BELOW pt_regs
# So "ret" pops from (pt_regs - 0x10) which is 0x10 bytes before r15
# That means it pops return_addr_to_free_pipe_info+something... not good.

# Let me use a DIFFERENT strategy.
# The pt_regs trick: instead of making all ROP in pt_regs,
# use a combined approach:
# - ops->release = "add rsp, 0xc8; ret"  (0xc8 bytes too shallow)
# - Set "ret" address to another gadget (in kernel stack): BUT we can't control that!
# OR:
# - ops->release = "add rsp, 0xe8; ret"  (0xe8 bytes too deep, overshoots pt_regs by 16)
#   rsp = pt_regs_start - 0x10, "ret" pops from before our pt_regs = crash
# OR:
# Use the "push rsi; pop rsp" pivot which puts rsp = FA (pipe_buffer*)
# then jmps to ACPI code... which we can't control.

# NEW APPROACH: Use __x86_return_thunk variants or look for different gadgets
# 
# Actually: Let me look for "add rsp, 0xd0; pop rbx; ret" or similar
# that adds 0xd8 total (0xd0 + pop = +0x08 = 0xd8)
# Let me search for this in the exploit below

print("[*] Exploit script placeholder - need to find exact pivot offset")
print("[*] Will build diagnostic first")
