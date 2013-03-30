package main

import (
	"syscall"
)

func syscall_params(regs *syscall.PtraceRegs) (uint64, [6]uint64) {
	return uint64(regs.Orig_eax), [6]uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.Rcx, regs.R8, regs.R9}
}

func syscall_retval(regs *syscall.PtraceRegs) int64 {
	return int64(regs.Eax)
}
