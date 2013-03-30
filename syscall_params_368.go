package main

import (
	"syscall"
)

func syscall_params(regs *syscall.PtraceRegs) (uint64, [6]uint64) {
	return uint64(regs.Orig_eax), [6]uint64{
		uint64(regs.Ebx), uint64(regs.Ecx), uint64(regs.Edx), uint64(regs.Esi), uint64(regs.Edi), uint64(regs.Ebp)}
}

func syscall_retval(regs *syscall.PtraceRegs) int64 {
	return int64(regs.Eax)
}
