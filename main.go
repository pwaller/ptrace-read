package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var _ = time.Second

var verbose = flag.Bool("verbose", false, "show system calls")
var delay = flag.Duration("delay", 0, "slow down execution by given duration per interesting syscall")

func read_ptrace_events(args []string) (*exec.Cmd, func() *syscall.PtraceRegs) {

	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		panic(err)
	}

	_, err = cmd.Process.Wait()
	if err != nil {
		panic(err)
	}

	child := cmd.Process.Pid

	err = syscall.PtraceSetOptions(child, syscall.PTRACE_O_TRACESYSGOOD)
	if err != nil {
		panic(err)
	}

	var regs syscall.PtraceRegs

	return cmd, func() *syscall.PtraceRegs {

		err = syscall.PtraceSyscall(child, 0)
		if err != nil {
			panic(err)
		}
		state, err := cmd.Process.Wait()
		if err != nil {
			panic(err)
		}
		waitstatus, ok := state.Sys().(syscall.WaitStatus)
		if !ok {
			panic(err)
		}
		if waitstatus.Exited() {
			// Process quit
			return nil
		}
		if !waitstatus.Stopped() {
			panic("Not handled: process isn't sigstopped!")
		}
		sig := waitstatus.StopSignal()
		if sig&0x80 == 0 {
			// Not something we're build to handle
			// High bit should be set for syscalls because of PTRACE_O_SYSGOOD
			return nil
		}
		err = syscall.PtraceGetRegs(child, &regs)
		if err != nil {
			panic(err)
		}
		return &regs
	}
}

type File struct {
	path             string
	fd               uintptr
	pos              int64
	fileinfo         os.FileInfo
	read_file_pieces map[int64]int64
	decay            []int64
	N                int
}

func (f *File) Show() {
	N := 80
	var pieces = bytes.Repeat([]byte(" "), N)
	if f.fileinfo.Size() == 0 {
		pieces = bytes.Repeat([]byte("#"), N)
	} else {
		for pos, size := range f.read_file_pieces {
			fpos := int(float64(N) * float64(pos) / float64(f.fileinfo.Size()))
			fsize := int(float64(N) * float64(size) / float64(f.fileinfo.Size()))
			if fsize < 1 {
				fsize = 1
			}
			for i := 0; i <= fsize && fpos+i < N; i++ {
				pieces[fpos+i] = '#'
			}
		}
	}
	log.Printf("%30s [%s]", f.path, string(pieces))
}

func main() {
	runtime.LockOSThread()

	flag.Parse()
	args := flag.Args()

	if *verbose {
		log.Printf("Starting program %v", args)
	}

	cmd, wait_syscall := read_ptrace_events(args)

	var buf [1024]byte

	var filemap = map[uintptr]*File{}

	for {
		regs := wait_syscall()
		if regs == nil {
			break
		}
		call, args := syscall_params(regs)
		callname := strings.ToLower(syscall_name(call)[4:])
		//log.Printf("call %d", call)
		_ = callname

		// Return of syscall
		regs = wait_syscall()
		if regs == nil {
			break
		}
		retval := syscall_retval(regs)

		interesting := true

	sw:
		switch call {
		case syscall.SYS_OPEN:
			count, err := syscall.PtracePeekData(cmd.Process.Pid, uintptr(args[0]), buf[:])
			if err != nil {
				panic(err)
			}
			i := bytes.IndexByte(buf[:count], 0)
			path := string(buf[:i])

			errno := syscall.Errno(-retval)
			if retval < 0 {
				errno = 0
				args[1] = 99999
			}

			// For the moment hide failed opens
			if retval >= 0 {
				_ = errno
				if *verbose {
					log.Printf("open(path=%v, flags=0x%x, mode=0x%x) -> fd=%v e=%v",
						path, args[1], args[2], retval, errno)
				}
			} else {
				interesting = false
			}

			if retval >= 0 {
				fd := uintptr(retval)
				fileinfo, err := os.Stat(path)
				if err != nil {
					panic(err)
				}
				filemap[fd] = &File{path, fd, 0, fileinfo, make(map[int64]int64), []int64{}, 0}
			}

		case syscall.SYS_READ:
			if *verbose {
				log.Printf("read(fd=%v, buf=0x%x, bufsize=%v) -> ret=%v",
					args[0], args[1], args[2], retval)
			}

			if retval < 0 {
				interesting = false
				break sw
			}

			fd := uintptr(args[0])
			if _, ok := filemap[fd]; !ok {
				// stdin?
				break sw
				//log.Panic("fd not in file map: ", fd)
			}
			f := filemap[fd]

			rfp := &f.read_file_pieces
			pos := f.pos
			if size, present := (*rfp)[pos]; present {
				if retval > size {
					// this read is at the same place but larger, so it over-rides
					// the existing read
					(*rfp)[pos] = retval
				}
			} else {
				(*rfp)[pos] = retval
			}

			// Only keep the last N reads
			f.decay = append(f.decay, pos)
			if len(f.decay) > 1 {
				if _, ok := (*rfp)[f.decay[0]]; ok {
					delete(*rfp, f.decay[0])
				}
				f.decay = f.decay[1:]
			}

			f.pos += retval

			f.Show()

		case syscall.SYS_READV:
			if *verbose {
				log.Printf("readv(fd=%v, buf=0x%x, bufsize=%v) -> ret=%v",
					args[0], args[1], args[2], retval)
			}

			fd := uintptr(args[0])
			filemap[fd].pos += retval

		case syscall.SYS_PREAD64:
			log.Printf("pread64(fd=%v, buf=0x%x, bufsize=%v, offset=%v) -> ret=%v",
				args[0], args[1], args[2], args[3], retval)

			fd := uintptr(args[0])
			filemap[fd].pos += retval

		case syscall.SYS_LSEEK:
			if *verbose {
				log.Printf("lseek(fd=%v, offset=%v, whence=%v) -> ret=%v",
					args[0], args[1], args[2], retval)
			}

			fd := uintptr(args[0])
			offset := int64(args[1])
			whence := int(args[2])
			switch whence {
			case os.SEEK_SET:
				filemap[fd].pos = offset
			case os.SEEK_CUR:
				if _, ok := filemap[fd]; !ok {
					log.Printf("knoown FD: %d", fd)
					break
				}
				filemap[fd].pos += offset
			case os.SEEK_END:
				//
				panic("Not implemented")
			}

		case syscall.SYS_CLOSE:
			if *verbose {
				log.Printf("close(fd=%x) = %v", args[0], retval)
			}
			fd := uintptr(args[0])
			if retval >= 0 && fd > 2 {
				delete(filemap, fd)
			}

		default:
			interesting = false
		}

		if interesting {
			time.Sleep(*delay)
		}

	}

}
