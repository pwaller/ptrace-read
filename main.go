package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

var _ = time.Second

func read_ptrace_events(cmd *exec.Cmd) chan *syscall.PtraceRegs {

	child := cmd.Process.Pid
	err := syscall.PtraceSetOptions(child, syscall.PTRACE_O_TRACESYSGOOD)
	if err != nil {
		panic(err)
	}

	var regs syscall.PtraceRegs

	ev := make(chan *syscall.PtraceRegs)
	go func() {
		for {
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
				break
			}
			if !waitstatus.Stopped() {
				panic("Not handled: process isn't sigstopped!")
			}
			sig := waitstatus.StopSignal()
			if sig&0x80 == 0 {
				// Not something we're build to handle
				// High bit should be set for syscalls because of PTRACE_O_SYSGOOD
				continue
			}
			err = syscall.PtraceGetRegs(child, &regs)
			if err != nil {
				panic(err)
			}
			ev <- &regs
			<-ev
		}
		ev <- nil
	}()
	return ev
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
			for i := 0; i < fsize && fpos+i < N; i++ {
				pieces[fpos+i] = '#'
			}
		}
	}
	log.Printf("%50s [%s]", f.path, string(pieces))
}

func main() {

	flag.Parse()
	args := flag.Args()
	log.Printf("Starting program %v", args)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	cmd.Stdout = os.Stdout
	err := cmd.Start()
	if err != nil {
		panic(err)
	}

	event := read_ptrace_events(cmd)

	var buf [1024]byte

	var filemap = map[uintptr]*File{}

	for {
		regs := <-event
		if regs == nil {
			break
		}
		call := regs.Orig_rax
		callname := strings.ToLower(syscall_name(call)[4:])
		_ = callname

		var args = [6]uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.Rcx, regs.R8, regs.R9}
		event <- nil

		// Return of syscall
		regs = <-event
		if regs == nil {
			break
		}
		retval := int64(regs.Rax)

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
				//log.Printf("open(path=%v, flags=0x%x, mode=0x%x) -> fd=%v e=%v", path, args[1], args[2], retval, errno)
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
			//log.Printf("read(fd=%v, buf=0x%x, bufsize=%v) -> ret=%v", args[0], args[1], args[2], retval)

			if retval < 0 {
				interesting = false
				break sw
			}

			fd := uintptr(args[0])
			//log.Printf("fd = %v", fd)
			if _, ok := filemap[fd]; !ok {
				log.Panic("fd not in file map: ", fd)
			}
			f := filemap[fd]

			// Only count every 10th read
			f.N += 1
			if f.N%10 != 1 {
				break sw
			}

			rfp := &f.read_file_pieces
			pos := f.pos
			//log.Printf("  current pos: %v, size = %v", pos, retval)
			if size, present := (*rfp)[pos]; present {
				if retval > size {
					// this read is at the same place but larger, so it over-rides
					// the existing read
					(*rfp)[pos] = retval
				}
			} else {
				(*rfp)[pos] = retval
			}

			// Only keep the last 100 reads
			f.decay = append(f.decay, pos)
			if len(f.decay) > 100 {
				if _, ok := (*rfp)[f.decay[0]]; ok {
					delete(*rfp, f.decay[0])
				}
				f.decay = f.decay[1:]
			}

			f.pos += retval
			//log.Printf("  new pos: %v, size = %v", filemap[fd].pos, retval)

			f.Show()

		case syscall.SYS_READV:
			log.Printf("readv(fd=%v, buf=0x%x, bufsize=%v) -> ret=%v", args[0], args[1], args[2], retval)

			fd := uintptr(args[0])
			filemap[fd].pos += retval

		case syscall.SYS_PREAD64:
			log.Printf("pread64(fd=%v, buf=0x%x, bufsize=%v) -> ret=%v", args[0], args[1], args[2], retval)

			fd := uintptr(args[0])
			filemap[fd].pos += retval

		case syscall.SYS_LSEEK:
			//log.Printf("lseek(fd=%v, offset=%v, whence=%v) -> ret=%v", args[0], args[1], args[2], retval)

			fd := uintptr(args[0])
			offset := int64(args[1])
			whence := int(args[2])
			switch whence {
			case os.SEEK_SET:
				filemap[fd].pos = offset
			case os.SEEK_CUR:
				filemap[fd].pos += offset
			case os.SEEK_END:
				//
				panic("Not implemented")
			}

		case syscall.SYS_CLOSE:
			//log.Printf("close(fd=%x) = %v", args[0], retval)
			fd := uintptr(args[0])
			if retval >= 0 {
				_ = fd
				//delete(filemap, fd)
			}

		default:
			interesting = false
		}

		if interesting {
			//time.Sleep(250*time.Millisecond)
			//time.Sleep(10*time.Millisecond)
		}

		event <- nil
	}

	err = cmd.Wait()
}
