//go:build linux

package procinfo

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func peerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if cred.Pid <= 0 {
		return 0, errors.New("procinfo: kernel reported no peer pid")
	}
	return int(cred.Pid), nil
}

// ProcessFacts reads /proc/<pid>. It is written for production Linux and is
// not exercised by the Darwin test environment except through the loopback
// transport, which uses the same interface.
func ProcessFacts(pid int) (*Facts, error) {
	base := "/proc/" + strconv.Itoa(pid)
	exe, err := os.Readlink(base + "/exe")
	if err != nil {
		return nil, fmt.Errorf("procinfo: read exe: %w", err)
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	st, err := os.Stat(base)
	if err != nil {
		return nil, err
	}
	startTicks, ppid, err := procStat(base + "/stat")
	if err != nil {
		return nil, err
	}
	boot, err := bootTime()
	if err != nil {
		return nil, err
	}
	var stSys syscall.Stat_t
	if v, ok := st.Sys().(*syscall.Stat_t); ok {
		stSys = *v
	}
	f := &Facts{
		PID:       pid,
		StartTime: boot.Add(time.Duration(startTicks/uint64(ticksPerSec())) * time.Second),
		UID:       stSys.Uid,
		Exe:       exe,
		PPID:      ppid,
	}
	if sha, _, _, err := HashFile(exe); err == nil {
		f.BinarySHA = sha
	} else if sha, err := HashFileCached(exe); err == nil {
		f.BinarySHA = sha
	} else {
		return nil, err
	}
	f.BinarySize, f.BinaryMod = st.Size(), st.ModTime()
	return f, nil
}

func procStat(path string) (startTicks uint64, ppid int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	// comm may contain spaces; fields resume after the last ')'.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 > len(b) {
		return 0, 0, errors.New("procinfo: bad stat")
	}
	fields := strings.Fields(string(b[i+2:]))
	if len(fields) < 20 {
		return 0, 0, errors.New("procinfo: short stat")
	}
	ppid, _ = strconv.Atoi(fields[1])
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return ticks, ppid, err
}

func bootTime() (time.Time, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "btime ") {
			sec, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
			return time.Unix(sec, 0), err
		}
	}
	return time.Time{}, errors.New("procinfo: no btime")
}

func ticksPerSec() int { return 100 }

// ProcName is kept for parity with the Darwin implementation.
func ProcName(pid int) (string, error) { return "", nil }
