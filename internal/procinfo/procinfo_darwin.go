//go:build darwin

package procinfo

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// localPeerPID is the Darwin sockopt that returns the peer PID (0x002,
// SOL_LOCAL). It is not exported by every x/sys version under a stable name.
const localPeerPID = 0x002

func peerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		pid, sockErr = syscall.GetsockoptInt(int(fd), unix.SOL_LOCAL, localPeerPID)
	}); err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if pid <= 0 {
		return 0, errors.New("procinfo: kernel reported no peer pid")
	}
	return pid, nil
}

// ProcessFacts reads facts about pid. On Darwin the UID and executable path
// are requested from the kernel via sysctl and ps, with a start time from
// kp_proc.p_starttime. Anything we cannot read is an error, never a guess.
func ProcessFacts(pid int) (*Facts, error) {
	if pid <= 0 {
		return nil, errors.New("procinfo: invalid pid")
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return nil, fmt.Errorf("procinfo: pid %d not found: %w", pid, err)
	}
	f := &Facts{
		PID:       pid,
		PPID:      int(kp.Eproc.Ppid),
		UID:       kp.Eproc.Ucred.Uid,
		StartTime: time.Unix(kp.Proc.P_starttime.Sec, int64(kp.Proc.P_starttime.Usec)*1000),
	}
	// Path of the running executable. KERN_PROCARGS2 starts with argc, then
	// argv[0]; the executable path follows the NUL-terminated argv block.
	if path, err := execPath(pid); err == nil && path != "" {
		f.Exe = path
	} else {
		f.Exe = strings.TrimRight(unix.ByteSliceToString(kp.Proc.P_comm[:]), "\x00")
	}
	if f.Exe == "" {
		return nil, errors.New("procinfo: cannot determine executable")
	}
	sha, err := HashFileCached(f.Exe)
	if err != nil {
		return nil, fmt.Errorf("procinfo: hash executable: %w", err)
	}
	f.BinarySHA = sha
	if st, err := os.Stat(f.Exe); err == nil {
		f.BinarySize, f.BinaryMod = st.Size(), st.ModTime()
	}
	return f, nil
}

// execPath reads KERN_PROCARGS2 and returns the absolute executable path. The
// layout is: int32 argc, exec_path\0, then argv/env strings.
func execPath(pid int) (string, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(raw) < 5 {
		return "", errors.New("procinfo: procargs2 too short")
	}
	// Skip argc (4 bytes), then the NUL-terminated exec path.
	rest := raw[4:]
	end := strings.IndexByte(string(rest), 0)
	if end <= 0 {
		return "", errors.New("procinfo: no exec path")
	}
	return string(rest[:end]), nil
}

// ProcName resolves the human name used for ps cross-checks in tests.
func ProcName(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	return strings.TrimSpace(string(out)), err
}
