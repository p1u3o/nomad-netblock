//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// netpush peer exemption.
//
// netpush needs the Consul API like the watch task, but every Docker task has a private
// cgroup namespace, so watch cannot name the netpush cgroup by path. netpush therefore opens
// its own cgroup root (/sys/fs/cgroup inside its container = its task cgroup) and passes the
// directory fd over a unix socket in the shared alloc dir (SCM_RIGHTS). Watch checks the peer
// (SO_PEERCRED uid, cgroup2 fs, not its own cgroup, memory.max) and renders
// `socket cgroupv2 level <watch level> "/sys/fs/cgroup/../../../proc/self/fd/3"` with the fd as
// nft's fd 3; nft stores the inode (cgroup id). Both tasks are siblings under the alloc, so the
// level that matches watch matches netpush too.
//
// The app task (root in the same alloc) can connect too, but it can only hand over its own
// cgroup (it cannot open another task's), which fails the memory.max check when the netpush
// task gets a distinct memory size, and the uid check unless it switches to netpush's uid.

const cgroup2Magic = 0x63677270

// rootCgroupID is the id of a cgroup namespace root that is the real root (never a task).
var rootCgroupID uint64 = 1

var (
	peerMu   sync.Mutex
	peerFile *os.File
)

func currentPeerFile() *os.File {
	peerMu.Lock()
	defer peerMu.Unlock()
	return peerFile
}

// setPeerFile installs f for nft and returns the previous file (caller closes it after the
// next successful apply).
func setPeerFile(f *os.File) *os.File {
	peerMu.Lock()
	defer peerMu.Unlock()
	old := peerFile
	peerFile = f
	return old
}

type peerReg struct {
	f   *os.File
	id  uint64
	uid int
}

func cgroupID(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// odRequest is netpush asking watch to add a service to the allow sets (on-demand mode).
// reply gets nil once the service's targets are in the sets.
type odRequest struct {
	kind, name string // kind consul or nomad; name as in allow_services / allow_nomad_services
	reply      chan error
}

// servePeer accepts netpush registrations until ctx ends. reqs (nil = on-demand off) carries
// requests from registered peers.
func servePeer(ctx context.Context, c Config, ownID uint64, out chan<- peerReg, reqs chan<- odRequest) {
	_ = os.Remove(c.NetpushSocket)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: c.NetpushSocket, Net: "unix"})
	if err != nil {
		logf("watch: NETPUSH EXEMPT DISABLED: listen %s: %v", c.NetpushSocket, err)
		return
	}
	_ = os.Chmod(c.NetpushSocket, 0o666) // netpush runs as another uid; identity is checked per connection
	go func() { <-ctx.Done(); l.Close() }()
	logf("watch: netpush exemption: listening on %s", c.NetpushSocket)
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("watch: netpush socket: %v", err)
			sleepCtx(ctx, time.Second)
			continue
		}
		go handlePeer(ctx, c, ownID, conn, out, reqs)
	}
}

func handlePeer(ctx context.Context, c Config, ownID uint64, conn *net.UnixConn, out chan<- peerReg, reqs chan<- odRequest) {
	defer conn.Close()
	reply := func(s string) {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte(s + "\n"))
	}
	f, uid, err := recvPeer(conn)
	if err == nil {
		err = checkPeer(c, ownID, f, uid)
	}
	if err != nil {
		if f != nil {
			f.Close()
		}
		logf("watch: netpush registration REJECTED (uid %d): %v", uid, err)
		reply("err " + err.Error())
		return
	}
	id, _ := fdIno(f)
	select {
	case out <- peerReg{f: f, id: id, uid: uid}:
	case <-ctx.Done():
		f.Close()
		return
	}
	reply(fmt.Sprintf("ok %d", id))
	_ = conn.SetDeadline(time.Time{})
	// Held open while netpush runs. Only this verified connection may send requests.
	servePeerRequests(ctx, c, conn, reqs)
}

// servePeerRequests answers one line per request:
//
//	udp-tproxy               -> "fd" + an IP_TRANSPARENT UDP socket on 127.0.0.1:ondemand_port
//	allow consul|nomad NAME  -> "ok" once NAME's targets are in the allow sets, or "err ..."
func servePeerRequests(ctx context.Context, c Config, conn *net.UnixConn, reqs chan<- odRequest) {
	br := bufio.NewReader(conn)
	reply := func(s string) {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte(s + "\n"))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 1 && f[0] == "udp-tproxy":
			if !c.OnDemandPool.IsValid() {
				reply("err ondemand_pool is not set in netblock.conf")
				continue
			}
			sock, err := tproxyUDPSocket(c.OnDemandPort)
			if err != nil {
				logf("watch: on-demand UDP listener: %v", err)
				reply("err " + err.Error())
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _, err = conn.WriteMsgUnix([]byte("fd\n"), syscall.UnixRights(int(sock.Fd())), nil)
			sock.Close()
			if err != nil {
				return
			}
		case len(f) == 3 && f[0] == "allow":
			if reqs == nil {
				reply("err ondemand_pool is not set in netblock.conf")
				continue
			}
			r := odRequest{kind: f[1], name: f[2], reply: make(chan error, 1)}
			select {
			case reqs <- r:
			case <-ctx.Done():
				return
			}
			select {
			case err := <-r.reply:
				if err != nil {
					reply("err " + err.Error())
				} else {
					reply("ok")
				}
			case <-time.After(30 * time.Second):
				reply("err timeout waiting for the allow sets")
			case <-ctx.Done():
				return
			}
		default:
			reply("err unknown request")
		}
	}
}

// tproxyUDPSocket opens the on-demand UDP listener for netpush. IP_TRANSPARENT needs
// CAP_NET_ADMIN, which watch has and netpush does not.
func tproxyUDPSocket(port uint16) (*os.File, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, o := range [][2]int{{syscall.SOL_SOCKET, syscall.SO_REUSEADDR}, {syscall.SOL_IP, syscall.IP_TRANSPARENT}, {syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR}} {
		if err := syscall.SetsockoptInt(fd, o[0], o[1], 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("setsockopt %d/%d: %v", o[0], o[1], err)
		}
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: int(port), Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind 127.0.0.1:%d: %v", port, err)
	}
	return os.NewFile(uintptr(fd), "ondemand-udp"), nil
}

func recvPeer(conn *net.UnixConn) (*os.File, int, error) {
	uid := -1
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, uid, err
	}
	var cred *syscall.Ucred
	var cerr error
	_ = raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cerr != nil {
		return nil, uid, cerr
	}
	uid = int(cred.Uid)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf, oob := make([]byte, 64), make([]byte, syscall.CmsgSpace(4*4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, uid, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, uid, err
	}
	var fds []int
	for _, m := range msgs {
		if r, err := syscall.ParseUnixRights(&m); err == nil {
			fds = append(fds, r...)
		}
	}
	if len(fds) != 1 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, uid, fmt.Errorf("want exactly 1 fd, got %d", len(fds))
	}
	f := os.NewFile(uintptr(fds[0]), "netpush-cgroup")
	if strings.TrimSpace(string(buf[:n])) != "netpush" {
		return f, uid, errors.New("bad hello")
	}
	return f, uid, nil
}

func fdIno(f *os.File) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func checkPeer(c Config, ownID uint64, f *os.File, uid int) error {
	if c.NetpushUID > 0 && uid != c.NetpushUID {
		return fmt.Errorf("peer uid %d, want %d", uid, c.NetpushUID)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("fd is not a directory")
	}
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &fs); err != nil {
		return err
	}
	if fs.Type != cgroup2Magic {
		return fmt.Errorf("fd is not on cgroup2 (fs type %#x)", fs.Type)
	}
	if st.Ino == ownID || st.Ino == rootCgroupID {
		return fmt.Errorf("fd is the watch cgroup or the root cgroup (id %d)", st.Ino)
	}
	if c.NetpushMemoryMax > 0 {
		b, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/memory.max", f.Fd()))
		if err != nil {
			return fmt.Errorf("memory.max: %v", err)
		}
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err != nil || v != c.NetpushMemoryMax {
			return fmt.Errorf("memory.max %q, want %d", strings.TrimSpace(string(b)), c.NetpushMemoryMax)
		}
	}
	return nil
}

// registerWithNetblock is the netpush side: hand our cgroup fd to netblock watch, keep the
// connection, and register again whenever it drops (watch restarted).
func registerWithNetblock(ctx context.Context, sock string) {
	registerWithNetblockLink(ctx, sock, nil)
}

// registerWithNetblockLink also makes the connection available for requests through link.
func registerWithNetblockLink(ctx context.Context, sock string, link *netblockLink) {
	var rl retryLog
	for ctx.Err() == nil {
		err := registerOnceLink(ctx, sock, link)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errPeerClosed) {
			// Was registered; watch went away. Log it and start a fresh window so the
			// first dial error after this is shown too.
			logf("netblock exemption: %v (retrying)", err)
			rl = retryLog{}
		} else if err != nil {
			if msg, ok := rl.next(time.Now(), err); ok {
				logf("%s", msg)
			}
		}
		sleepCtx(ctx, 2*time.Second)
	}
}

// retryLog lets the first retry error through, then at most one line per minute with the
// number of attempts suppressed in between (watch can be down for a while; we retry every 2s).
type retryLog struct {
	last       time.Time
	suppressed int
}

func (r *retryLog) next(now time.Time, err error) (string, bool) {
	if !r.last.IsZero() && now.Sub(r.last) < time.Minute {
		r.suppressed++
		return "", false
	}
	msg := fmt.Sprintf("netblock exemption: %v (retrying every 2s)", err)
	if r.suppressed > 0 {
		msg += fmt.Sprintf(" [%d failed attempts not logged]", r.suppressed)
	}
	r.last, r.suppressed = now, 0
	return msg, true
}

var errPeerClosed = errors.New("netblock watch closed the registration connection")

func registerOnce(ctx context.Context, sock string) error { return registerOnceLink(ctx, sock, nil) }

// peerMsg is one line from watch, with the fd that came with it ("fd" lines).
type peerMsg struct {
	line string
	f    *os.File
}

// readPeer delivers watch's lines (and passed fds) until the connection ends.
func readPeer(conn *net.UnixConn, out chan<- peerMsg) {
	defer close(out)
	buf, oob := make([]byte, 512), make([]byte, syscall.CmsgSpace(4*4))
	var pending []byte
	var fds []*os.File
	defer func() {
		for _, f := range fds {
			f.Close()
		}
	}()
	for {
		n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
		n, oobn = max(n, 0), max(oobn, 0)
		if oobn > 0 {
			if msgs, perr := syscall.ParseSocketControlMessage(oob[:oobn]); perr == nil {
				for _, m := range msgs {
					if r, err := syscall.ParseUnixRights(&m); err == nil {
						for _, fd := range r {
							syscall.CloseOnExec(fd)
							fds = append(fds, os.NewFile(uintptr(fd), "netblock-fd"))
						}
					}
				}
			}
		}
		pending = append(pending, buf[:n]...)
		for {
			i := bytes.IndexByte(pending, '\n')
			if i < 0 {
				break
			}
			m := peerMsg{line: strings.TrimSpace(string(pending[:i]))}
			pending = pending[i+1:]
			if m.line == "fd" && len(fds) > 0 {
				m.f, fds = fds[0], fds[1:]
			}
			out <- m
		}
		if err != nil || n == 0 {
			return
		}
	}
}

func registerOnceLink(ctx context.Context, sock string, link *netblockLink) error {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return err
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	dir, err := os.Open(cgroupRoot)
	if err != nil {
		return err
	}
	defer dir.Close()
	if _, _, err := conn.WriteMsgUnix([]byte("netpush\n"), syscall.UnixRights(int(dir.Fd())), nil); err != nil {
		return err
	}
	msgs := make(chan peerMsg, 4)
	go readPeer(conn, msgs)
	var line string
	select {
	case m, ok := <-msgs:
		if !ok {
			return errors.New("no answer from netblock watch: connection closed")
		}
		line = m.line
	case <-time.After(15 * time.Second):
		return errors.New("no answer from netblock watch: timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
	if !strings.HasPrefix(line, "ok ") {
		return fmt.Errorf("netblock watch rejected the registration: %s", line)
	}
	logf("netblock exemption: registered, cgroup id %s", strings.TrimPrefix(line, "ok "))
	if link == nil {
		for range msgs {
		}
		return errPeerClosed
	}
	sess := &peerSession{conn: conn, msgs: msgs, done: make(chan struct{})}
	link.attach(sess)
	<-sess.done // readPeer closed msgs (watch went away) or ctx ended
	link.detach(sess)
	return errPeerClosed
}

// netblockLink is netpush's request channel to watch over the registration connection.
// Requests are serialised; each gets one reply line.
type netblockLink struct {
	reqMu      sync.Mutex
	mu         sync.Mutex
	sess       *peerSession
	changed    chan struct{} // closed and replaced on attach
	onRegister func()        // run (in a goroutine) after every registration
}

type peerSession struct {
	conn *net.UnixConn
	msgs chan peerMsg
	done chan struct{}
	once sync.Once
}

func (s *peerSession) end() { s.once.Do(func() { close(s.done) }) }

func newNetblockLink() *netblockLink { return &netblockLink{changed: make(chan struct{})} }

func (l *netblockLink) attach(s *peerSession) {
	l.mu.Lock()
	l.sess = s
	close(l.changed)
	l.changed = make(chan struct{})
	cb := l.onRegister
	l.mu.Unlock()
	go l.monitor(s)
	if cb != nil {
		go cb()
	}
}

// monitor notices the connection closing while no request is running.
func (l *netblockLink) monitor(s *peerSession) {
	for {
		l.reqMu.Lock()
		select {
		case m, ok := <-s.msgs:
			l.reqMu.Unlock()
			if !ok {
				s.end()
				return
			}
			if m.f != nil {
				m.f.Close()
			}
			logf("netblock: unexpected message from watch: %q", m.line)
			continue
		default:
		}
		l.reqMu.Unlock()
		select {
		case <-s.done:
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (l *netblockLink) detach(s *peerSession) {
	l.mu.Lock()
	if l.sess == s {
		l.sess = nil
	}
	l.mu.Unlock()
}

// request sends one line and waits for the reply, waiting for a registration first.
func (l *netblockLink) request(ctx context.Context, line string) (string, *os.File, error) {
	for {
		l.mu.Lock()
		s, ch := l.sess, l.changed
		l.mu.Unlock()
		if s != nil {
			break
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return "", nil, fmt.Errorf("not registered with netblock watch: %v", ctx.Err())
		}
	}
	l.reqMu.Lock()
	defer l.reqMu.Unlock()
	l.mu.Lock()
	s := l.sess
	l.mu.Unlock()
	if s == nil {
		return "", nil, errors.New("netblock watch connection lost")
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.conn.Write([]byte(line + "\n")); err != nil {
		s.end()
		return "", nil, err
	}
	select {
	case m, ok := <-s.msgs:
		if !ok {
			s.end()
			return "", nil, errors.New("netblock watch connection lost")
		}
		if strings.HasPrefix(m.line, "err ") {
			if m.f != nil {
				m.f.Close()
			}
			return "", nil, errors.New(strings.TrimPrefix(m.line, "err "))
		}
		return m.line, m.f, nil
	case <-ctx.Done():
		// The reply may still come; drop the session so replies cannot get out of step.
		s.conn.Close()
		return "", nil, ctx.Err()
	}
}
