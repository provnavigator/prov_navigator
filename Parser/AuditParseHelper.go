package main

import (
	"encoding/json"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"time"
)

type EventEdge struct {
	TimeStamp time.Time
	SrcNode   interface{}
	DstNode   interface{}
}

type ProcessEventNode struct {
	Pid  string `clf:"pid" clf1:"pid"`
	PPid string `clf:"ppid"`
	Cmd  string `clf:"cmd" clf1:"cmd"`
	Exec string `clf:"exec"`
	Cwd  string `clf:"cwd"`
}

type FileEventNode struct {
	FilePath string `clf:"file_path" clf1:"filename"`
}

type SocketEventNode struct {
	SrcIP   string `clf:"src_ip" clf1:"ip"`
	SrcPort string `clf:"src_port" clf1:"port"`
	DstIP   string `clf:"dst_ip" clf1:"ip"`
	DstPort string `clf:"dst_port" clf1:"port"`
	IP      string `clf:"ip"`
	Port    string `clf:"port"`
}

type SocketType struct {
	Source *aucoalesce.Address `json:"source,omitempty"      yaml:"source,omitempty"`
	Dest   *aucoalesce.Address `json:"destination,omitempty" yaml:"destination,omitempty"`
}

type AuditNodeType int

const (
	PROCESS AuditNodeType = 0
	FILE    AuditNodeType = 1
	SOCKET  AuditNodeType = 2
)

type AuditEdgeType int

const (
	WRITE AuditEdgeType = 0

	READ    AuditEdgeType = 1
	EXECUTE AuditEdgeType = 2

	START AuditEdgeType = 3
	END   AuditEdgeType = 4

	READ_SOCKET AuditEdgeType = 5

	WRITE_SOCKET AuditEdgeType = 6

	OTHERS AuditEdgeType = 10
)

func (a AuditEdgeType) String() string {
	switch a {
	case WRITE:
		return "Write"
	case READ:
		return "Read"
	case EXECUTE:
		return "Execute"
	case START:
		return "Start"
	case END:
		return "End"
	case READ_SOCKET:
		return "ReadSocket"
	case WRITE_SOCKET:
		return "WriteSocket"
	case OTHERS:
		return "Others"
	}
	panic("no such type")
}

var SyscallSrcNodeMap = map[AuditEdgeType]AuditNodeType{
	WRITE:        PROCESS,
	READ:         FILE,
	START:        PROCESS,
	END:          PROCESS,
	READ_SOCKET:  SOCKET,
	WRITE_SOCKET: PROCESS,
}

var SyscallDstNodeMap = map[AuditEdgeType]AuditNodeType{
	WRITE:        FILE,
	READ:         PROCESS,
	START:        PROCESS,
	END:          PROCESS,
	READ_SOCKET:  PROCESS,
	WRITE_SOCKET: SOCKET,
}

var SyscallsMap = map[string]AuditEdgeType{
	"write":      WRITE,
	"open":       WRITE,
	"openat":     WRITE,
	"read":       READ,
	"newfstatat": READ,
	"execve":     EXECUTE,
	"chmod":      EXECUTE,
	"fchmod":     EXECUTE,
	"fchmodat":   EXECUTE,
	"create":     EXECUTE,
	"close":      WRITE,

	"clone":           START,
	"clone3":          START,
	"set_tid_address": START,
	"fork":            START,
	"vfork":           START,
	"kill":            START,
	"exit":            END,
	"exit_group":      END,

	"getpeername": READ_SOCKET,
	"getsockname": READ_SOCKET,
	"rcvmsg":      READ_SOCKET,
	"rcvfrom":     READ_SOCKET,
	"accept":      READ_SOCKET,
	"accept4":     READ_SOCKET,
	"listen":      READ_SOCKET,

	"sendmsg": WRITE_SOCKET,
	"connect": WRITE_SOCKET,
	"sendto":  WRITE_SOCKET,
	"bind":    WRITE_SOCKET,
}

func (s *ChanStream) updateSharedFdTables(pid string, fd string, path string, isAdd bool) bool {
	for i := 0; i < len(s.sharedFdTables); i++ {
		if _, ok := s.sharedFdTables[i][pid]; ok {
			for sharedPid := range s.sharedFdTables[i] {
				if isAdd {
					if _, okk := s.fdMap[sharedPid]; !okk {
						s.fdMap[sharedPid] = map[string]string{}
					}
					s.fdMap[sharedPid][fd] = path
				} else {
					if _, okk := s.fdMap[sharedPid]; okk {
						if _, okkk := s.fdMap[sharedPid][fd]; okkk {
							delete(s.fdMap[sharedPid], fd)
						}
					}
				}
			}
			return true
		}
	}
	return false
}

func (s *ChanStream) GetProcess(e *aucoalesce.Event) (ProcessEventNode, string) {
	if e.Process.PID != "" {
		return ProcessEventNode{
			Pid:  e.Process.PID,
			PPid: e.Process.PPID,
			Cmd:  e.Process.Name,
			Exec: e.Process.Exe,
			Cwd:  e.Process.CWD,
		}, "process#" + e.Process.PID
	} else {
		return ProcessEventNode{
			Pid:  e.Process.PID,
			PPid: e.Process.PPID,
			Cmd:  e.Process.Name,
			Exec: e.Process.Exe,
			Cwd:  e.Process.CWD,
		}, ""
	}
}

func (s *ChanStream) GetFileBasic(e *aucoalesce.Event) (FileEventNode, string) {
	fn := FileEventNode{}
	if e.File != nil && e.File.Path != "" {
		fn.FilePath = e.File.Path
		return fn, "file#" + fn.FilePath
	}
	return fn, ""
}

func (s *ChanStream) GetFile(e *aucoalesce.Event) (FileEventNode, string) {

	syscall := ""
	if _syscall, ok := e.Data["syscall"]; ok {
		syscall = _syscall
	} else {
		return s.GetFileBasic(e)
	}
	pid := e.Process.PID
	if syscall == "write" || syscall == "pwrite" || syscall == "writev" ||
		syscall == "send" || syscall == "sendto" || syscall == "sendmsg" {
		fd := e.Data["a0"]
		if _, ok := s.fdMap[pid]; ok {
			if _, okk := s.fdMap[pid][fd]; !okk {
				return s.GetFileBasic(e)
			}
			fp := s.fdMap[pid][fd]
			fn := FileEventNode{fp}
			return fn, "file#" + fp
		}
	} else if syscall == "read" || syscall == "pread" || syscall == "readv" ||
		syscall == "recv" || syscall == "recvfrom" || syscall == "recvmsg" {
		fd := e.Data["a0"]
		if _, ok := s.fdMap[pid]; ok {
			if _, okk := s.fdMap[pid][fd]; !okk {
				return s.GetFileBasic(e)
			}
			fp := s.fdMap[pid][fd]
			fn := FileEventNode{fp}
			return fn, "file#" + fp
		}
	}
	return s.GetFileBasic(e)
}

func (s *ChanStream) GetSocketBasic(e *aucoalesce.Event) (SocketEventNode, string) {
	node := SocketEventNode{}
	if e.Source != nil && e.Source.IP != "" && e.Source.Port != "" {
		node.IP = e.Source.IP
		node.Port = e.Source.Port
		node.SrcIP = e.Source.IP
		node.SrcPort = e.Source.Port
		return node, "socket#" + node.SrcIP + ":" + node.SrcPort
	}
	if e.Dest != nil && e.Dest.IP != "" && e.Dest.Port != "" {
		node.IP = e.Dest.IP
		node.Port = e.Dest.Port
		node.DstIP = e.Dest.IP
		node.DstPort = e.Dest.Port
		return node, "socket#" + node.DstIP + ":" + node.DstPort
	}
	return node, ""
}

func (s *ChanStream) GetSocket(e *aucoalesce.Event) (SocketEventNode, string) {

	syscall := ""
	if _syscall, ok := e.Data["syscall"]; ok {
		syscall = _syscall
	} else {
		return s.GetSocketBasic(e)
	}
	pid := e.Process.PID
	if syscall == "write" || syscall == "pwrite" || syscall == "writev" ||
		syscall == "send" || syscall == "sendto" || syscall == "sendmsg" ||
		syscall == "read" || syscall == "pread" || syscall == "readv" ||
		syscall == "recv" || syscall == "recvfrom" || syscall == "recvmsg" {
		fd := e.Data["a0"]
		if _, ok := s.fdMap[pid]; ok {
			if _, okk := s.fdMap[pid][fd]; !okk {
				return s.GetSocketBasic(e)
			}
			socketStr := s.fdMap[pid][fd]
			socket := SocketType{}
			err := json.Unmarshal([]byte(socketStr), &socket)
			if err != nil {
				node := SocketEventNode{}
				if socket.Source != nil && socket.Source.IP != "" && socket.Source.Port != "" {
					node.IP = socket.Source.IP
					node.Port = socket.Source.Port
					node.SrcIP = socket.Source.IP
					node.SrcPort = socket.Source.Port
					return node, "socket#" + node.SrcIP + ":" + node.SrcPort
				}
				if socket.Dest != nil && socket.Dest.IP != "" && socket.Dest.Port != "" {
					node.IP = socket.Dest.IP
					node.Port = socket.Dest.Port
					node.DstIP = socket.Dest.IP
					node.DstPort = socket.Dest.Port
					return node, "socket#" + node.DstIP + ":" + node.DstPort
				}
				return node, ""
			}
		}
	} else if syscall == "getpeername" {
		d := e.Data
		node := SocketEventNode{}
		if socket_addr, ok := d["socket_addr"]; ok {
			if socket_port, ok := d["socket_port"]; ok {
				node.SrcIP = socket_addr
				node.SrcPort = socket_port
				node.IP = socket_addr
				node.Port = socket_port
				return node, "socket#" + socket_addr + ":" + socket_port
			}
		}
		return node, ""
	}
	return s.GetSocketBasic(e)
}
