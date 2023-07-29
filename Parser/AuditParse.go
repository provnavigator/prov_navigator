package main

import (
	"HHPG/CLF"
	"encoding/json"
	"fmt"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"log"
	"strings"
	"time"
)

var format = "json"

type AuditParser struct {
	pusher      *Pusher
	reassembler *libaudit.Reassembler
	fdMap       map[int]map[int]string
}

func NewAuditParser(pusher *Pusher, isRWParsed bool) *AuditParser {
	stream := &ChanStream{pusher: pusher, logType: "auditd",
		fdMap:          map[string]map[string]string{},
		sharedFdTables: []map[string]bool{},
		isRWParsed:     isRWParsed,
	}
	reassmbler, err := libaudit.NewReassembler(5, 2*time.Second, stream)
	if err != nil {
		log.Fatal(err)
	}
	return &AuditParser{
		pusher:      pusher,
		reassembler: reassmbler,
	}
}

func (a *AuditParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	panic("not implemented")
}

func (a *AuditParser) ParsePushLine(rawLine string) error {
	msg, err := auparse.ParseLogLine(rawLine)
	if err != nil {
		log.Fatal("Log parsed fail with error '%v'", err)
		return err
	}
	a.reassembler.PushMessage(msg)
	return nil
}

func (a *AuditParser) toParsedLog() {

}

func (a *AuditParser) LogType() string {
	return "auditd"
}

type ChanStream struct {
	pusher         *Pusher
	isRWParsed     bool
	logType        string
	fdMap          map[string]map[string]string
	sharedFdTables []map[string]bool
}

func (s *ChanStream) pushOne(event *aucoalesce.Event, rawString string) {
	if syscall, ok := event.Data["syscall"]; ok &&
		!s.isRWParsed &&
		(syscall == "read" || syscall == "write") {
		return
	}
	if syscall, ok := event.Data["syscall"]; ok && event.Result == "success" && s.isRWParsed {
		object := event.Summary.Object
		pid := event.Process.PID

		if syscall == "open" || syscall == "openat" {
			if object.Type == "file" && object.Primary != "" {
				fp := object.Primary
				fd := event.Data["exit"]

				if !s.updateSharedFdTables(pid, fd, fp, true) {

					if _, okk := s.fdMap[pid]; !okk {
						s.fdMap[pid] = map[string]string{}
					}
					s.fdMap[pid][fd] = fp
				}
			}
		} else if syscall == "close" {

			fd := event.Data["a0"]

			if !s.updateSharedFdTables(pid, fd, "", false) {

				if _, okk := s.fdMap[pid]; okk {
					if _, okkk := s.fdMap[pid][fd]; okkk {
						delete(s.fdMap[pid], fd)
					}
				}
			}
		} else if syscall == "dup" || syscall == "dup2" || syscall == "dup3" {

			oldFd := event.Data["a0"]
			newFd := event.Data["exit"]
			if _, okk := s.fdMap[pid]; okk {
				if fp, okk := s.fdMap[pid][oldFd]; okk {
					if !s.updateSharedFdTables(pid, newFd, fp, true) {
						s.fdMap[pid][newFd] = fp
					}
				}
			}
		} else if syscall == "fork" || syscall == "vfork" || syscall == "clone" || syscall == "clone3" {
			newPid := event.Data["exit"]
			oldPid := pid

			if _, okk := s.fdMap[oldPid]; okk {
				newFds := map[string]string{}
				for k, v := range s.fdMap[oldPid] {
					newFds[k] = v
				}
				s.fdMap[newPid] = newFds
			}

			if syscall == "clone" && strings.Contains(event.Data["a2"], "CLONE_FILES") {
				flag := true
				for i := 0; i < len(s.sharedFdTables); i++ {
					if _, ok := s.sharedFdTables[i][oldPid]; ok {
						s.sharedFdTables[i][newPid] = true
						flag = false
						break
					}
				}
				if flag {
					newSet := make(map[string]bool)
					newSet[pid] = true
					newSet[newPid] = true
					s.sharedFdTables = append(s.sharedFdTables, newSet)
				}
			}
		} else if syscall == "connect" {
			socket := SocketType{Source: event.Source, Dest: event.Dest}
			socketByte, err := json.Marshal(socket)
			if err == nil {
				socketStr := string(socketByte)
				fd := event.Data["a0"]

				if !s.updateSharedFdTables(pid, fd, socketStr, true) {

					if _, okk := s.fdMap[pid]; !okk {
						s.fdMap[pid] = map[string]string{}
					}
					s.fdMap[pid][fd] = socketStr
				}
			}
		} else if syscall == "pipe" {

		}

	}

	if syscall, ok := event.Data["syscall"]; ok {
		if actionType, ok := SyscallsMap[syscall]; ok {
			eventEdge := EventEdge{}
			eventEdge.TimeStamp = event.Timestamp

			tags := make([]CLF.Tag, 0, 5)
			start, end := "", ""

			if syscall == "close" {

				eventEdge.SrcNode, start = s.GetProcess(event)
				eventEdge.DstNode, end = s.GetFile(event)

				if end == "" {
					eventEdge.DstNode, end = s.GetSocket(event)
				}
			} else if syscall == "clone" || syscall == "clone3" || syscall == "fork" || syscall == "vfork" {

				eventEdge.SrcNode, start = s.GetProcess(event)
				dstPid, ok := event.Data["exit"]
				if ok {
					end = "process#" + dstPid
					eventEdge.DstNode = ProcessEventNode{
						Pid: dstPid,
					}
				}
			} else if syscall == "set_tid_address" {

				srcPid := event.Process.PPID
				start = "process#" + srcPid
				eventEdge.SrcNode = ProcessEventNode{
					Pid: srcPid,
				}

				dstPid, ok := event.Data["exit"]
				if ok {
					end = "process#" + dstPid
					eventEdge.DstNode = ProcessEventNode{
						Pid: dstPid,
					}
				}
			} else if syscall == "kill" {
				eventEdge.SrcNode, start = s.GetProcess(event)
				dstPid, ok := event.Data["a0"]
				if ok {
					dstPid = hexStr2DecStr(dstPid)
					end = "process#" + dstPid
					eventEdge.DstNode = ProcessEventNode{
						Pid: dstPid,
					}
				}
			} else {

				switch SyscallSrcNodeMap[actionType] {
				case PROCESS:
					eventEdge.SrcNode, start = s.GetProcess(event)
				case FILE:
					eventEdge.SrcNode, start = s.GetFile(event)
				case SOCKET:
					eventEdge.SrcNode, start = s.GetSocket(event)
				default:
					panic("wrong node type")
				}

				switch SyscallDstNodeMap[actionType] {
				case PROCESS:
					eventEdge.DstNode, end = s.GetProcess(event)
				case FILE:
					eventEdge.DstNode, end = s.GetFile(event)
				case SOCKET:
					eventEdge.DstNode, end = s.GetSocket(event)
				default:
					panic("wrong node type")
				}
			}

			if start != "" {
				tags = append(tags, CLF.Tag{ID: -1, Key: "audit_start", Value: start, Type: CLF.Normal})
			}

			if end != "" {
				tags = append(tags, CLF.Tag{ID: -1, Key: "audit_end", Value: end, Type: CLF.Normal})
			}

			logs := CLF.Log{ID: -1, Time: event.Timestamp, LogType: s.logType, LogRaw: rawString}
			for tag := range UnwrapObject(eventEdge.SrcNode, "clf") {
				tags = append(tags, CLF.Tag{ID: -1, Key: "src_" + tag.k, Value: tag.v, Type: CLF.Normal})
			}
			for tag := range UnwrapObject(eventEdge.SrcNode, "clf1") {
				tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
				if tag.k == "filename" {
					tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: GetFileName(tag.v), Type: CLF.Normal})
				}
			}
			for tag := range UnwrapObject(eventEdge.DstNode, "clf") {
				tags = append(tags, CLF.Tag{ID: -1, Key: "dst_" + tag.k, Value: tag.v, Type: CLF.Normal})
			}
			for tag := range UnwrapObject(eventEdge.DstNode, "clf1") {
				tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
				if tag.k == "filename" {
					tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: GetFileName(tag.v), Type: CLF.Normal})
				}
			}

			tags = append(tags, CLF.Tag{ID: -1, Key: "action", Value: syscall, Type: CLF.Normal})
			tags = append(tags, CLF.Tag{ID: -1, Key: "type", Value: fmt.Sprintf("%s", SyscallsMap[syscall]), Type: CLF.Normal})

			pl := CLF.ParsedLog{
				Log:  logs,
				Tags: tags,
			}

			err := s.pusher.PushParsedLog(PatchIPEntries(pl))
			if err != nil {
				panic(err)
			}
		}
	}
}

func (s *ChanStream) outputMultipleMessages(msgs []*auparse.AuditMessage) error {
	var err error
	event, err := aucoalesce.CoalesceMessages(msgs)
	sb := strings.Builder{}
	if err != nil {
		log.Printf("failed to coalesce messages: %v", err)
		return nil
	}

	for _, msg := range msgs {
		sb.WriteString(msg.RawData + "\n")
	}

	s.pushOne(event, sb.String())
	return nil
}

func (s *ChanStream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	if err := s.outputMultipleMessages(msgs); err != nil {
		log.Printf("[WARN] failed writing message to output: %v", err)
	}
}

func (s *ChanStream) EventsLost(count int) {
	log.Printf("detected the loss of %v sequences.", count)
}
