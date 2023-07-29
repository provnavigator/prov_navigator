package main

import (
	"HHPG/CLF"
	"log"
	"regexp"
	"strings"
	"time"
)

type OpensshLog struct {
	Timestamp int64
	Pid       string `clf:"pid"`
	Ip        string
	Port      string
	UserName  string `clf:"UserName"`
	State     string `clf:"State"`
}

func getOpensshTimeStamp(line string) int64 {
	reg := regexp.MustCompile(".{3} [0-9]+ [0-9]+:[0-9]+:[0-9]+")
	const form = "Jan 02 15:04:05 2006"
	s := reg.FindString(line)
	t, err := time.Parse(form, s+" 2023")
	if err != nil {
		log.Fatal(err)
		return -1
	}
	return t.Unix()
}

func parseOpensshLine(line string) OpensshLog {
	reg1 := regexp.MustCompile("sshd\\[([0-9]+)]: Accepted password for (.*) from (.*) port ([0-9]+)")
	reg2 := regexp.MustCompile("sshd\\[([0-9]+)]: Disconnected from user (.*) (.*) port ([0-9]+)")
	s1 := reg1.FindStringSubmatch(line)
	s2 := reg2.FindStringSubmatch(line)
	if len(s1) > 0 {
		var parsedLine = OpensshLog{
			Timestamp: getOpensshTimeStamp(line),
			Pid:       s1[1],
			Ip:        s1[3],
			Port:      s1[4],
			UserName:  s1[2],
			State:     "Connect",
		}
		return parsedLine
	} else if len(s2) > 0 {
		var parsedLine = OpensshLog{
			Timestamp: getOpensshTimeStamp(line),
			Pid:       s2[1],
			Ip:        s2[3],
			Port:      s2[4],
			UserName:  s2[2],
			State:     "Disconnect",
		}
		return parsedLine
	} else {
		return OpensshLog{}
	}
}

type OpensshParser struct {
	pusher *Pusher
}

func NewOpensshParser(pusher *Pusher) OpensshParser {
	return OpensshParser{
		pusher: pusher,
	}
}

func (p OpensshParser) LogType() string {
	return "openssh"
}

func (p OpensshParser) ParsePushLine(rawLine string) error {
	pl, skip, err := p.ParseLine(rawLine)
	if skip {
		return nil
	}

	if err != nil {
		return err
	}
	err = p.pusher.PushParsedLog(pl)
	if err != nil {
		return err
	}

	return nil
}

func (p OpensshParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	rawLine = strings.TrimRight(rawLine, " \n")
	parsedLine := parseOpensshLine(rawLine)

	for tag := range UnwrapObject(parsedLine, "clf") {
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
	}

	if parsedLine.State == "Connect" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "openssh_start", Value: "OpenSSH.exe." + parsedLine.Pid, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "openssh_end", Value: parsedLine.Ip + ":" + parsedLine.Port, Type: CLF.Normal})
	} else if parsedLine.State == "Disconnect" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "openssh_start", Value: parsedLine.Ip + ":" + parsedLine.Port, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "openssh_end", Value: "OpenSSH.exe." + parsedLine.Pid, Type: CLF.Normal})
	}

	pl.Tags = tags
	ts := time.Unix(parsedLine.Timestamp, 0)
	pl.Log = CLF.Log{ID: -1, Time: ts, LogType: p.LogType(), LogRaw: rawLine}

	return pl, false, nil
}
