package main

import (
	"HHPG/CLF"
	"bufio"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type VimLog struct {
	Timestamp int64
	Pid       int64  `clf:"pid"`
	Action    string `clf:"action"`
	Path      string `clf:"filename"`
	FileName  string
	FileSize  int64
}

func readVimLog(name string) []string {
	var lines []string
	f, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
		return lines
	}
	reader := bufio.NewReader(f)
	for {
		s, err := reader.ReadString('\n')
		if err == io.EOF {
			return lines
		} else if err != nil {
			log.Fatal(err)
			return lines
		}
		s = strings.TrimRight(s, " \n")
		lines = append(lines, s)
	}
}

func parseVimLine(line string) VimLog {
	var s = strings.Split(line, "\t")
	timestamp, err1 := strconv.ParseInt(s[0], 10, 64)
	pid, err2 := strconv.ParseInt(s[2], 10, 64)
	size, err3 := strconv.ParseInt(s[7], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return VimLog{}
	}
	var parsedLine = VimLog{
		Timestamp: timestamp,
		Pid:       pid,
		Action:    s[3],
		Path:      s[5],
		FileName:  s[6],
		FileSize:  size,
	}
	return parsedLine
}

type VimParser struct {
	pusher *Pusher
}

func NewVimParser(pusher *Pusher) VimParser {
	return VimParser{
		pusher: pusher,
	}
}

func (p VimParser) LogType() string {
	return "Vim"
}

func (p VimParser) ParsePushLine(rawLine string) error {
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

func (p VimParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	rawLine = strings.TrimRight(rawLine, " \n")
	parsedLine := parseVimLine(rawLine)

	for tag := range UnwrapObject(parsedLine, "clf") {
		if tag.k == "filename" {
			tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: GetFileName(tag.v), Type: CLF.Normal})
		}
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
	}

	if parsedLine.Action == "BufWrite" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "vim_start", Value: "vim.exe." + strconv.FormatInt(parsedLine.Pid, 10), Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "vim_end", Value: parsedLine.FileName, Type: CLF.Normal})
	} else if parsedLine.Action == "BufRead" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "vim_start", Value: parsedLine.FileName, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "vim_end", Value: "vim.exe." + strconv.FormatInt(parsedLine.Pid, 10), Type: CLF.Normal})
	}

	pl.Tags = tags
	ts := time.Unix(parsedLine.Timestamp, 0)
	pl.Log = CLF.Log{ID: -1, Time: ts, LogType: p.LogType(), LogRaw: rawLine}

	return pl, false, nil
}
