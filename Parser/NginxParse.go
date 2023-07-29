package main

import (
	"HHPG/CLF"
	"bufio"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

type NginxLog struct {
	Timestamp    int64
	Host         string `clf:"remote_ip"`
	Method       string `clf:"method"`
	Url          string `clf:"filename"`
	ResponseCode string `clf:"response_code"`
	TransferSize string
	Referer      string
	UserAgent    string `clf:"user_agent"`
}

func readNginxLog(name string) []string {
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

func getNginxStamp(line string) int64 {
	reg := regexp.MustCompile("\\[.*]")
	const form = "[_2/Jan/2006:15:04:05 -0700]"

	s := reg.FindString(line)
	t, err := time.Parse(form, s)
	if err != nil {
		log.Fatal(err)
		return -1
	}
	return t.Unix()
}

func parseNginxLine(line string) NginxLog {
	var s = strings.Split(line, " ")
	var s2 = strings.Split(line, "\"")
	var parsedLine = NginxLog{
		Timestamp:    getNginxStamp(line),
		Host:         s[0],
		Method:       s[5][1:],
		Url:          s[6],
		ResponseCode: s[8],
		TransferSize: s[9],
		Referer:      strings.Trim(s[10], "\""),
		UserAgent:    s2[5],
	}
	return parsedLine
}

type NginxParser struct {
	pusher *Pusher
}

func NewNginxParser(pusher *Pusher) NginxParser {
	return NginxParser{
		pusher: pusher,
	}
}

func (p NginxParser) LogType() string {
	return "Nginx"
}

func (p NginxParser) ParsePushLine(rawLine string) error {
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

func (p NginxParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	rawLine = strings.TrimRight(rawLine, " \n")
	parsedLine := parseNginxLine(rawLine)

	for tag := range UnwrapObject(parsedLine, "clf") {
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
		if tag.k == "filename" {
			tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: GetFileName(tag.v), Type: CLF.Normal})
		}
	}

	if parsedLine.Method == "GET" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "nginx_start", Value: parsedLine.Url, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "nginx_end", Value: parsedLine.Host, Type: CLF.Normal})
	} else {
		tags = append(tags, CLF.Tag{ID: -1, Key: "nginx_start", Value: parsedLine.Host, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "nginx_end", Value: parsedLine.Url, Type: CLF.Normal})
	}

	pl.Tags = tags
	ts := time.Unix(parsedLine.Timestamp, 0)
	pl.Log = CLF.Log{ID: -1, Time: ts, LogType: p.LogType(), LogRaw: rawLine}

	return PatchIPEntries(pl), false, nil
}
