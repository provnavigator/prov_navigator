package main

import (
	"HHPG/CLF"
	"log"
	"regexp"
	"strings"
	"time"
)

type ApacheLog struct {
	Timestamp    int64
	Host         string `clf:"remote_ip"`
	Method       string `clf:"method"`
	Url          string `clf:"filename"`
	ResponseCode string `clf:"response_code"`
	TransferSize string
}

func getApacheStamp(line string) int64 {
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

func parseApacheLine(line string) ApacheLog {
	var s = strings.Split(line, " ")
	var parsedLine = ApacheLog{
		Timestamp:    getApacheStamp(line),
		Host:         s[0],
		Method:       s[5][1:],
		Url:          s[6],
		ResponseCode: s[8],
		TransferSize: s[9],
	}
	return parsedLine
}

type ApacheParser struct {
	pusher *Pusher
}

func NewApacheParser(pusher *Pusher) ApacheParser {
	return ApacheParser{
		pusher: pusher,
	}
}

func (p ApacheParser) LogType() string {
	return "Apache"
}

func (p ApacheParser) ParsePushLine(rawLine string) error {
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

func (p ApacheParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	rawLine = strings.TrimRight(rawLine, " \n")
	parsedLine := parseApacheLine(rawLine)

	for tag := range UnwrapObject(parsedLine, "clf") {
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
		if tag.k == "filename" {
			tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: GetFileName(tag.v), Type: CLF.Normal})
		}
	}

	if parsedLine.Method == "GET" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "apache_start", Value: parsedLine.Url, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "apache_end", Value: parsedLine.Host, Type: CLF.Normal})
	} else {
		tags = append(tags, CLF.Tag{ID: -1, Key: "apache_start", Value: parsedLine.Host, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "apache_end", Value: parsedLine.Url, Type: CLF.Normal})
	}

	pl.Tags = tags
	ts := time.Unix(parsedLine.Timestamp, 0)
	pl.Log = CLF.Log{ID: -1, Time: ts, LogType: p.LogType(), LogRaw: rawLine}

	return PatchIPEntries(pl), false, nil
}
