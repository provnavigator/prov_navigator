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

type ProftpdLog struct {
	Timestamp            int64
	TransferTime         string
	Host                 string `clf:"ip"`
	FileSize             string `clf:"filesize"`
	FileName             string `clf:"filename"`
	TransferType         string
	SpecialFlag          string
	Direction            string `clf:"direction"`
	AccessMode           string
	Username             string `clf:"username"`
	Service              string
	AuthenticationMethod string
	AuthenticationUserId string
	TransferStatus       string
}

func readProftpdLog(name string) []string {
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

func getProftpdStamp(line string) int64 {
	reg := regexp.MustCompile(".* .* [0-9]+ [0-9]+:[0-9]+:[0-9]+ [0-9]+")
	const form = "Mon Jan _2 15:04:05 2006"
	s := reg.FindString(line)
	t, err := time.Parse(form, s)
	if err != nil {
		log.Fatal(err)
		return -1
	}
	return t.Unix()
}

var TransferTypeDesc = map[string]string{
	"a": "Ascii",
	"b": "Binary",
}

var SpecialFlagDesc = map[string]string{
	"_": "None",
	"C": "Compressed",
	"U": "Uncompressed",
	"T": "Tar",
}

var DirectionDesc = map[string]string{
	"i": "Upload",
	"o": "Download",
	"d": "Delete",
}

var AccessModeDesc = map[string]string{
	"r": "SystemUser",
	"a": "Anonymous",
}

var TransferStatusDesc = map[string]string{
	"c": "Complete",
	"i": "Incomplete",
}

func parseProftpdLine(line string) ProftpdLog {
	var s = strings.Split(line, " ")
	var parsedLine = ProftpdLog{
		Timestamp:            getProftpdStamp(line),
		TransferTime:         s[5],
		Host:                 s[6],
		FileSize:             s[7],
		FileName:             s[8],
		TransferType:         TransferTypeDesc[s[9]],
		SpecialFlag:          SpecialFlagDesc[s[10]],
		Direction:            DirectionDesc[s[11]],
		AccessMode:           AccessModeDesc[s[12]],
		Username:             s[13],
		Service:              s[14],
		AuthenticationMethod: s[15],
		AuthenticationUserId: s[16],
		TransferStatus:       TransferStatusDesc[s[17]],
	}
	return parsedLine
}

type ProftpdParser struct {
	pusher *Pusher
}

func NewProftpdParser(pusher *Pusher) ProftpdParser {
	return ProftpdParser{
		pusher: pusher,
	}
}

func (p ProftpdParser) LogType() string {
	return "Proftpd"
}

func (p ProftpdParser) ParsePushLine(rawLine string) error {
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

func (p ProftpdParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	parsedLog := parseProftpdLine(rawLine)
	direction := parsedLog.Direction
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	pl.Log = CLF.Log{
		ID:      -1,
		Time:    time.Unix(parsedLog.Timestamp, 0),
		LogRaw:  rawLine,
		LogType: p.LogType(),
	}

	if direction == "Upload" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "proftpd_start", Value: parsedLog.Host, Type: 0})
		tags = append(tags, CLF.Tag{ID: -1, Key: "src_remote_ip", Value: parsedLog.Host, Type: 0})

		tags = append(tags, CLF.Tag{ID: -1, Key: "proftpd_end", Value: parsedLog.FileName, Type: 0})
		tags = append(tags, CLF.Tag{ID: -1, Key: "dst_path", Value: parsedLog.FileName, Type: 0})
	} else if direction == "Download" || direction == "Delete" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "proftpd_start", Value: parsedLog.FileName, Type: 0})
		tags = append(tags, CLF.Tag{ID: -1, Key: "src_path", Value: parsedLog.FileName, Type: 0})

		tags = append(tags, CLF.Tag{ID: -1, Key: "proftpd_end", Value: parsedLog.Host, Type: 0})
		tags = append(tags, CLF.Tag{ID: -1, Key: "dst_remote_ip", Value: parsedLog.Host, Type: 0})
	}

	for tag := range UnwrapObject(parsedLog, "clf") {
		if tag.k == "filename" {
			tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: GetFileName(tag.v), Type: CLF.Normal})
		}
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
	}

	pl.Tags = tags
	return pl, false, nil
}
