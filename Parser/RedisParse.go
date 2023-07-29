package main

import (
	"HHPG/CLF"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type RedisLog struct {
	Timestamp   float64
	Ip          string `clf:"ip"`
	Port        string `clf:"port"`
	Command     string `clf:"cmd"`
	Content     string `clf:"content"`
	LibPath     string `clf:"libpath"`
	Function    string `clf:"function"`
	CommandMode string `clf:"commandmode"`
	FileMode    string `clf:"filemode"`
}

func parseRedisLine(line string) RedisLog {
	var s = strings.Split(line, " ")
	timestamp, err := strconv.ParseFloat(s[0], 64)
	if err != nil {
		return RedisLog{}
	}
	ipPort := strings.Split(strings.Trim(s[2], "]"), ":")
	content := ""
	for i := 4; i < len(s); i++ {
		content += strings.Trim(s[i], "\"") + " "
	}
	var parsedLine = RedisLog{
		Timestamp: timestamp,
		Ip:        ipPort[0],
		Port:      ipPort[1],
		Command:   strings.Trim(s[3], "\""),
		Content:   content,
	}
	if parsedLine.Command == "SCRIPT" {
		s = strings.Split(line, ";")
		for j := 0; j < len(s); j++ {
			reg := regexp.MustCompile("loadlib\\((.*),(.*)\\)")
			match := reg.FindStringSubmatch(s[j])
			if len(match) > 0 {
				parsedLine.LibPath = strings.Trim(match[1], "\\\" ")
				parsedLine.Function = strings.Trim(match[2], "\\\" ")
			}
			reg = regexp.MustCompile("io\\.popen\\((.*),(.*)\\)")
			match = reg.FindStringSubmatch(s[j])
			if len(match) > 0 {
				res := strings.Split(match[1], " ")
				parsedLine.Command = strings.Trim(res[0], "\\\" ")
				parsedLine.Content = strings.Trim(res[1], "\\\" ")
				parsedLine.CommandMode = strings.Trim(match[2], "\\\" ")
			}
			reg = regexp.MustCompile("read\\((.*?)\\)")
			match = reg.FindStringSubmatch(s[j])
			if len(match) > 0 {
				parsedLine.FileMode = strings.Trim(match[1], "\\\" ")
			}
		}
	}
	return parsedLine
}

type RedisParser struct {
	pusher *Pusher
}

func NewRedisParser(pusher *Pusher) RedisParser {
	return RedisParser{
		pusher: pusher,
	}
}

func (p RedisParser) LogType() string {
	return "Redis"
}

func (p RedisParser) ParsePushLine(rawLine string) error {
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

func (p RedisParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	rawLine = strings.TrimRight(rawLine, " \n")
	parsedLine := parseRedisLine(rawLine)

	if parsedLine.Timestamp == 0 {
		return pl, true, nil
	}

	obj := strings.Split(parsedLine.Content, " ")[0]
	host_ip := parsedLine.Ip + ":" + parsedLine.Port
	if parsedLine.Command == "SET" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "redis_start", Value: host_ip, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "redis_end", Value: obj, Type: CLF.Normal})
	} else if parsedLine.Command == "GET" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "redis_start", Value: obj, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "redis_end", Value: host_ip, Type: CLF.Normal})
	} else if parsedLine.Command == "stat" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "redis_start", Value: obj, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "redis_end", Value: host_ip, Type: CLF.Normal})
	} else {
		return pl, true, nil
	}

	for tag := range UnwrapObject(parsedLine, "clf") {
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: ellipsis(tag.v, MAX_TAG_VAL_BYTES), Type: CLF.Normal})
	}

	pl.Tags = tags
	ts := time.UnixMicro(int64(parsedLine.Timestamp * 1e6))
	pl.Log = CLF.Log{ID: -1, Time: ts, LogType: p.LogType(), LogRaw: rawLine}

	return pl, false, nil
}
