package main

import (
	"HHPG/CLF"
	"errors"
	"regexp"
	"strings"
	"time"
)

type MiniHttpdParser struct {
	pusher *Pusher
}

func NewMiniHttpParser(pusher *Pusher) *MiniHttpdParser {
	return &MiniHttpdParser{
		pusher: pusher,
	}
}

func (p *MiniHttpdParser) LogType() string {
	return "MiniHttpd"
}

func (p *MiniHttpdParser) ParsePushLine(rawLine string) error {
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

func (p *MiniHttpdParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	re := regexp.MustCompile(
		"(?P<remote_ip>.*) - - \\[(?P<time>.*)\\] \"" +
			"(?P<method>\\w+) (?P<path>\\S*) (?P<protocol>[^\\\"\\s]*)\" " +
			"(?P<status_code>[\\d-]+) (?P<len>[\\d-]+) \"" +
			"(?P<unknown0>[^\"]*)\" \"(?P<user_agent>[^\"\\n]*)\"")
	found := re.FindAllStringSubmatch(rawLine, -1)
	groupNames := re.SubexpNames()

	m := make(map[string]string)
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	if len(found) != 1 {

		return pl, false, errors.New("parse error")
	}

	find := found[0]
	start, end := "", ""
	for j, n := range groupNames {
		if j != 0 && n != "" {
			if strings.Contains(n, "unknown") {
				continue
			}

			m[n] = strings.TrimSpace(find[j])
			tags = append(tags, CLF.Tag{
				ID:    -1,
				Key:   n,
				Value: m[n],
				Type:  CLF.Normal,
			})
			if n == "filename" {
				tags = append(tags, CLF.Tag{ID: -1, Key: n, Value: GetFileName(m[n]), Type: CLF.Normal})
			}
			if n == "remote_ip" {
				start = m[n]
				tags = append(tags, CLF.Tag{ID: -1, Key: "ip", Value: start, Type: CLF.Normal})
			}
			if n == "path" {
				end = m[n]
				tags = append(tags, CLF.Tag{ID: -1, Key: "file_path", Value: end, Type: CLF.Normal})
				reIPV4 := regexp.MustCompile("^/((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}/$")
				match := reIPV4.MatchString(end)
				if match {
					end = strings.Trim(end, "/")
				}
			}
		}
	}

	if start != "" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "minihttpd_start", Value: start, Type: CLF.Normal})
	}
	if end != "" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "minihttpd_end", Value: end, Type: CLF.Normal})
	}

	const layout = "02/Jan/2006:15:04:05 -0700"
	ts, err := time.Parse(layout, m["time"])
	if err != nil {
		return pl, false, errors.New("timestamp error")
	}

	pl.Log = CLF.Log{ID: -1, Time: ts, LogRaw: rawLine, LogType: p.LogType()}
	pl.Tags = tags

	return pl, false, nil
}
