package main

import (
	"HHPG/CLF"
	"regexp"
	"strings"
	"time"
)

type FirefoxParser struct {
	pusher *Pusher
	line   string
	enter  bool
}

func NewFirefoxParser(pusher *Pusher) *FirefoxParser {
	return &FirefoxParser{
		pusher: pusher, line: "", enter: false,
	}
}

func (f *FirefoxParser) lineValidation(s string) string {

	if strings.Contains(s, "uri=http") {
		return s
	}
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")

	if strings.Contains(s, "http response [") || strings.Contains(s, "http request [") {
		f.line = s
		f.enter = true
		return ""
	} else if f.enter {
		f.line = f.line + "\n" + s
		if strings.Contains(s, " ]") {
			f.enter = false
			return f.line
		}
	}
	return ""
}

func (f *FirefoxParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	validLine := f.lineValidation(rawLine)
	if validLine == "" {
		return pl, true, nil
	}

	httpEntry := parseHttpLine(validLine)

	if httpEntry.HttpType != "Request" {
		return pl, true, nil
	}

	ts := time.Unix(httpEntry.Timestamp, 0)
	pl.Log = CLF.Log{
		ID:      -1,
		Time:    ts,
		LogRaw:  validLine,
		LogType: f.LogType(),
	}

	for tag := range UnwrapObject(httpEntry, "clf") {
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: ellipsis(tag.v, MAX_TAG_VAL_BYTES), Type: CLF.Normal})
	}

	host := httpEntry.Host
	port := ""
	if host == "" {
		matchDomain := regexp.MustCompile(":\\/\\/[^\\/]*")
		found := matchDomain.FindAllStringSubmatch(rawLine, -1)
		if len(found) > 0 && len(found[0]) > 0 {
			host = found[0][0][3:]
		}
	}

	if host != "" {
		sp := strings.Split(host, ":")
		if len(sp) > 1 {
			host = sp[0]
			port = sp[1]
		}
	}

	tags = append(tags, CLF.Tag{ID: -1, Key: "query", Value: ellipsis(httpEntry.Host+httpEntry.Query, MAX_TAG_VAL_BYTES), Type: CLF.Normal})
	tags = append(tags, CLF.Tag{ID: -1, Key: "host", Value: ellipsis(host, MAX_TAG_VAL_BYTES), Type: CLF.Normal})
	if port != "" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "port", Value: port, Type: CLF.Normal})
	}
	tags = append(tags, CLF.Tag{ID: -1, Key: "firefox_start", Value: "firefox", Type: CLF.Normal})
	tags = append(tags, CLF.Tag{ID: -1, Key: "firefox_end", Value: ellipsis(httpEntry.Host+httpEntry.Query, MAX_TAG_VAL_BYTES), Type: CLF.Normal})

	filenameRe := regexp.MustCompile("(?:.+\\/)([^#?]+)")
	allMatch := filenameRe.FindAllStringSubmatch(httpEntry.Query, -1)
	if len(allMatch) > 0 && len(allMatch[0]) > 1 {
		tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: ellipsis(allMatch[0][1], MAX_TAG_VAL_BYTES), Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: ellipsis(GetFileName(allMatch[0][1]), MAX_TAG_VAL_BYTES), Type: CLF.Normal})
	}

	pl.Tags = tags
	return pl, false, nil
}

func (f *FirefoxParser) ParsePushLine(rawLine string) error {
	pl, skip, err := f.ParseLine(rawLine)
	if skip {
		return nil
	}

	if err != nil {
		return err
	}
	err = f.pusher.PushParsedLog(pl)
	if err != nil {
		return err
	}

	return nil
}

func (f *FirefoxParser) LogType() string {
	return "Firefox"
}
