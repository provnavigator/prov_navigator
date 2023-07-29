package main

import (
	"HHPG/CLF"
	"errors"
	"regexp"
	"strings"
	"time"
)

type NetworkParser struct {
	pusher *Pusher
}

func NewNetworkParser(pusher *Pusher) NetworkParser {
	return NetworkParser{
		pusher: pusher,
	}
}

func (p NetworkParser) LogType() string {
	return "Network"
}

func (p NetworkParser) ParsePushLine(rawLine string) error {
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

func (p NetworkParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {

	res := [...]*regexp.Regexp{
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\\w+)" +
				"\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t" +
				"(?P<len>[\\d]+)\t(?P<method>\\w+) (?P<filename>\\S*) (?P<protocol>[^\\\"\\s]*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\\w+)" +
				"\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t" +
				"(?P<len>[\\d]+)\t(?P<protocol>[^\\\"\\s]*) (?P<retValue>[\\d]+) (?P<text>.*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\\w+)" +
				"\t\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t([\\d]+)\t(?P<text>.*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>\\w+)" +
				"\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t([\\d]+)\t(?P<text>.*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>[-\\w]+)" +
				"\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t([\\d]+)\t(?P<text>.*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
				"\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t([\\d]+)\t(?P<text>.*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
				"\t\t\t\t(?P<text>.*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
				"\t(?P<srcPort>[\\d]+),(?P<destPort>[\\d]+)\t\t(?P<text>.*)"),
		regexp.MustCompile(
			"(?P<sequenceNum>[\\d]+)\t(?P<time>.*)\t(?P<srcIp>.*)\t(?P<destIp>.*)\t(?P<protocolName>.*)" +
				"\t\t\t([\\d]+)\t(?P<text>.*)"),

		regexp.MustCompile(
			"[\\s]*(?P<sequenceNum>[\\d]+)[\\s]+(?P<time>.*)[\\s]+(?P<srcIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+) → (?P<destIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+)[\\s]+" +
				"HTTP[\\s]*(?P<len>[\\d]+)[\\s]*(?P<method>\\w+)[\\s]*(?P<filename>.*)[\\s]*HTTP/1.1"),

		regexp.MustCompile(
			"[\\s]*(?P<sequenceNum>[\\d]+)[\\s]+(?P<time>.*)[\\s]+(?P<srcIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+) → (?P<destIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+)[\\s]+" +
				"TCP[\\s]*(?P<len>[\\d]+)[\\s]*(?P<srcPort>[\\d]+) → (?P<destPort>[\\d]+)[\\s]*(?P<text>.*)"),

		regexp.MustCompile(
			"[\\s]*(?P<sequenceNum>[\\d]+)[\\s]+(?P<time>.*)[\\s]+(?P<srcIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+) → (?P<destIp>[0-9]+.[0-9]+.[0-9]+.[0-9]+)[\\s]+" +
				"(?P<text>.*)"),
	}
	var founds [][][]string
	var groupNames [][]string
	for _, re := range res {
		founds = append(founds, re.FindAllStringSubmatch(rawLine, -1))
		groupNames = append(groupNames, re.SubexpNames())
	}

	m := make(map[string]string)
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	idx := -1
	for index, found := range founds {
		if len(found) == 1 {
			idx = index
			break
		}
	}
	if idx == -1 {
		return pl, false, errors.New("parse error")
	}

	find := founds[idx][0]
	start, end := "", ""
	for j, n := range groupNames[idx] {
		if j != 0 && n != "" {
			m[n] = strings.TrimSpace(find[j])
			tags = append(tags, CLF.Tag{
				ID:    -1,
				Key:   n,
				Value: ellipsis(m[n], MAX_TAG_VAL_BYTES),
				Type:  CLF.Normal,
			})
			if n == "srcIp" {
				start = m[n] + start
				tags = append(tags, CLF.Tag{ID: -1, Key: "ip", Value: m[n], Type: CLF.Normal})
			}
			if n == "srcPort" {
				start = start + ":" + m[n]
				tags = append(tags, CLF.Tag{ID: -1, Key: "port", Value: m[n], Type: CLF.Normal})
			}
			if n == "destIp" {
				end = m[n] + end
				tags = append(tags, CLF.Tag{ID: -1, Key: "ip", Value: m[n], Type: CLF.Normal})
			}
			if n == "destPort" {
				end = end + ":" + m[n]
				tags = append(tags, CLF.Tag{ID: -1, Key: "port", Value: m[n], Type: CLF.Normal})
			}

			if n == "text" {
				textSplit := strings.Split(m[n], " ")
				for _, candidateFilename := range textSplit {
					if strings.Contains(candidateFilename, "txt") {
						tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: GetFileName(candidateFilename), Type: CLF.Normal})
					}
				}
			}

			if n == "filename" {
				tags = append(tags, CLF.Tag{ID: -1, Key: n, Value: GetFileName(m[n]), Type: CLF.Normal})
				if strings.Contains(m[n], "system") {
					textSplit := strings.Split(m[n], "'")
					if len(textSplit) == 3 {
						path := textSplit[1]
						tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: GetFileName(path), Type: CLF.Normal})
					}
				}
			}

		}
	}

	if start != "" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "network_start", Value: start, Type: CLF.Normal})
	}
	if end != "" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "network_end", Value: end, Type: CLF.Normal})
	}

	const layout = "Jan 2, 2006 15:04:05.000000000 CST"
	ts, err := time.Parse(layout, m["time"])
	if err != nil {

		ts = time.Now()

	}

	pl.Log = CLF.Log{ID: -1, Time: ts, LogRaw: rawLine, LogType: p.LogType()}
	pl.Tags = tags

	return pl, false, nil
}
