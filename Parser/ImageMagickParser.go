package main

import (
	"HHPG/CLF"
	"log"
	"regexp"
	"strings"
	"time"
)

type ImagemagickLog struct {
	Timestamp int64
	Pid       string
	Rights    string
	Path      string `clf:"path"`
	File      string `clf:"filename"`
}

func getImagemagickTimeStamp(line string) int64 {
	const form = "2006-01-02T15:04:05Z07:00"
	s := strings.Split(line, " ")[0]
	t, err := time.Parse(form, s)
	if err != nil {
		log.Fatal(err)
		return -1
	}
	return t.Unix()
}

func parseImagemagickLine(line string) ImagemagickLog {
	reg1 := regexp.MustCompile("convert\\[(.*)].*rights=(.*); pattern=\"(.*)\"")
	s1 := reg1.FindStringSubmatch(line)
	if len(s1) == 0 || s1[3] == "PNG" {
		return ImagemagickLog{}
	}
	var parsedLine = ImagemagickLog{
		Timestamp: getImagemagickTimeStamp(line),
		Pid:       s1[1],
		Rights:    s1[2],
		Path:      s1[3],
		File:      s1[3],
	}
	return parsedLine
}

type ImageMagickParser struct {
	pusher   *Pusher
	currLine string
}

func NewImageMagickParser(pusher *Pusher) *ImageMagickParser {
	return &ImageMagickParser{
		pusher:   pusher,
		currLine: "",
	}
}

func (p *ImageMagickParser) LogType() string {
	return "ImageMagick"
}

func (p *ImageMagickParser) ParsePushLine(rawLine string) error {
	rawLine = strings.TrimRight(rawLine, " \n")
	if len(rawLine) > 2 && rawLine[:2] == "  " {
		p.currLine += rawLine[1:]
		return nil
	} else {
		if p.currLine != "" {
			pl, _, err := p.ParseLine(p.currLine)
			p.currLine = rawLine
			if err != nil {
				return err
			}
			err = p.pusher.PushParsedLog(pl)
			if err != nil {
				return err
			}
		} else {
			p.currLine = rawLine
		}
	}

	return nil
}

func (p *ImageMagickParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	tags := make([]CLF.Tag, 0, 5)

	rawLine = strings.TrimRight(rawLine, " \n")
	parsedLine := parseImagemagickLine(rawLine)

	for tag := range UnwrapObject(parsedLine, "clf") {
		tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: tag.v, Type: CLF.Normal})
		if tag.k == "filename" {
			tags = append(tags, CLF.Tag{ID: -1, Key: tag.k, Value: GetFileName(tag.v), Type: CLF.Normal})
		}
	}

	if parsedLine.Rights == "Write" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "ImageMagick_start", Value: "ImageMagick.exe", Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "ImageMagick_end", Value: parsedLine.File, Type: CLF.Normal})
	} else if parsedLine.Rights == "Read" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "ImageMagick_start", Value: parsedLine.File, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "ImageMagick_end", Value: "ImageMagick.exe", Type: CLF.Normal})
	}

	pl.Tags = tags
	ts := time.Unix(parsedLine.Timestamp, 0)
	pl.Log = CLF.Log{ID: -1, Time: ts, LogType: p.LogType(), LogRaw: rawLine}

	return PatchIPEntries(pl), false, nil
}
