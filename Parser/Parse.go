package main

import (
	"HHPG/CLF"
	"bufio"
	"log"
	"os"
)

type Parser interface {
	ParseLine(rawLine string) (CLF.ParsedLog, bool, error)
	ParsePushLine(rawLine string) error
	LogType() string
}

type Pusher struct {
	parsedLogCh *chan CLF.ParsedLog
}

func (p *Pusher) PushParsedLog(pl CLF.ParsedLog) error {
	*p.parsedLogCh <- pl
	return nil
}

func ParseFile(name string, parser Parser) error {
	f, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(bufio.NewReader(f))

	var lineNum int
	for s.Scan() {
		line := s.Text()
		lineNum++
		err = parser.ParsePushLine(line)
		if err != nil {
			return err
		}
	}

	return nil
}
