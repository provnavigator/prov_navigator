package main

import (
	"HHPG/CLF"
	"regexp"
	"strings"
)

type DNSParser struct {
	pusher *Pusher
}

func NewDNSParser(pusher *Pusher) DNSParser {
	return DNSParser{
		pusher: pusher,
	}
}

func (p DNSParser) LogType() string {
	return "DNS"
}

func (p DNSParser) ParsePushLine(rawLine string) error {
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

func (p DNSParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {

	pl := CLF.ParsedLog{}

	if !strings.Contains(rawLine, "Standard query response") {
		return pl, true, nil
	}

	tags := make([]CLF.Tag, 0, 5)
	A := regexp.MustCompile("A [^ ]*")
	AAAA := regexp.MustCompile("AAAA [^ ]*")
	reIPV4 := regexp.MustCompile("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$")
	reIPV6 := regexp.MustCompile("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$")

	found := A.FindAllStringSubmatch(rawLine, -1)
	if len(found) == 0 {
		found = AAAA.FindAllStringSubmatch(rawLine, -1)
	}

	if len(found) == 0 {
		return pl, true, nil
	}

	for _, find := range found {
		f := strings.Split(find[0], " ")[1]
		if reIPV4.MatchString(f) || reIPV6.MatchString(f) {
			tags = append(tags, CLF.Tag{ID: -1, Key: "ip", Value: f, Type: 0})
		} else {
			tags = append(tags, CLF.Tag{ID: -1, Key: "domain", Value: f, Type: 0})
		}
	}

	pl.Tags = tags
	return pl, false, nil
}
