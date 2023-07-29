package main

import (
	"HHPG/CLF"
	"strings"
)

func PatchIPEntries(log CLF.ParsedLog) CLF.ParsedLog {
	logs := log.Log
	tags := make([]CLF.Tag, 0, cap(log.Tags))

	ips := make(map[string]bool)
	for _, originTag := range log.Tags {
		if strings.Contains(strings.ToLower(originTag.Key), "ip") {
			ips[originTag.Value] = true
		} else {
			tags = append(tags, originTag)
		}
	}

	for ip, _ := range ips {
		tags = append(tags, CLF.Tag{ID: -1, Key: "ip", Value: ip, Type: CLF.Normal})
	}

	return CLF.ParsedLog{Log: logs, Tags: tags}
}
