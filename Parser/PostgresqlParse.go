package main

import (
	"HHPG/CLF"
	"strconv"
	"strings"
	"time"
)

type PostgresqlParser struct {
	pusher   *Pusher
	netMap   map[string]PostgresqlNetState
	currLine string
}

func NewPostgresqlParser(pusher *Pusher) *PostgresqlParser {
	return &PostgresqlParser{
		pusher: pusher, netMap: map[string]PostgresqlNetState{}, currLine: "",
	}
}

func (f *PostgresqlParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	panic("not implemented")
}

func (f *PostgresqlParser) ParsePushLine(rawLine string) error {
	if strings.Contains(rawLine, "statement:") {
		f.currLine = rawLine
	} else if !strings.Contains(rawLine, "LOG:") {
		f.currLine += rawLine
	} else {
		if strings.Contains(rawLine, "connection received") {
			id, net := getPostgresqlHostAndPort(rawLine)
			f.netMap[id] = net
		}
		if f.currLine == "" {
			return nil
		}
		pLogs := ParsePostgresqlLine(f.currLine, f.netMap)
		for _, pLog := range pLogs {
			pl := CLF.ParsedLog{}
			tags := make([]CLF.Tag, 0, 5)

			pl.Log = CLF.Log{
				ID:      -1,
				Time:    time.Unix(pLog.Timestamp, 0),
				LogRaw:  f.currLine,
				LogType: f.LogType(),
			}

			SqlAction := pLog.Action
			remote := pLog.Host + ":" + strconv.Itoa(pLog.Port)
			start, end := "", ""
			if SqlAction == "" {
				continue
			} else if SqlAction == "SELECT" {

				start = "PostgreSQL.exe"
				end = remote
			} else {

				end = "PostgreSQL.exe"
				start = remote
			}

			tags = append(tags, CLF.Tag{ID: -1, Key: "psql_start", Value: start, Type: CLF.Normal})
			tags = append(tags, CLF.Tag{ID: -1, Key: "psql_end", Value: end, Type: CLF.Normal})

			tags = append(tags, CLF.Tag{ID: -1, Key: "host", Value: pLog.Host, Type: CLF.Normal})
			tags = append(tags, CLF.Tag{ID: -1, Key: "port", Value: strconv.Itoa(pLog.Port), Type: CLF.Normal})
			tags = append(tags, CLF.Tag{ID: -1, Key: "action", Value: pLog.Action, Type: CLF.Normal})
			tags = append(tags, CLF.Tag{ID: -1, Key: "cmd", Value: pLog.Cmd, Type: CLF.Normal})

			pl.Tags = tags
			err := f.pusher.PushParsedLog(pl)
			if err != nil {
				return err
			}
		}
		f.currLine = ""
	}
	return nil
}

func (f *PostgresqlParser) LogType() string {
	return "PostgreSql"
}
