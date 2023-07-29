package CLF

import (
	"fmt"
	"time"
)

type TagType int

const (
	Normal TagType = 0
	Group  TagType = 1
)

var SQLITE_FILE = "./CLFDB/sqlite.db"

type ParsedLog struct {
	Log  Log
	Tags []Tag
}

type Log struct {
	ID      int64
	Time    time.Time
	LogRaw  string
	LogType string
}

func (l *Log) timestampString() string {
	timeStamp := l.Time.Format("2006-01-02 15:04:05.000")
	return fmt.Sprintf("%v", timeStamp)
}

type Tag struct {
	ID    int64
	Key   string
	Value string
	Type  TagType
}
