package CLF

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"log"
)

type DNSInserter struct {
	ParsedLogCh *chan ParsedLog
}

func (pi *DNSInserter) Insert(goroutine int) {
	log.Printf("Start dnsInserter routine %d\n", goroutine)
	db, err := sql.Open("sqlite3", SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}
	logCnt := 0
	tagCnt := 0
	for logItem := range *pi.ParsedLogCh {

		tags := &logItem.Tags
		domain := ""
		for _, tag := range *tags {
			if tag.Key == "domain" && tag.Value != "" {
				domain = tag.Value
				break
			}
		}
		if domain == "" {
			continue
		}

		for _, tag := range *tags {
			if tag.Key == "domain" || tag.Value == "" {
				continue
			}

			q := "INSERT INTO `dns` (_domain, _ip) VALUES (?, ?);"
			insert, _ := db.Prepare(q)
			_, _ = insert.Exec(domain, tag.Value)
			insert.Close()
		}
	}
	log.Printf("Stop dns inserter routine %d, insert %d log with %d tag\n", goroutine, logCnt, tagCnt)
}
