package CLF

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
)

func DBPrepare() {
	if SQLITE_FILE != ":memory:" {
		log.Printf("Clean Up Database...\n")
		e := os.Remove(SQLITE_FILE)
		if e != nil {
			log.Printf("SQL file not exists...\n")
		}
		e = os.Remove(SQLITE_FILE + "-journal")
		if e != nil {
			log.Printf("SQL file journal not exists...\n")
		}
	}
	db, err := sql.Open("sqlite3", SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	sql_table := `
create table if not exists log
(
_time    timestamp(3)           not null,
log_raw  text                   null,
log_type TEXT default '' not null
);
create table if not exists tag
(
_key   TEXT   not null,
_value TEXT  not null,
_type  int default 0 not null,
constraint tag_kvt_index
unique (_key, _value, _type)
);
create table r_log_tag
(
log_id int  not null,
tag_id int  not null,
constraint r_log_tag_id_index
unique (log_id, tag_id),
constraint r_log_tag_log_id_fk
foreign key (log_id) references log (rowid)
on delete cascade,
constraint r_log_tag_tag_id_fk
foreign key (tag_id) references tag (rowid)
on delete cascade
);
create table if not exists dns
(
_domain   TEXT   not null,
_ip TEXT  not null,
constraint r_dns
unique (_domain, _ip)
);
	`
	_, err = db.Exec(sql_table)
	if err != nil {
		panic(err)
	}
}

type Inserter struct {
	ParsedLogCh *chan ParsedLog
}

func (pi *Inserter) Insert(goroutine int) {
	log.Printf("Start inserter routine %d\n", goroutine)
	db, err := sql.Open("sqlite3", SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}
	logCnt := 0
	tagCnt := 0
	for logItem := range *pi.ParsedLogCh {

		l := &logItem.Log
		tags := &logItem.Tags

		q := "INSERT INTO `log` (_time, log_raw, log_type) VALUES (?, ?, ?);"
		insert, err := db.Prepare(q)
		if err != nil {
			panic(err)
		}

		resp, err := insert.Exec(l.timestampString(), l.LogRaw, l.LogType)
		insert.Close()

		lastInsertLogId, err := resp.LastInsertId()
		if err != nil {
			fmt.Println(err)
			continue
		}

		l.ID = lastInsertLogId
		logCnt++
		for idx, tag := range *tags {
			q := "INSERT INTO `tag` (_key, _value, _type) VALUES (?, ?, ?);"
			insert, _ := db.Prepare(q)
			resp, err = insert.Exec(tag.Key, tag.Value, tag.Type)
			insert.Close()

			var tagId int64 = -1
			if err == nil {
				tagId, _ = resp.LastInsertId()
			} else {
				qu := "SELECT `rowid` FROM `tag` WHERE _key = ? AND _value= ?;"
				row := db.QueryRow(qu, tag.Key, tag.Value)
				err = row.Scan(&tagId)
				if err != nil {
					panic(err)
				}
			}
			if tagId == -1 {
				panic("no tag id")
			}

			(*tags)[idx].ID = tagId

			q = "INSERT INTO `r_log_tag` (log_id, tag_id) VALUES (?, ?);"
			insert, _ = db.Prepare(q)
			resp, err = insert.Exec(l.ID, tagId)
			insert.Close()

			if err != nil {

			}
			tagCnt++
		}
	}
	log.Printf("Stop inserter routine %d, insert %d log with %d tag\n", goroutine, logCnt, tagCnt)
}
