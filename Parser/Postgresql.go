package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type PostgresqlNetState struct {
	Host string
	Port int
}

type PostgresqlLog struct {
	Timestamp int64
	Host      string
	Port      int
	Action    string
	Cmd       string
}

func getPostgresqlHostAndPort(line string) (string, PostgresqlNetState) {

	reg := regexp.MustCompile("\\[([0-9]+)] LOG: +connection received: host=(.*) port=([0-9]+)")
	match := reg.FindStringSubmatch(line)
	if len(match) > 0 {
		id := match[1]
		host := match[2]
		port, err := strconv.Atoi(match[3])
		if err != nil {
			log.Fatal(err)
		}
		return id, PostgresqlNetState{host, port}
	}
	return "", PostgresqlNetState{"", 0}
}

func readPostgresqlLog(name string) ([]string, map[string]PostgresqlNetState) {
	var lines []string
	var netMap = make(map[string]PostgresqlNetState)
	f, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
		return lines, netMap
	}
	reader := bufio.NewReader(f)
	for {
		s, err := reader.ReadString('\n')
		if err == io.EOF {
			return lines, netMap
		} else if err != nil {
			log.Fatal(err)
			return lines, netMap
		}

		if strings.Contains(s, "statement:") {
			lines = append(lines, s)
			continue
		}

		if strings.Contains(s, "connection received") {
			id, net := getPostgresqlHostAndPort(s)
			netMap[id] = net
			continue
		}

		if !strings.Contains(s, "LOG:") {
			lines[len(lines)-1] += s
			continue
		}
	}
}

func getPostgresqlId(line string) string {
	reg := regexp.MustCompile("\\[([0-9]+)] LOG")
	match := reg.FindStringSubmatch(line)
	if len(match) > 0 {
		id := match[1]
		return id
	}
	return ""
}

func getPostgresqlTimeStamp(line string) int64 {
	reg := regexp.MustCompile("[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+\\.[0-9]+")
	const form = "2006-01-02 15:04:05.000"
	s := reg.FindString(line)
	t, err := time.Parse(form, s)
	if err != nil {
		log.Fatal(err)
		return -1
	}
	return t.Unix()
}

var actionPatterns = map[string]string{

	"CREATE DATABASE +([^ \n;]*)": "CREATE DATABASE",
	"ALTER DATABASE +([^ \n;]*)":  "ALTER DATABASE",
	"DROP DATABASE +([^ \n;]*)":   "DROP DATABASE",

	"CREATE TABLE +([^ \n(;]*)": "CREATE TABLE",
	"ALTER TABLE +([^ \n;]*)":   "ALTER TABLE",
	"DROP TABLE +([^ \n;]*)":    "DROP TABLE",

	"INSERT INTO +([^ \n;]*)":    "INSERT DATA",
	"UPDATE +([^\n;]*) SET":      "UPDATE DATA",
	"DELETE FROM +([^ \n;]*)":    "DELETE DATA",
	"TRUNCATE TABLE +([^ \n;]*)": "TRUNCATE TABLE",

	"SELECT .* FROM +([^ \n;]*)":         "SELECT",
	"COPY .* FROM PROGRAM '+([^ \n;]*)'": "COPY",
}

func getPostgresqlActionAndCmd(line string) (string, string) {
	for k, v := range actionPatterns {
		reg := regexp.MustCompile(k)
		match := reg.FindStringSubmatch(line)
		if len(match) > 0 {
			cmd := match[1]
			return v, cmd
		}
	}
	return "", ""
}

func ParsePostgresqlLine(line string, netMap map[string]PostgresqlNetState) []PostgresqlLog {
	var id = getPostgresqlId(line)
	var result []PostgresqlLog
	lines := strings.Split(line, ";")
	for _, subLine := range lines {
		action, cmd := getPostgresqlActionAndCmd(subLine)
		if len(action) >= 0 {
			var parsedLine = PostgresqlLog{
				Timestamp: getPostgresqlTimeStamp(line),
				Host:      netMap[id].Host,
				Port:      netMap[id].Port,
				Action:    action,
				Cmd:       cmd,
			}
			result = append(result, parsedLine)
		}
	}
	return result
}

func WritePostgresqlResult(name string, lines []PostgresqlLog) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
		return err
	}
	js, err := json.Marshal(lines)
	if err != nil {
		log.Fatal(err)
		return err
	}
	s := string(js)
	s = strings.ReplaceAll(s, "\\u003c", "<")
	s = strings.ReplaceAll(s, "\\u003e", ">")
	s = strings.ReplaceAll(s, "\\u0026", "&")
	_, err = f.WriteString(s)
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

func parsePostgresql(inputName string, outputName string) {
	var lines, netMap = readPostgresqlLog(inputName)
	var parsedLines []PostgresqlLog
	for _, j := range lines {
		rec := ParsePostgresqlLine(j, netMap)
		for _, k := range rec {
			parsedLines = append(parsedLines, k)
		}
	}
	err := WritePostgresqlResult(outputName, parsedLines)
	if err != nil {
		log.Fatal(err)
	}
}
