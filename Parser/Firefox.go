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

type HttpLog struct {
	Timestamp    int64
	Host         string
	Query        string
	HttpType     string
	ResponseCode int
	Referer      string `clf:"referer"`
	Location     string `clf:"location"`
}

func readHttpLog(name string) []string {
	var lines []string
	f, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
		return lines
	}
	reader := bufio.NewReader(f)
	var enter = false
	var line = ""
	for {
		s, err := reader.ReadString('\n')
		if err == io.EOF {
			return lines
		} else if err != nil {
			log.Fatal(err)
			return lines
		}

		if strings.Contains(s, "uri=http") {
			lines = append(lines, s)
			continue
		}
		s = strings.TrimSpace(s)
		s = strings.ReplaceAll(s, "'", "")
		s = strings.ReplaceAll(s, "\"", "")

		if strings.Contains(s, "http response [") || strings.Contains(s, "http request [") {
			line = s
			enter = true
		} else if enter {
			line = line + "\n" + s
			if strings.Contains(s, " ]") {
				enter = false
				lines = append(lines, line)
			}
		}
	}
}

func getTimeStamp(line string) int64 {
	reg := regexp.MustCompile("[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+\\.[0-9]+")
	const form = "2006-01-02 15:04:05.000000"
	s := reg.FindString(line)
	t, err := time.Parse(form, s)
	if err != nil {
		log.Fatal(err)
		return -1
	}
	return t.Unix()
}

func getHost(line string) string {

	reg := regexp.MustCompile(" Host: ([^\n]*)\n")
	match := reg.FindStringSubmatch(line)
	if len(match) > 0 {
		host := match[1]

		return host
	}

	reg = regexp.MustCompile(" Location: ([^\n]*)\n")
	match = reg.FindStringSubmatch(line)
	if len(match) > 0 {
		host := match[1]
		if len(host) > 0 && host[len(host)-1] == ']' {
			host = strings.TrimRight(host, "]")
		}
		if strings.Contains(host, "://") {
			host = strings.Split(host, "://")[1]
		}
		host = strings.Split(host, "/")[0]

		return host
	}
	return ""
}

func getQuery(line string) string {

	if strings.Contains(line, "uri=http") && strings.Contains(line, "://") {
		query := strings.Split(line, "://")[1]
		if len(query) > 0 {
			query = strings.Split(query, " ")[0]
			query = strings.Split(query, "\n")[0]
			query = strings.TrimSpace(query)
			if len(query) > 0 && query[len(query)-1] == ']' {
				query = strings.TrimRight(query, "]")
			}
			if len(query) > 0 && query[len(query)-1] == '/' {
				query = strings.TrimRight(query, "/")
			}
			return query
		}
		return ""
	}

	reg := regexp.MustCompile("GET ([^\n]*) HTTP")
	match := reg.FindStringSubmatch(line)
	if len(match) > 0 {
		query := match[1]
		if len(query) > 0 && query[len(query)-1] == ']' {
			query = strings.TrimRight(query, "]")
		}

		query = strings.ReplaceAll(query, ",", "")
		return query
	}

	reg = regexp.MustCompile("POST ([^\n]*) HTTP")
	match = reg.FindStringSubmatch(line)
	if len(match) > 0 {
		query := match[1]
		tmp := strings.SplitN(query, "/", 1)
		if len(tmp) > 0 {
			query = tmp[0]
		} else {
			query = ""
		}
		if len(query) > 0 && query[len(query)-1] == ']' {
			query = strings.TrimRight(query, "]")
		}
		query = strings.ReplaceAll(query, ",", "")
		return query
	}
	return ""
}

func getHttpType(line string) string {

	if strings.Contains(line, "uri=http") {
		return "Request"
	}

	if strings.Contains(line, "http request [") {
		return "Request"
	} else {
		return "Response"
	}
}

func getResponseCode(line string) int {
	reg := regexp.MustCompile("HTTP/[0-9]\\.[0-9] ([0-9]+) ")
	match := reg.FindStringSubmatch(line)
	if len(match) > 0 {
		val, err := strconv.Atoi(match[1])
		if err != nil {
			log.Fatal(err)
		}
		return val
	}
	return 0
}

func getReferer(line string) string {
	reg := regexp.MustCompile(" Referer: ([^\n]*)\n")
	match := reg.FindStringSubmatch(line)
	if len(match) > 0 {
		ref := match[1]
		if strings.Contains(ref, "://") {
			ref = strings.Split(ref, "://")[1]
		}
		if len(ref) > 0 && ref[len(ref)-1] == '/' {
			ref = strings.TrimRight(ref, "/")
		}
		ref = strings.ReplaceAll(ref, ",", "")
		return ref
	}
	return ""
}

func getLocation(line string) string {
	reg := regexp.MustCompile(" Location: ([^\n]*)\n")
	match := reg.FindStringSubmatch(line)
	if len(match) > 0 {
		location := match[1]
		if strings.Contains(location, "://") {
			location = strings.Split(location, "://")[1]
		}
		if len(location) > 0 && location[len(location)-1] == '/' {
			location = strings.TrimRight(location, "/")
		}
		location = strings.ReplaceAll(location, ",", "")
		return location
	}
	return ""
}

func parseHttpLine(line string) HttpLog {
	var parsedLine = HttpLog{
		Timestamp:    getTimeStamp(line),
		Host:         getHost(line),
		Query:        getQuery(line),
		HttpType:     getHttpType(line),
		ResponseCode: getResponseCode(line),
		Referer:      getReferer(line),
		Location:     getLocation(line),
	}
	return parsedLine
}

func writeResult(name string, lines []HttpLog) error {
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

func parseHttp(inputName string, outputName string) {
	var lines = readHttpLog(inputName)
	var parsedLines []HttpLog
	for _, j := range lines {
		parsedLines = append(parsedLines, parseHttpLine(j))
	}
	err := writeResult(outputName, parsedLines)
	if err != nil {
		log.Fatal(err)
	}
}
