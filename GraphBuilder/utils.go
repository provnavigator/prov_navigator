package main

import (
	"HHPG"
	"HHPG/CLF"
	"database/sql"
	"fmt"
	"github.com/awalterschulze/gographviz"
	"log"
	"os"
	"strconv"
	"strings"
)

var LogtypePrefixMap = map[string]string{
	"auditd":         "audit",
	"MiniHttpd":      "minihttpd",
	"Network":        "network",
	"SecurityEvents": "securityEvents",
	"Firefox":        "firefox",
	"PostgreSql":     "psql",
	"Proftpd":        "proftpd",
	"Nginx":          "nginx",
	"Apache":         "apache",
	"Redis":          "redis",
	"Vim":            "vim",
	"Openssh":        "openssh",
	"ImageMagick":    "ImageMagick",
}

func addquotation(str string) string {
	return fmt.Sprintf("%q", str)
}

func getShape(str string, log_type string, nodeLoc string) string {
	if log_type == "auditd" || log_type == "SecurityEvents" {
		if strings.HasPrefix(str, "file") {
			return "ellipse"
		}
		if strings.HasPrefix(str, "process") {
			return "box"
		}
		if strings.HasPrefix(str, "socket") {
			return "diamond"
		}
	}
	if log_type == "Network" {
		return "diamond"
	}
	if log_type == "MiniHttpd" {
		if nodeLoc == "start" {
			return "diamond"
		} else {
			return "ellipse"
		}
	}
	if log_type == "Firefox" {
		if nodeLoc == "start" {
			return "box"
		} else {
			return "ellipse"
		}
	}
	if log_type == "PostgreSql" {
		if strings.Contains(str, "PostgreSQL.exe") {
			return "box"
		} else {
			return "diamond"
		}
	}
	return string("")
}

func UpdateNetwork() {

	db, err := sql.Open("sqlite3", CLF.SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}
	sel := "update `log` set log_type=? where log_type=?;"
	db.Exec(sel, HHPG.Dataset, "Network")

}

func FindNeighbors(id int) [][]string {

	var neighborLns [][]string

	db, err := sql.Open("sqlite3", CLF.SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	sel := "select `_time`, `_key`, `_value` from `log`,`r_log_tag`,`tag` where `log`.rowid=`r_log_tag`.log_id and `tag`.rowid=`r_log_tag`.tag_id and `log`.rowid=?;"
	row, err := db.Query(sel, id)
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		var key, value, time string
		for row.Next() {
			row.Scan(&time, &key, &value)
			var neighborLn = []string{time, key, value}
			neighborLns = append(neighborLns, neighborLn)
		}
	}
	return neighborLns
}

func BuildCorrelations(graph *gographviz.Graph, id int, neighborLns [][]string, log_type string, key_prefix string) {

	flag := 0
	var start, end, time string
	str := string("")
	for _, neighborLn := range neighborLns {
		time = neighborLn[0]
		key, value := neighborLn[1], neighborLn[2]
		key_start := key_prefix + "_start"
		key_end := key_prefix + "_end"
		if key == key_start {
			start = value
			flag += 1
		}
		if key == key_end {
			end = value
			flag += 1
		}
		if key != key_start && key != key_end && key != "time" && key != "Date and Time" {
			str = str + key + string(":") + value + string("\n")
		}
	}
	if flag == 2 {
		str = string("log_id:") + strconv.Itoa(id) + string("\n") + str
		str = string("time:") + time + string("\n") + str

		if log_type == "Network" {
			str = str + string("data_source:") + HHPG.Dataset + string("\n")
		} else {
			str = str + string("data_source:") + log_type + string("\n")
		}

		m := make(map[string]string)
		m["label"] = addquotation(str)

		start_m := make(map[string]string)
		start_m["shape"] = addquotation(getShape(start, log_type, "start"))
		end_m := make(map[string]string)
		end_m["shape"] = addquotation(getShape(end, log_type, "end"))

		start = addquotation(start)
		end = addquotation(end)

		graph.AddNode("G", start, start_m)
		graph.AddNode("G", end, end_m)
		graph.AddEdge(start, end, true, m)
	}
}

func ConstructHHPG(dotName string) error {

	graphAst, _ := gographviz.Parse([]byte(`digraph G{}`))
	graph := gographviz.NewGraph()
	gographviz.Analyse(graphAst, graph)

	db, err := sql.Open("sqlite3", CLF.SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	for log_type, key_prefix := range LogtypePrefixMap {
		s := "SELECT `rowid` FROM `log` WHERE log_type=?;"
		r, err := db.Query(s, log_type)
		defer r.Close()
		if err != nil {
			fmt.Printf("err: %v\n", err)
		} else {
			for r.Next() {
				var id int
				r.Scan(&id)
				if id%10000 == 0 {
					fmt.Println("id = ", id)
				}

				neighborLns := FindNeighbors(id)
				BuildCorrelations(graph, id, neighborLns, log_type, key_prefix)
			}
		}
	}

	fo, err := os.OpenFile(dotName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer fo.Close()

	fo.WriteString(graph.String())

	UpdateNetwork()

	return nil
}

func ParseTags(key string, value string) (string, map[string]string) {
	tagNode := key + string("=") + value
	tagNode_m := make(map[string]string)
	tagNode_m["label"] = addquotation(tagNode)
	tagNode_m["shape"] = addquotation("ellipse")
	tagNode = addquotation(tagNode)

	return tagNode, tagNode_m
}

func AddConnection(graph *gographviz.Graph, logNode string, tagNode string) {
	graph.AddEdge(logNode, tagNode, true, nil)
}

func ConstructCLG(dotName string) error {

	graphAst, _ := gographviz.Parse([]byte(`digraph G{}`))
	graph := gographviz.NewGraph()
	gographviz.Analyse(graphAst, graph)

	db, err := sql.Open("sqlite3", CLF.SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	s := "select `log_id`, `log_raw`, `log_type`, `_key`, `_value` from `log`,`r_log_tag`,`tag` where `log`.rowid=`r_log_tag`.log_id and `tag`.rowid=`r_log_tag`.tag_id;"
	r, err := db.Query(s)
	defer r.Close()
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		for r.Next() {
			var log_id int
			var log_raw, log_type, key, value string
			r.Scan(&log_id, &log_raw, &log_type, &key, &value)
			if strings.HasSuffix(key, "start") || strings.HasSuffix(key, "end") {
				continue
			}

			logLabel := string("log_raw:") + log_raw + string("\n") + string("log_type:") + log_type + string("\n")
			logNode := string("log_id:") + strconv.Itoa(log_id)
			logNode_m := make(map[string]string)
			logNode_m["label"] = addquotation(logLabel)
			logNode_m["shape"] = addquotation("box")
			logNode = addquotation(logNode)

			graph.AddNode("G", logNode, logNode_m)

			tagNode, tagNode_m := ParseTags(key, value)

			graph.AddNode("G", tagNode, tagNode_m)

			AddConnection(graph, logNode, tagNode)

		}
	}

	fo, err := os.OpenFile(dotName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer fo.Close()

	fo.WriteString(graph.String())

	return nil
}
