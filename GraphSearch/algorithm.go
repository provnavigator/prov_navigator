package main

import (
	"HHPG"
	"HHPG/CLF"
	"database/sql"
	"fmt"
	"github.com/awalterschulze/gographviz"
	mapset "github.com/deckarep/golang-set"
	"gopkg.in/eapache/queue.v1"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var Audit = map[string]string{
	"ATLAS/S1":    "SecurityEvents",
	"ATLAS/S2":    "SecurityEvents",
	"ATLAS/S3":    "SecurityEvents",
	"ATLAS/S4":    "SecurityEvents",
	"MiniHttpd":   "auditd",
	"PostgreSql":  "auditd",
	"Proftpd":     "auditd",
	"Nginx":       "auditd",
	"Apache":      "auditd",
	"Redis":       "auditd",
	"Vim":         "auditd",
	"APT/S1":      "auditd",
	"APT/S1-1":    "auditd",
	"APT/S1-2":    "auditd",
	"APT/S2":      "auditd",
	"Openssh":     "auditd",
	"ImageMagick": "auditd",
	"php":         "auditd",
}

var App = map[string]string{
	"ATLAS/S1":    "Firefox",
	"ATLAS/S2":    "Firefox",
	"ATLAS/S3":    "Firefox",
	"ATLAS/S4":    "Firefox",
	"MiniHttpd":   "MiniHttpd",
	"PostgreSql":  "PostgreSql",
	"Proftpd":     "Proftpd",
	"Nginx":       "Nginx",
	"Apache":      "Apache",
	"Redis":       "Redis",
	"Vim":         "Vim",
	"APT/S1":      "APT/S1",
	"APT/S1-1":    "APT/S1-1",
	"APT/S1-2":    "APT/S1-2",
	"APT/S2":      "APT/S2",
	"Openssh":     "Openssh",
	"ImageMagick": "ImageMagick",
	"php":         "php",
}

var DEProcesses = map[string][]string{
	"ATLAS/S1":    {"firefox.exe"},
	"ATLAS/S2":    {"firefox.exe"},
	"ATLAS/S3":    {"firefox.exe"},
	"ATLAS/S4":    {"firefox.exe"},
	"MiniHttpd":   {"/usr/local/sbin/mini_httpd"},
	"PostgreSql":  {"/usr/local/pgsql/bin/postgres"},
	"Proftpd":     {"/usr/local/sbin/proftpd"},
	"Nginx":       {"/usr/sbin/nginx"},
	"Apache":      {"/usr/local/apache2/bin/httpd"},
	"Redis":       {"/usr/bin/redis-check-rdb"},
	"Vim":         {"/usr/local/bin/vim"},
	"APT/S1":      {"/usr/sbin/apache2", "/usr/local/sbin/proftpd"},
	"APT/S2":      {"/usr/bin/python3.8"},
	"Openssh":     {"/usr/local/sbin/sshd"},
	"ImageMagick": {"/usr/local/bin/magick"},
	"php":         {"/usr/sbin/apache2"},
}

func GetMaliciousNodes() map[string]string {
	maliciousNodes := make(map[string]string)
	maliciousNodes["ATLAS/S1"] = "\"socket_src#192.168.223.128:49319\\nsocket_dst#192.168.223.3:8080\""
	maliciousNodes["ATLAS/S2"] = "\"socket_src#192.168.223.128:65414\\nsocket_dst#192.168.223.3:8080\""
	maliciousNodes["ATLAS/S3"] = "\"file#C:\\\\Users\\\\aalsahee\\\\Downloads\\\\msf.rtf\""
	maliciousNodes["ATLAS/S4"] = "\"file#C:\\\\Users\\\\aalsahee\\\\Downloads\\\\msf.doc\""
	maliciousNodes["MiniHttpd"] = "\"file#/etc/passwd\""
	maliciousNodes["PostgreSql"] = "\"file#/etc/localtime\""
	maliciousNodes["Proftpd"] = "\"file#/evil.txt\""
	maliciousNodes["Nginx"] = "\"file#/files../etc/passwd\""
	maliciousNodes["Apache"] = "\"file#/etc/passwd\""
	maliciousNodes["Redis"] = "\"file#/etc/passwd\""
	maliciousNodes["Vim"] = "\"process#11408\""
	maliciousNodes["Openssh"] = "\"process#17663\""
	maliciousNodes["ImageMagick"] = "\"file#img/poc.png\""
	maliciousNodes["php"] = "\"file#/opt/ftp/attackk.sh\""
	maliciousNodes["APT/S1"] = "\"file#/opt/ftp/attackk.sh\""
	maliciousNodes["APT/S1-1"] = "\"file#/opt/ftp/attackk.sh\""
	maliciousNodes["APT/S1-2"] = "\"file#/opt/ftp/attackk.sh\""
	maliciousNodes["APT/S2"] = "\"file#/etc/crontab\""
	return maliciousNodes
}

func IsDENode(graph *gographviz.Graph, node string) bool {
	for _, process := range DEProcesses[HHPG.Dataset] {

		nodeSet := mapset.NewSet()

		for _, edge := range graph.Edges.Edges {
			tags := strings.Split(edge.Attrs["label"][1:len(edge.Attrs["label"])-1], "\\n")
			tags = tags[:len(tags)-1]
			for _, tag := range tags {
				if strings.HasPrefix(tag, "src_exec") && strings.Split(tag, ":")[1] == process {
					nodeSet.Add(edge.Src)
				}
				if strings.HasPrefix(tag, "dst_exec") && strings.Split(tag, ":")[1] == process {
					nodeSet.Add(edge.Dst)
				}
				if strings.HasPrefix(tag, "Process Name") && strings.Split(tag, ":")[1] == process {
					if strings.HasPrefix(edge.Src, "\"process#") {
						nodeSet.Add(edge.Src)
					}
					if strings.HasPrefix(edge.Dst, "\"process#") {
						nodeSet.Add(edge.Dst)
					}
				}
			}
		}

		ansNode, depLen := string(""), 0
		for _, curNode := range nodeSet.ToSlice() {
			if GetDependencyLen(graph, curNode.(string)) > depLen {
				ansNode = curNode.(string)
				depLen = GetDependencyLen(graph, curNode.(string))
			}
		}
		if ansNode == node {
			return true
		}
	}
	return false
}

func GetPath() (string, string) {
	dotPath, subDotPath := string(""), string("")
	if strings.Contains(HHPG.Dataset, "ATLAS") || strings.Contains(HHPG.Dataset, "APT") {
		datasetName := strings.Split(HHPG.Dataset, "/")[1]
		dotPath = "Graphs/" + HHPG.Dataset + "/" + datasetName + ".dot"
		subDotPath = "Graphs/" + HHPG.Dataset + "/" + datasetName + "-subgraph.dot"
	} else {
		dotPath = "Graphs/" + HHPG.Dataset + "/" + HHPG.Dataset + ".dot"
		subDotPath = "Graphs/" + HHPG.Dataset + "/" + HHPG.Dataset + "-subgraph.dot"
	}
	return dotPath, subDotPath
}

func BuildNewGraph() *gographviz.Graph {
	graphAst, _ := gographviz.Parse([]byte(`digraph G{}`))
	newGraph := gographviz.NewGraph()
	gographviz.Analyse(graphAst, newGraph)
	return newGraph
}

func GetGraph(dotPath string) *gographviz.Graph {
	f, err := os.ReadFile(dotPath)
	if err != nil {
		panic(err)
	}
	graph, err := gographviz.Read(f)
	if err != nil {
		panic(err)
	}
	return graph
}

func WriteGraph(graph *gographviz.Graph, dotPath string) {
	fo, err := os.OpenFile(dotPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	defer fo.Close()

	fo.WriteString(graph.String())
}

func GetEdgesMap(graph *gographviz.Graph) map[int]*gographviz.Edge {
	edgesMap := make(map[int]*gographviz.Edge)
	for _, edge := range graph.Edges.Edges {
		edgesMap[GetLogId(edge)] = edge
	}
	return edgesMap
}

func GetLogId(edge *gographviz.Edge) int {
	tags := strings.Split(edge.Attrs["label"][1:len(edge.Attrs["label"])-1], "\\n")
	tags = tags[:len(tags)-1]
	for _, tag := range tags {
		if strings.HasPrefix(tag, "log_id") {
			logId, _ := strconv.Atoi(strings.Split(tag, ":")[1])
			return logId
		}
	}
	return -1
}

func GetTime(edge *gographviz.Edge) string {
	tags := strings.Split(edge.Attrs["label"][1:len(edge.Attrs["label"])-1], "\\n")
	tags = tags[:len(tags)-1]
	for _, tag := range tags {
		if strings.HasPrefix(tag, "time") {
			time := tag[len("time:"):]
			return time
		}
	}
	return ""
}

func CompareTime(time1 string, time2 string) int {
	t1, err := time.Parse("2006-01-02 15:04:05.000", time1)
	t2, err := time.Parse("2006-01-02 15:04:05.000", time2)
	if err == nil {
		if t1.Before(t2) {
			return -1
		}
		if t1.Equal(t2) {
			return 0
		}
		if t1.After(t2) {
			return 1
		}
	}
	return 0
}

func GetDataSource(edge *gographviz.Edge) string {
	tags := strings.Split(edge.Attrs["label"][1:len(edge.Attrs["label"])-1], "\\n")
	tags = tags[:len(tags)-1]
	for _, tag := range tags {
		if strings.HasPrefix(tag, "data_source") {
			dataSource := strings.Split(tag, ":")[1]
			return dataSource
		}
	}
	return ""
}

func GetEntityDataSource(graph *gographviz.Graph, node string) string {
	for _, edges := range graph.Edges.SrcToDsts[node] {
		for _, edge := range edges {
			if GetDataSource(edge) == Audit[HHPG.Dataset] {
				return Audit[HHPG.Dataset]
			}
		}
	}
	for _, edges := range graph.Edges.DstToSrcs[node] {
		for _, edge := range edges {
			if GetDataSource(edge) == Audit[HHPG.Dataset] {
				return Audit[HHPG.Dataset]
			}
		}
	}
	return App[HHPG.Dataset]
}

func GetCorrelatedEdges(edge *gographviz.Edge, logType string, edgesMap map[int]*gographviz.Edge, isExist bool) []*gographviz.Edge {

	logId := GetLogId(edge)

	idSet := mapset.NewSet()

	db, err := sql.Open("sqlite3", CLF.SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	s := "SELECT `tag_id` FROM `r_log_tag` WHERE log_id=?;"
	r, err := db.Query(s, logId)
	defer r.Close()
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		for r.Next() {
			var tagId int
			r.Scan(&tagId)

			sel := "SELECT `log_id` FROM `log`, `r_log_tag` WHERE `log`.rowid=`r_log_tag`.log_id and tag_id=? and log_type=?;"
			row, err := db.Query(sel, tagId, logType)
			if err != nil {
				fmt.Printf("err: %v\n", err)
			} else {
				for row.Next() {
					var id int
					row.Scan(&id)
					idSet.Add(id)
					if isExist {
						var retIds = []*gographviz.Edge{edgesMap[id]}
						return retIds
					}
				}
			}

			if logType == App[HHPG.Dataset] {
				sel = ` SELECT DISTINCT r_log_tag.log_id
					FROM tag as tag1, dns, tag as tag2, r_log_tag, log
					WHERE tag2.rowid = ? AND tag1._key = 'host' AND tag1._value = dns._domain 
					  AND dns._ip = tag2._value AND tag1.rowid = r_log_tag.tag_id 
					  AND r_log_tag.log_id = log.rowid AND log.log_type = ?;`
			} else if logType == Audit[HHPG.Dataset] {
				sel = ` SELECT DISTINCT r_log_tag.log_id
					FROM tag as tag1, dns, tag as tag2, r_log_tag, log
					WHERE tag1.rowid = ? AND tag1._key = 'host' AND tag1._value = dns._domain 
					  AND dns._ip = tag2._value AND tag2.rowid = r_log_tag.tag_id 
					  AND r_log_tag.log_id = log.rowid AND log.log_type = ?;`
			}

			row, err = db.Query(sel, tagId, logType)
			if err != nil {
				fmt.Printf("err: %v\n", err)
			} else {
				for row.Next() {
					var id int
					row.Scan(&id)
					idSet.Add(id)
				}
			}
		}
	}
	var ret = idSet.ToSlice()
	var retIds []*gographviz.Edge
	for _, id := range ret {
		if edgesMap[id.(int)] != nil {
			retIds = append(retIds, edgesMap[id.(int)])
		}
	}
	return retIds
}

func GetDetailedCR(appList []*gographviz.Edge, auditLogIdSet mapset.Set) (int, int) {
	db, err := sql.Open("sqlite3", CLF.SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}

	idSet := mapset.NewSet()
	edgeAuditCR, edgeAppCR := 0, 0
	logType := Audit[HHPG.Dataset]

	for _, edge := range appList {
		logId := GetLogId(edge)
		flag := false

		s := "SELECT `tag_id` FROM `r_log_tag` WHERE log_id=?;"
		r, err := db.Query(s, logId)
		defer r.Close()
		if err != nil {
			fmt.Printf("err: %v\n", err)
		} else {
			for r.Next() {
				var tagId int
				r.Scan(&tagId)

				sel := "SELECT `log_id` FROM `log`, `r_log_tag` WHERE `log`.rowid=`r_log_tag`.log_id and tag_id=? and log_type=?;"
				row, err := db.Query(sel, tagId, logType)
				if err != nil {
					fmt.Printf("err: %v\n", err)
				} else {
					for row.Next() {
						var id int
						row.Scan(&id)
						idSet.Add(id)
						flag = true
					}
				}

				if logType == App[HHPG.Dataset] {
					sel = ` SELECT DISTINCT r_log_tag.log_id
					FROM tag as tag1, dns, tag as tag2, r_log_tag, log
					WHERE tag2.rowid = ? AND tag1._key = 'host' AND tag1._value = dns._domain 
					  AND dns._ip = tag2._value AND tag1.rowid = r_log_tag.tag_id 
					  AND r_log_tag.log_id = log.rowid AND log.log_type = ?;`
				} else if logType == Audit[HHPG.Dataset] {
					sel = ` SELECT DISTINCT r_log_tag.log_id
					FROM tag as tag1, dns, tag as tag2, r_log_tag, log
					WHERE tag1.rowid = ? AND tag1._key = 'host' AND tag1._value = dns._domain 
					  AND dns._ip = tag2._value AND tag2.rowid = r_log_tag.tag_id 
					  AND r_log_tag.log_id = log.rowid AND log.log_type = ?;`
				}

				row, err = db.Query(sel, tagId, logType)
				if err != nil {
					fmt.Printf("err: %v\n", err)
				} else {
					for row.Next() {
						var id int
						row.Scan(&id)
						idSet.Add(id)
						flag = true
					}
				}
			}
		}

		if flag {
			edgeAppCR++
		}
	}
	ret := idSet.ToSlice()
	for _, id := range ret {
		if auditLogIdSet.Contains(id.(int)) {
			edgeAuditCR++
		}
	}

	return edgeAuditCR, edgeAppCR
}

func IsConnected(auditEndEdge *gographviz.Edge, originEdge *gographviz.Edge, graph *gographviz.Graph) bool {
	if auditEndEdge == nil || originEdge == nil {
		return false
	}

	edgeQueue := queue.New()
	edgeQueue.Add(auditEndEdge)
	var nodeNum int = 0
	for {
		nodeNum++
		if edgeQueue.Length() == 0 || nodeNum > 100 {
			break
		}
		edge := edgeQueue.Remove().(*gographviz.Edge)
		if edge.Dst == originEdge.Src {
			return true
		}
		for _, nextEdges := range graph.Edges.SrcToDsts[edge.Dst] {
			for _, nextEdge := range nextEdges {
				if GetDataSource(nextEdge) == Audit[HHPG.Dataset] {
					edgeQueue.Add(nextEdge)
				}
			}
		}
	}
	return false
}

func SearchForSpp(edge *gographviz.Edge, originEdge *gographviz.Edge, graph *gographviz.Graph, edgesMap map[int]*gographviz.Edge) [][]*gographviz.Edge {

	var sppsList [][]*gographviz.Edge
	correlatedAppEdges := GetCorrelatedEdges(edge, App[HHPG.Dataset], edgesMap, false)
	for _, appStartEdge := range correlatedAppEdges {

		edgeQueue := queue.New()
		edgeQueue.Add(appStartEdge)
		for {

			if edgeQueue.Length() == 0 {
				break
			}
			appEndEdge := edgeQueue.Remove().(*gographviz.Edge)
			correlatedAuditEdges := GetCorrelatedEdges(appEndEdge, Audit[HHPG.Dataset], edgesMap, false)
			for _, auditEndEdge := range correlatedAuditEdges {

				if auditEndEdge == originEdge {
					continue
				}
				if auditEndEdge.Src == originEdge.Src || auditEndEdge.Src == originEdge.Dst {
					continue
				}
				if IsDENode(graph, auditEndEdge.Src) {
					continue
				}
				if CompareTime(GetTime(auditEndEdge), GetTime(originEdge)) <= 0 && IsConnected(auditEndEdge, originEdge, graph) {
					var spp = []*gographviz.Edge{appStartEdge, appEndEdge, edge, auditEndEdge}
					sppsList = append(sppsList, spp)

					MaxSppNum := 150000

					if len(sppsList) > MaxSppNum {
						return sppsList
					}
				}
			}

			appEndEdgeSrcNode := appEndEdge.Src
			for _, appEndEdges := range graph.Edges.DstToSrcs[appEndEdgeSrcNode] {
				for _, newAppEndEdge := range appEndEdges {
					if GetDataSource(newAppEndEdge) == App[HHPG.Dataset] {
						if newAppEndEdge.Src == appEndEdge.Src || newAppEndEdge.Src == appEndEdge.Dst {
							continue
						}
						edgeQueue.Add(newAppEndEdge)
					}
				}
			}
		}
	}
	return sppsList
}

func ProcessDependencyExplosion(originEdge *gographviz.Edge, graph *gographviz.Graph, edgesMap map[int]*gographviz.Edge, newGraph *gographviz.Graph) []*gographviz.Edge {
	edgeQueue := queue.New()
	edgeQueue.Add(originEdge)

	var sppsList [][]*gographviz.Edge

	var nodeNum int = 0
	nodeNumMax := 10
	for {
		nodeNum++

		if edgeQueue.Length() == 0 || nodeNum > nodeNumMax {
			if nodeNum > nodeNumMax && nodeNumMax < 5000 && len(sppsList) == 0 {
				nodeNumMax *= 2
			} else {
				break
			}
		}
		edge := edgeQueue.Remove().(*gographviz.Edge)

		var curSppsList [][]*gographviz.Edge

		curSppsList = SearchForSpp(edge, originEdge, graph, edgesMap)

		if len(curSppsList) > 0 {
			for _, spp := range curSppsList {
				sppsList = append(sppsList, spp)
			}
		}
		edgeDstNode := edge.Dst
		for _, newEdges := range newGraph.Edges.SrcToDsts[edgeDstNode] {
			for _, newEdge := range newEdges {
				edgeQueue.Add(newEdge)
			}
		}
	}
	return GetTopSPP(sppsList)
}

func GetScore(edge1 *gographviz.Edge, edge2 *gographviz.Edge, db *sql.DB) float64 {
	logId1 := GetLogId(edge1)
	logId2 := GetLogId(edge2)
	var tagList1 []int
	var tagList2 []int

	score := 0.0

	s := "SELECT `tag_id` FROM `r_log_tag` WHERE log_id=?;"
	r, err := db.Query(s, logId1)
	defer r.Close()
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		for r.Next() {
			var tagId int
			r.Scan(&tagId)
			tagList1 = append(tagList1, tagId)
		}
	}

	s = "SELECT `tag_id` FROM `r_log_tag` WHERE log_id=?;"
	r, err = db.Query(s, logId2)
	defer r.Close()
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		for r.Next() {
			var tagId int
			r.Scan(&tagId)
			tagList2 = append(tagList2, tagId)
		}
	}

	for _, tagId1 := range tagList1 {
		for _, tagId2 := range tagList2 {
			if tagId1 == tagId2 {

				logNum := 0.0
				s = "SELECT `log_id` FROM `r_log_tag` WHERE tag_id=?;"
				r, err = db.Query(s, tagId1)
				defer r.Close()
				if err != nil {
					fmt.Printf("err: %v\n", err)
				} else {
					for r.Next() {
						var logId int
						r.Scan(&logId)
						logNum += 1
					}
				}
				score += 1.0 / logNum
			}
		}
	}
	return score
}

func GetTopSPP(sppsList [][]*gographviz.Edge) []*gographviz.Edge {

	db, err := sql.Open("sqlite3", CLF.SQLITE_FILE)
	defer db.Close()
	if err != nil {
		panic(err)
	}
	if len(sppsList) > 0 {
		maxScore := 0.0
		maxIdx := 0
		for idx, spp := range sppsList {
			appStartEdge, appEndEdge, auditStartEdge, auditEndEdge := spp[0], spp[1], spp[2], spp[3]
			score := 0.0
			score += GetScore(appStartEdge, auditStartEdge, db)
			score += GetScore(appEndEdge, auditEndEdge, db)

			if score > maxScore {
				maxScore = score
				maxIdx = idx
			}
		}
		return sppsList[maxIdx]
	} else {
		return nil
	}
}

func IsExist(nodeQueue *queue.Queue, backwardNode string) bool {
	for i := 0; i < nodeQueue.Length(); i++ {
		if nodeQueue.Get(i).(string) == backwardNode {
			return true
		}
	}
	return false
}

func AddToNewGraphByTwoEdges(edgeStart *gographviz.Edge, edgeEnd *gographviz.Edge, graph *gographviz.Graph, newGraph *gographviz.Graph, logType string) {
	edgeQueue := queue.New()
	var initEdges []*gographviz.Edge
	initEdges = append(initEdges, edgeStart)
	edgeQueue.Add(initEdges)
	for {
		if edgeQueue.Length() == 0 {
			break
		}
		edges := edgeQueue.Remove().([]*gographviz.Edge)
		edge := edges[0]
		if edge == edgeEnd || edge.Dst == edgeEnd.Src {
			edges = append([]*gographviz.Edge{edgeEnd}, edges...)
			for _, curEdge := range edges {
				newGraph.Nodes.Add(graph.Nodes.Lookup[curEdge.Src])
				newGraph.Nodes.Add(graph.Nodes.Lookup[curEdge.Dst])
				newGraph.Edges.Add(curEdge)
			}
			break
		}
		for _, nextEdges := range graph.Edges.SrcToDsts[edge.Dst] {
			for _, nextEdge := range nextEdges {
				if GetDataSource(nextEdge) == logType {
					newEdges := append([]*gographviz.Edge{nextEdge}, edges...)
					edgeQueue.Add(newEdges)
				}
			}
		}
	}
}

func AddToNewGraph(edge *gographviz.Edge, appStartEdge *gographviz.Edge, appEndEdge *gographviz.Edge, auditEndEdge *gographviz.Edge, graph *gographviz.Graph, newGraph *gographviz.Graph) {
	AddToNewGraphByTwoEdges(appEndEdge, appStartEdge, graph, newGraph, App[HHPG.Dataset])
	AddToNewGraphByTwoEdges(auditEndEdge, edge, graph, newGraph, Audit[HHPG.Dataset])
}

func ForwardAnalysis(graph *gographviz.Graph, newGraph *gographviz.Graph, DeBackwardNodes []string, maliciousLabel string) {
	edgeSet := mapset.NewSet()
	for _, DeBackwardNode := range DeBackwardNodes {

		nodeSet := mapset.NewSet()
		nodeSet.Add(DeBackwardNode)

		edgePathMap := make(map[string][]*gographviz.Edge)

		edgeQueue := queue.New()
		for _, edges := range graph.Edges.SrcToDsts[DeBackwardNode] {
			for _, edge := range edges {
				var initEdges []*gographviz.Edge
				initEdges = append(initEdges, edge)
				edgeQueue.Add(initEdges)
			}
		}

		for {

			if edgeQueue.Length() == 0 {
				break
			}

			currentEdges := edgeQueue.Remove().([]*gographviz.Edge)
			currentEdge := currentEdges[0]
			currentNode := currentEdge.Dst

			if nodeSet.Contains(currentNode) == false {
				for _, edges := range graph.Edges.SrcToDsts[currentNode] {
					for _, edge := range edges {
						if GetDataSource(edge) != Audit[HHPG.Dataset] {
							continue
						}
						newEdges := append([]*gographviz.Edge{edge}, currentEdges...)
						edgeQueue.Add(newEdges)
					}
				}
				nodeSet.Add(currentNode)
			}
			edgePathMap[currentNode] = append(edgePathMap[currentNode], currentEdges...)
		}
		for _, edge := range edgePathMap[maliciousLabel] {
			newGraph.Nodes.Add(graph.Nodes.Lookup[edge.Src])
			newGraph.Nodes.Add(graph.Nodes.Lookup[edge.Dst])
			if edgeSet.Contains(edge) == false {
				newGraph.Edges.Add(edge)
				edgeSet.Add(edge)
			}
			for _, edge1 := range edgePathMap[edge.Src] {
				newGraph.Nodes.Add(graph.Nodes.Lookup[edge1.Src])
				newGraph.Nodes.Add(graph.Nodes.Lookup[edge1.Dst])
				if edgeSet.Contains(edge1) == false {
					newGraph.Edges.Add(edge1)
					edgeSet.Add(edge1)
				}
			}
			for _, edge1 := range edgePathMap[edge.Dst] {
				newGraph.Nodes.Add(graph.Nodes.Lookup[edge1.Src])
				newGraph.Nodes.Add(graph.Nodes.Lookup[edge1.Dst])
				if edgeSet.Contains(edge1) == false {
					newGraph.Edges.Add(edge1)
					edgeSet.Add(edge1)
				}
			}
		}

	}
}

func PrintGraphInfo(graph *gographviz.Graph, info string) {
}

func GetDependencyLen(graph *gographviz.Graph, node string) int {
	length := 0
	for _, edgeList := range graph.Edges.DstToSrcs[node] {
		length += len(edgeList)
	}
	for _, edgeList := range graph.Edges.SrcToDsts[node] {
		length += len(edgeList)
	}
	return length
}

func GraphSearch(dotPath string, subDotPath string, maliciousLabels []string, withSpp bool) {
	graph := GetGraph(dotPath)
	newGraph := BuildNewGraph()
	lastGraph := BuildNewGraph()

	PrintGraphInfo(graph, "graph")

	var DeBackwardNodes []string

	edgesMap := GetEdgesMap(graph)

	nodeQueue := queue.New()
	for _, maliciousLabel := range maliciousLabels {
		nodeQueue.Add(maliciousLabel)
	}

	nodeSet := mapset.NewSet()

	var nodeNum int = 0

	for {

		nodeNum++
		if nodeQueue.Length() == 0 || nodeNum > 10000 {
			break
		}

		currentNode := nodeQueue.Remove().(string)
		nodeSet.Add(currentNode)

		for _, edges := range graph.Edges.DstToSrcs[currentNode] {
			for _, edge := range edges {
				if GetDataSource(edge) != Audit[HHPG.Dataset] {
					continue
				}

				backwardNode := edge.Src

				if nodeSet.Contains(backwardNode) {
					newGraph.Edges.Add(edge)
					continue
				}

				if IsDENode(graph, backwardNode) && withSpp {

					nodeSet.Add(backwardNode)

					spp := ProcessDependencyExplosion(edge, graph, edgesMap, newGraph)
					if spp != nil && len(spp) == 4 {
						appStartEdge, appEndEdge, auditEndEdge := spp[0], spp[1], spp[3]

						AddToNewGraph(edge, appStartEdge, appEndEdge, auditEndEdge, graph, newGraph)

						DeBackwardNodes = append(DeBackwardNodes, auditEndEdge.Src)

						if IsExist(nodeQueue, auditEndEdge.Src) == false {
							nodeQueue.Add(auditEndEdge.Src)
							nodeSet.Add(auditEndEdge.Src)
						}
					} else {
						fmt.Println("fail")
					}

				} else {
					newGraph.Nodes.Add(graph.Nodes.Lookup[edge.Src])
					newGraph.Nodes.Add(graph.Nodes.Lookup[edge.Dst])
					newGraph.Edges.Add(edge)

					if IsExist(nodeQueue, backwardNode) == false {
						nodeQueue.Add(backwardNode)
						nodeSet.Add(backwardNode)
					}
				}
			}
		}
	}

	if withSpp {
		ForwardAnalysis(newGraph, lastGraph, DeBackwardNodes, maliciousLabels[0])
	} else {
		lastGraph = newGraph
	}

	PrintGraphInfo(newGraph, "newGraph")
	PrintGraphInfo(lastGraph, "lastGraph")

	WriteGraph(lastGraph, subDotPath)

}

func GetPrecision(dotPath string, groundTruths []string) {
	nodeSum, nodeRight := 0, 0
	edgeSum, edgeRight := 0, 0
	graph := GetGraph(dotPath)

	for nodeName := range graph.Nodes.Lookup {
		nodeSum++
		for _, groundTruth := range groundTruths {
			if strings.Contains(nodeName, groundTruth) {
				nodeRight++
				break
			}
		}
	}

	for _, edge := range graph.Edges.Edges {
		start := edge.Src
		end := edge.Dst
		edgeSum++
		for _, groundTruth := range groundTruths {
			if strings.Contains(start, groundTruth) || strings.Contains(end, groundTruth) {
				edgeRight++
				break
			}
		}
	}
}

func GetRecall(dotPath string, groundTruths []string) {
	gtSum, gtRight := 0, 0
	graph := GetGraph(dotPath)
	for _, groundTruth := range groundTruths {
		gtSum++
		for _, edge := range graph.Edges.Edges {
			start := edge.Src
			end := edge.Dst
			if strings.Contains(start, groundTruth) || strings.Contains(end, groundTruth) {
				gtRight++
				break
			}
		}
	}
}

func GetEntitySituation(graph *gographviz.Graph, groundTruths []string) {
	nodeSum, nodeAttack, nodeNonAttack := 0, 0, 0
	for nodeName := range graph.Nodes.Lookup {
		nodeSum++
		flag := false
		for _, groundTruth := range groundTruths {
			if strings.Contains(nodeName, groundTruth) {
				flag = true
				break
			}
		}
		if GetEntityDataSource(graph, nodeName) != Audit[HHPG.Dataset] {
			flag = false
		}
		if flag {
			nodeAttack++
		} else {
			nodeNonAttack++
		}
	}
}

func isGroundTruth(nodeName string, groundTruths []string) bool {
	for _, groundTruth := range groundTruths {
		if strings.Contains(nodeName, groundTruth) {
			return true
		}
	}
	return false
}

func GetRelationSituation(graph *gographviz.Graph, groundTruths []string) {
	edgeSum, edgeAttack, edgeNonAttack := 0, 0, 0
	for _, edge := range graph.Edges.Edges {
		start := edge.Src
		end := edge.Dst
		edgeSum++
		flag := false
		for _, groundTruth := range groundTruths {
			if strings.Contains(start, groundTruth) || strings.Contains(end, groundTruth) {
				flag = true
				break
			}
		}
		if GetDataSource(edge) != Audit[HHPG.Dataset] {
			flag = false
		}
		if flag {
			edgeAttack++
		} else {
			edgeNonAttack++
		}
	}
}

func main() {

	dotPath, subDotPath := GetPath()

	maliciousNodes := GetMaliciousNodes()

	var maliciousLabels []string

	graph := GetGraph(dotPath)

	for name := range graph.Nodes.Lookup {
		if name == maliciousNodes[HHPG.Dataset] {
			maliciousLabels = append(maliciousLabels, name)
		}
	}

	var withSpps = [1]bool{true}

	for _, withSpp := range withSpps {

		startTime := time.Now().Unix()

		GraphSearch(dotPath, subDotPath, maliciousLabels, withSpp)

		endTime := time.Now().Unix()

		fmt.Println("time=", endTime-startTime, "s")
	}

	HHPG.GetMemStats()

}
