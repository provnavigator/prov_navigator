package main

import (
	"HHPG/CLF"
	"encoding/json"
	"fmt"
	"github.com/xuri/excelize/v2"
	"strconv"
	"strings"
	"time"
)

type SecurityEvent struct {
	eventType string
	data      map[string]map[string]string
}

type SecurityEventsParser struct {
	pusher                 *Pusher
	attri_map              map[string][]string
	more_lines_attris_list []string

	isFirstLine bool

	cur_log_kind       string
	cur_top_attri_list []string
	cur_values_list    [][]string
	cur_top_attri      string
	line_cnt           int
	last_line_cnt      int

	more_line_attri_flag bool
	isFCScan             bool
	tmp                  string
	cur_attri            string

	f             *excelize.File
	allEventTypes map[string]bool
}

func NewSecurityEventsParser(pusher *Pusher, attrMap map[string][]string, moreLinesAttrMap []string) *SecurityEventsParser {
	return &SecurityEventsParser{
		pusher: pusher, attri_map: attrMap, more_lines_attris_list: moreLinesAttrMap,
		more_line_attri_flag: false,
		isFCScan:             false,
		line_cnt:             0,
		last_line_cnt:        0,
		f:                    excelize.NewFile(),
		isFirstLine:          true,
		allEventTypes:        map[string]bool{},
	}
}

func (s *SecurityEventsParser) SplitOneLine(line string) ([]string, bool) {
	s.line_cnt++
	line_elems := strings.Split(line, "\t")
	var new_top_attri_flag bool = false
	if line_elems[0] != "" && line_elems[0][len(line_elems[0])-1] == ':' {
		new_top_attri_flag = true
	}
	len_line_elems := len(line_elems)
	prefix_4_nil_flag := false
	if len_line_elems >= 4 {
		prefix_4_nil_flag = true
		for i := 0; i < 4; i++ {
			if line_elems[i] != "" {
				prefix_4_nil_flag = false
			}
		}
	}
	for i := 0; i < len_line_elems; i++ {
		line_elems[i] = strings.TrimSpace(line_elems[i])
		if line_elems[i] == "" {
			line_elems = append(line_elems[:i], line_elems[i+1:]...)
			i--
			len_line_elems--
		}
	}
	if len(line_elems) > 0 {

		if prefix_4_nil_flag || (line_elems[0][len(line_elems[0])-1] != ':' && line_elems[0] != "Audit Success" && line_elems[0] != "Audit Failure" && line_elems[0] != "Information") {
			var tmp string
			for _, elem := range line_elems {
				tmp += elem + " "
			}
			new_top_attri_flag = false
			line_elems = []string{tmp}
		}
	}

	if new_top_attri_flag {
		if line_elems[0][len(line_elems[0])-2] == ' ' {
			line_elems[0] = strings.TrimSpace(line_elems[0][:len(line_elems[0])-1]) + ":"
		}
	}
	return line_elems, new_top_attri_flag
}

func (s *SecurityEventsParser) RefineEntry(se SecurityEvent) CLF.ParsedLog {
	pl := CLF.ParsedLog{}
	keys := strings.Split(se.eventType, ":")
	keys = keys[:len(keys)-1]
	keys = append([]string{"Title"}, keys...)

	tags := make([]CLF.Tag, 0, 5)

	for _, key1 := range keys {
		for key2, value := range se.data[key1] {
			_, ok := helpfulTags[key2]
			if ok && key2 != "" && value != "" {
				if key2 == "Process ID" || key2 == "Creator Process ID" || key2 == "New Process ID" {
					if strings.Contains(value, "0x") {
						dec, _ := strconv.ParseInt(value[2:], 16, 64)
						value = strconv.Itoa(int(dec))
						se.data[key1][key2] = value
					}
				}
				if key2 == "Application Name" || key2 == "Process Name" || key2 == "New Process Name" {
					valueList := strings.Split(value, "\\")
					value = valueList[len(valueList)-1]
					if strings.HasSuffix(value, "\"") {
						value = value[:len(value)-1]
					}
					se.data[key1][key2] = value
				}
				value = ellipsis(value, MAX_TAG_VAL_BYTES)
				tags = append(tags, CLF.Tag{
					ID:    -1,
					Key:   key2,
					Value: value,
					Type:  CLF.Normal,
				})
			}
		}
	}

	startValue, endValue := GetValue(se)

	if startValue != "" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "securityEvents_start", Value: startValue, Type: CLF.Normal})
	}

	if endValue != "" {
		tags = append(tags, CLF.Tag{ID: -1, Key: "securityEvents_end", Value: endValue, Type: CLF.Normal})
	}

	if strings.HasPrefix(startValue, "file#") {
		valueList := strings.Split(startValue, "\\")
		value := valueList[len(valueList)-1]
		tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: value, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: GetFileName(value), Type: CLF.Normal})
	}

	if strings.HasPrefix(endValue, "file#") {
		valueList := strings.Split(endValue, "\\")
		value := valueList[len(valueList)-1]
		tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: value, Type: CLF.Normal})
		tags = append(tags, CLF.Tag{ID: -1, Key: "filename", Value: GetFileName(value), Type: CLF.Normal})
	}

	const layout = "1/2/2006 3:04:05 PM"
	ts, err := time.Parse(layout, se.data["Title"]["Date and Time"])
	if err != nil {
		fmt.Println(err)
	}

	bytes, _ := json.Marshal(se.data)
	rawLine := string(bytes)

	pl.Log = CLF.Log{ID: -1, Time: ts, LogRaw: rawLine, LogType: s.LogType()}
	pl.Tags = tags

	return pl
}

func (s *SecurityEventsParser) ParseLine(rawLine string) (CLF.ParsedLog, bool, error) {
	pl := CLF.ParsedLog{}
	if s.isFirstLine {
		s.isFirstLine = false
		s.SplitOneLine(rawLine)
		return pl, true, nil
	}
	var line_elems []string
	var new_top_attri_flag bool

	if s.isFCScan {
		line_elems, _ = s.SplitOneLine(rawLine)
		if len(line_elems) > 1 {
			for i, elem := range s.attri_map[s.cur_top_attri] {
				if elem == s.cur_attri && s.cur_values_list[len(s.cur_values_list)-1][i] == "" {
					s.cur_values_list[len(s.cur_values_list)-1][i] = s.tmp
					break
				}
			}
			s.isFCScan = false
			goto NEWLOG
		} else {
			for _, elem := range line_elems {
				s.tmp += elem + "\n"
			}
			return pl, true, nil
		}
	}

	line_elems, new_top_attri_flag = s.SplitOneLine(rawLine)

	if len(line_elems) == 0 || (len(line_elems) == 1 && line_elems[0][len(line_elems[0])-1] != ':') {
		return pl, true, nil
	}

NEWLOG:
	if line_elems[0] != "Audit Success" && line_elems[0] != "Audit Failure" && line_elems[0] != "Information" {

		s.more_line_attri_flag = false
		for _, elem := range s.more_lines_attris_list {
			if line_elems[0] == elem {
				s.more_line_attri_flag = true
				break
			}
		}
		if s.more_line_attri_flag {
			s.tmp = ""
			s.cur_attri = line_elems[0][:len(line_elems[0])-1]
			if len(line_elems) > 1 {
				s.tmp += line_elems[1] + " "
			}
			s.isFCScan = true
			return pl, true, nil

		} else if new_top_attri_flag {
			s.cur_top_attri = line_elems[0]
			s.cur_log_kind += s.cur_top_attri
			s.cur_top_attri_list = append(s.cur_top_attri_list, line_elems[0])
			s.cur_values_list = append(s.cur_values_list, make([]string, len(s.attri_map[s.cur_top_attri])))
			if len(s.attri_map[s.cur_top_attri]) == 0 && len(line_elems) > 1 {
				s.cur_values_list = append(s.cur_values_list, []string{line_elems[1]})
			}
		} else {
			for i, elem := range s.attri_map[s.cur_top_attri] {
				if elem == line_elems[0][:len(line_elems[0])-1] && s.cur_values_list[len(s.cur_values_list)-1][i] == "" {
					if len(line_elems) < 2 {
						s.cur_values_list[len(s.cur_values_list)-1][i] = "(empty)"
					} else {
						s.cur_values_list[len(s.cur_values_list)-1][i] = line_elems[1]
					}
					break
				}
			}
		}
	} else {
		var data []string
		isParsed := false
		for _, elem := range s.cur_values_list {
			data = append(data, elem...)
		}
		if s.cur_log_kind != "" {
			se := SecurityEvent{}
			curMap := make(map[string]map[string]string)
			var cur_attri_name_data []string
			var cur_top_attri_name_data []string
			for _, key := range s.cur_top_attri_list {
				cur_top_attri_name_data = append(cur_top_attri_name_data, key)
				if len(s.attri_map[key]) > 0 {
					cur_top_attri_name_data = append(cur_top_attri_name_data, make([]string, len(s.attri_map[key])-1)...)
					cur_attri_name_data = append(cur_attri_name_data, s.attri_map[key]...)
				} else {
					cur_attri_name_data = append(cur_attri_name_data, "value")
				}
			}

			lastTopAttrName := ""
			for kk, topAttr := range cur_top_attri_name_data {
				if topAttr != "" {
					lastTopAttrName = topAttr
				}
				curTopRealName := lastTopAttrName[:len(lastTopAttrName)-1]
				if _, ok := curMap[curTopRealName]; !ok {
					curMap[curTopRealName] = make(map[string]string)
				}
				curMap[curTopRealName][cur_attri_name_data[kk]] = data[kk]
			}

			se.eventType = s.cur_log_kind
			se.data = curMap
			pl = s.RefineEntry(se)
			isParsed = true
		}
		s.last_line_cnt = s.line_cnt
		s.cur_top_attri_list = []string{}
		s.cur_values_list = [][]string{}
		s.cur_top_attri_list = append(s.cur_top_attri_list, "Title:")
		line_elems = append(line_elems[:4], line_elems[4]+line_elems[5])
		s.cur_values_list = append(s.cur_values_list, line_elems)
		s.cur_top_attri = "Title:"
		s.cur_log_kind = ""
		return pl, !isParsed, nil

	}
	return pl, true, nil
}

func (s *SecurityEventsParser) ParsePushLine(rawLine string) error {
	pl, skip, err := s.ParseLine(rawLine)
	if skip {
		return nil
	}

	if err != nil {
		return err
	}
	err = s.pusher.PushParsedLog(pl)
	if err != nil {
		return err
	}

	logData := make(map[string]map[string]string)
	err = json.Unmarshal([]byte(pl.Log.LogRaw), &logData)
	if err != nil {
		return err
	}
	taskCategory := logData["Title"]["Task Category"]
	if strings.Contains(taskCategory, "Filtering Platform Connection") &&
		strings.Contains(taskCategory, "permitted a connection") {
		tags := make([]CLF.Tag, 0, 5)
		for _, oldTag := range pl.Tags[:] {
			if oldTag.Key == "securityEvents_start" {
				tags = append(tags, CLF.Tag{ID: -1, Key: "securityEvents_end", Value: oldTag.Value, Type: CLF.Normal})
			} else if oldTag.Key == "securityEvents_end" {
				tags = append(tags, CLF.Tag{ID: -1, Key: "securityEvents_start", Value: oldTag.Value, Type: CLF.Normal})
			} else {
				tags = append(tags, CLF.Tag{ID: -1, Key: oldTag.Key, Value: oldTag.Value, Type: CLF.Normal})
			}
		}
		pl.Tags = tags
		err = s.pusher.PushParsedLog(pl)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SecurityEventsParser) LogType() string {
	return "SecurityEvents"
}
