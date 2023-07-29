package main

import (
	"bufio"
	"fmt"
	"github.com/xuri/excelize/v2"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Title struct {
	Keywords      string
	Date_and_Time string
	Source        string
	Event_ID      string
	Task_Category string
	Information   string
}

type Access_Request_Information struct {
	Transaction_ID                   string
	Accesses                         string
	Access_Reasons                   string
	Access_Mask                      string
	Privileges_Used_for_Access_Check string
	Restricted_SID_Count             string
}

var line_cnt int
var filePath string

func seMain() {
	filePath = "CLF/SecurityEvents"
	fileName := filePath + "/security_events.txt"
	f_out_attri, _ := os.OpenFile(filePath+"/attributes_introducution.txt", os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0755)
	os.Stdout = f_out_attri
	attri_map, more_lines_attris_list := Generate_attri_map(fileName)
	outfileName := filePath + "/security_events.xlsx"

	f := excelize.NewFile()
	line_cnt = 0
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println("File open faild:", err)
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Scan()
	Read_and_split(sc)
	var log_kind_list []string
	var log_kind_cur_line []int
	var cur_log_kind string
	var cur_top_attri_list []string
	var cur_values_list [][]string
	var cur_top_attri string
	for sc.Scan() {
		line_elems, new_top_attri_flag := Read_and_split(sc)

		if len(line_elems) == 0 || (len(line_elems) == 1 && line_elems[0][len(line_elems[0])-1] != ':') {
			continue
		}
	NEWLOG:
		if line_elems[0] != "Audit Success" && line_elems[0] != "Audit Failure" && line_elems[0] != "Information" {

			more_line_attri_flag := false
			for _, elem := range more_lines_attris_list {
				if line_elems[0] == elem {
					more_line_attri_flag = true
					break
				}
			}
			if more_line_attri_flag {
				tmp := ""
				cur_attri := line_elems[0][:len(line_elems[0])-1]
				if len(line_elems) > 1 {
					tmp += line_elems[1] + " "
				}
				for sc.Scan() {
					line_elems, _ = Read_and_split(sc)
					if len(line_elems) > 1 {
						for i, elem := range attri_map[cur_top_attri] {
							if elem == cur_attri && cur_values_list[len(cur_values_list)-1][i] == "" {
								cur_values_list[len(cur_values_list)-1][i] = tmp
								break
							}
						}
						goto NEWLOG
					} else {
						for _, elem := range line_elems {
							tmp += elem + "\n"
						}
					}
				}
			} else if new_top_attri_flag {
				cur_top_attri = line_elems[0]
				cur_log_kind += cur_top_attri
				cur_top_attri_list = append(cur_top_attri_list, line_elems[0])
				cur_values_list = append(cur_values_list, make([]string, len(attri_map[cur_top_attri])))
				if len(attri_map[cur_top_attri]) == 0 && len(line_elems) > 1 {
					cur_values_list = append(cur_values_list, []string{line_elems[1]})
				}
			} else {
				for i, elem := range attri_map[cur_top_attri] {
					if elem == line_elems[0][:len(line_elems[0])-1] && cur_values_list[len(cur_values_list)-1][i] == "" {
						if len(line_elems) < 2 {
							cur_values_list[len(cur_values_list)-1][i] = "(empty)"
						} else {
							cur_values_list[len(cur_values_list)-1][i] = line_elems[1]
						}
						break
					}
				}
			}
		} else {
			var data []string
			for _, elem := range cur_values_list {
				data = append(data, elem...)
			}
			w_flag := false
			for i, elem := range log_kind_list {
				if elem == cur_log_kind {
					WriterXLSX(log_kind_cur_line, f, i, data)
					w_flag = true
					break
				}
			}
			if !w_flag && cur_log_kind != "" {
				log_kind_list = append(log_kind_list, cur_log_kind)
				log_kind_cur_line = append(log_kind_cur_line, 0)
				new_log_kind_id := len(log_kind_list) - 1
				if new_log_kind_id != 0 {
					f.NewSheet("Sheet" + strconv.Itoa(new_log_kind_id+1))
				}
				var cur_attri_name_data []string
				var cur_top_attri_name_data []string
				for _, key := range cur_top_attri_list {
					cur_top_attri_name_data = append(cur_top_attri_name_data, key)
					if len(attri_map[key]) > 0 {
						cur_top_attri_name_data = append(cur_top_attri_name_data, make([]string, len(attri_map[key])-1)...)
						cur_attri_name_data = append(cur_attri_name_data, attri_map[key]...)
					} else {
						cur_attri_name_data = append(cur_attri_name_data, "")
					}
				}
				WriterXLSX(log_kind_cur_line, f, new_log_kind_id, cur_top_attri_name_data)
				WriterXLSX(log_kind_cur_line, f, new_log_kind_id, cur_attri_name_data)
				WriterXLSX(log_kind_cur_line, f, new_log_kind_id, data)
			}

			cur_top_attri_list = []string{}
			cur_values_list = [][]string{}
			cur_top_attri_list = append(cur_top_attri_list, "Title:")
			line_elems = append(line_elems[:4], line_elems[4]+line_elems[5])
			cur_values_list = append(cur_values_list, line_elems)
			cur_top_attri = "Title:"
			cur_log_kind = ""
		}
	}
	f.SaveAs(outfileName)
}

func Generate_attri_map(fileName string) (map[string][]string, []string) {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println("File open faild:", err)
	}
	defer file.Close()
	var attri_map map[string][]string = make(map[string][]string)
	var attri_change_lines_map map[string][]int = make(map[string][]int)
	title_name := []string{"Keywords", "Date and Time", "Source", "Event ID", "Task Category"}
	attri_map["Title:"] = append(attri_map["Title:"], title_name...)
	attri_change_lines_map["Title:"] = append(attri_change_lines_map["Title:"], -1)
	var cur_top_attri string = ""
	var cur_attri_list []string
	sc := bufio.NewScanner(file)
	sc.Scan()
	line_cnt = 0
	last_line_cnt := 0
	Read_and_split(sc)
	var last_line_elems []string
	var more_lines_attris_map = make(map[string]int)
	for sc.Scan() {
		line_elems, new_top_attri_flag := Read_and_split(sc)

		if len(line_elems) == 1 && line_elems[0][len(line_elems[0])-1] != ':' {
			if len(last_line_elems) > 0 && last_line_elems[0][len(last_line_elems[0])-1] == ':' {
				more_lines_attris_map[last_line_elems[0]] = line_cnt
			}
			continue
		}
		if len(line_elems) > 0 && line_elems[0] != "Audit Success" && line_elems[0] != "Audit Failure" && line_elems[0] != "Information" {
			if new_top_attri_flag {
				if cur_attri_list != nil && len(cur_top_attri) > 0 {
					old_attri_list := attri_map[cur_top_attri]
					if len(old_attri_list) > len(cur_attri_list) {
						cur_attri_list, old_attri_list = old_attri_list, cur_attri_list
					}
					for _, to_be_insert_elem := range old_attri_list {
						flag := true
						for _, elem := range cur_attri_list {
							if to_be_insert_elem == elem {
								flag = false
								break
							}
						}
						if flag {
							cur_attri_list = append(cur_attri_list, to_be_insert_elem)
						}
					}
					if len(attri_map[cur_top_attri]) < len(cur_attri_list) || (len(attri_map[cur_top_attri]) == 0 && len(attri_change_lines_map[cur_top_attri]) == 0) {
						attri_change_lines_map[cur_top_attri] = append(attri_change_lines_map[cur_top_attri], last_line_cnt)
					}
					attri_map[cur_top_attri] = cur_attri_list
				}
				last_line_cnt = line_cnt
				_, flag := attri_map[line_elems[0]]
				if !flag {
					attri_map[line_elems[0]] = []string{}
				}
				cur_top_attri = line_elems[0]
				cur_attri_list = []string{}
			} else {
				cur_attri_list = append(cur_attri_list, line_elems[0][:len(line_elems[0])-1])
			}
		}
		last_line_elems = line_elems
	}

	more_lines_attris_list := make([]string, 0, len(more_lines_attris_map))
	for key := range more_lines_attris_map {
		more_lines_attris_list = append(more_lines_attris_list, key)
	}

	attri_list := []string{}
	for top_attri, top_attri_list := range attri_map {
		tmp := top_attri + "\t" + fmt.Sprint(attri_change_lines_map[top_attri]) + "\t" + fmt.Sprint(top_attri_list)
		attri_list = append(attri_list, tmp)
	}
	sort.Strings(attri_list)
	for _, elem := range attri_list {
		e := strings.Split(elem, "\t")
		fmt.Printf("%-60s %-40s %-80s\n", e[0], e[1], e[2])
	}

	return attri_map, more_lines_attris_list
}

func Read_and_split(sc *bufio.Scanner) ([]string, bool) {
	line_cnt++

	line := sc.Text()
	return SplitLine(line)
}

func SplitLine(line string) ([]string, bool) {
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

func WriterXLSX(log_cnt []int, f *excelize.File, i int, data []string) {
	insert_row := "A" + strconv.Itoa(log_cnt[i]+1)
	sheet_name := "Sheet" + strconv.Itoa(i+1)
	err := f.SetSheetRow(sheet_name, insert_row, &data)
	if err != nil {
		fmt.Println(err)
	}
	log_cnt[i]++
}
