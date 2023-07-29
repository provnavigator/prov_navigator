package main

import "strings"

func GetFileName(filename string) string {
	if strings.Contains(filename, "/") {
		strList := strings.Split(filename, "/")
		return strList[len(strList)-1]
	}
	return filename
}
