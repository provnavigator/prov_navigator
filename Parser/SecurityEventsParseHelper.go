package main

import (
	"strings"
)

var helpfulTags = map[string]int{
	"Date and Time":          1,
	"Event ID":               1,
	"Task Category":          1,
	"Logon ID":               1,
	"New Process ID":         1,
	"New Process Name":       1,
	"Creator Process ID":     1,
	"Process ID":             1,
	"Application Name":       1,
	"Process Name":           1,
	"Target Process ID":      1,
	"Object Type":            1,
	"Object Name":            1,
	"Transaction ID":         1,
	"Accesses":               1,
	"Direction":              1,
	"Source Address":         1,
	"Source Port":            1,
	"Destination Address":    1,
	"Destination Port":       1,
	"Protocol":               1,
	"Workstation Name":       1,
	"Source Network Address": 1,
	"Network Address":        1,
	"Port":                   1,
}

func GetValue(se SecurityEvent) (string, string) {
	startValue, endValue := "", ""

	taskCategory := se.data["Title"]["Task Category"]
	if taskCategory == "File System\"An attempt was made to access an object." {
		accesses := strings.ToLower(se.data["Access Request Information"]["Accesses"])
		pid := se.data["Process Information"]["Process ID"]
		file := se.data["Object"]["Object Name"]

		if strings.Contains(accesses, "write") {
			return "process#" + pid, "file#" + file
		} else if strings.Contains(accesses, "read") || strings.Contains(accesses, "execute") {
			return "file#" + file, "process#" + pid
		}
	}
	if taskCategory == "Process Creation\"A new process has been created." {
		pid := se.data["Process Information"]["Creator Process ID"]
		newPid := se.data["Process Information"]["New Process ID"]

		return "process#" + pid, "process#" + newPid
	}
	if taskCategory == "Process Termination\"A process has exited." {
		pid := se.data["Process Information"]["Process ID"]
		return "process#" + pid, "process#" + pid
	}
	if strings.Contains(taskCategory, "Filtering Platform Connection") {
		pid := se.data["Application Information"]["Process ID"]

		srcIp := se.data["Network Information"]["Source Address"]
		srcPort := se.data["Network Information"]["Source Port"]
		dstIp := se.data["Network Information"]["Destination Address"]
		dstPort := se.data["Network Information"]["Destination Port"]

		if strings.Contains(taskCategory, "permitted a bind to a local port") {
			return "process#" + pid, "socket#" + srcIp + ":" + srcPort
		}
		if strings.Contains(taskCategory, "permitted a connection") {
			socketName := "socket_src#" + srcIp + ":" + srcPort + "\n" + "socket_dst#" + dstIp + ":" + dstPort
			return "process#" + pid, socketName
		}
		if strings.Contains(taskCategory, "permitted an application or service to listen "+
			"on a port for incoming connections") {
			return "socket#" + srcIp + ":" + srcPort, "process#" + pid
		}
	}

	return startValue, endValue
}

func GetValueOld(se SecurityEvent) (string, string) {
	startValue, endValue := "", ""

	processName := ""
	_, ok := se.data["Process Information"]
	if ok {
		v, ok := se.data["Process Information"]["Process Name"]
		if ok && v != "" {
			processName = "\n" + "process_name#" + v
		}
	}

	taskCategory := se.data["Title"]["Task Category"]
	if taskCategory == "File System\"An attempt was made to access an object." {
		accesses := strings.ToLower(se.data["Access Request Information"]["Accesses"])
		pid := se.data["Process Information"]["Process ID"]
		file := se.data["Object"]["Object Name"]

		if strings.Contains(accesses, "write") {
			return "process#" + pid + processName, "file#" + file
		} else if strings.Contains(accesses, "read") || strings.Contains(accesses, "execute") {
			return "file#" + file, "process#" + pid + processName
		}
	}
	if taskCategory == "Process Creation\"A new process has been created." {
		pid := se.data["Process Information"]["Creator Process ID"]
		newPid := se.data["Process Information"]["New Process ID"]
		newProcessName := "\n" + "process_name#" + se.data["Process Information"]["New Process Name"]
		return "process#" + pid, "process#" + newPid + newProcessName
	}
	if taskCategory == "Process Termination\"A process has exited." {
		pid := se.data["Process Information"]["Process ID"]
		return "process#" + pid + processName, "process#" + pid + processName
	}
	if strings.Contains(taskCategory, "Filtering Platform Connection") {
		pid := se.data["Application Information"]["Process ID"]
		processName = "\n" + "process_name#" + se.data["Application Information"]["Application Name"]
		srcIp := se.data["Network Information"]["Source Address"]
		srcPort := se.data["Network Information"]["Source Port"]
		dstIp := se.data["Network Information"]["Destination Address"]
		dstPort := se.data["Network Information"]["Destination Port"]

		if strings.Contains(taskCategory, "permitted a bind to a local port") {
			return "process#" + pid + processName, "socket#" + srcIp + ":" + srcPort
		}
		if strings.Contains(taskCategory, "permitted a connection") {
			socketName := "socket_src#" + srcIp + ":" + srcPort + "\n" + "socket_dst#" + dstIp + ":" + dstPort
			return "process#" + pid + processName, socketName
		}
		if strings.Contains(taskCategory, "permitted an application or service to listen "+
			"on a port for incoming connections") {
			return "socket#" + srcIp + ":" + srcPort, "process#" + pid + processName
		}
	}

	return startValue, endValue
}
