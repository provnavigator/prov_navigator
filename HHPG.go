package HHPG

import (
	"runtime"
)

const Dataset string = "PostgreSql"

func GetMemStats() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
}
