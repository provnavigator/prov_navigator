package main

import (
	"HHPG"
	"fmt"
	"os"
	"strings"
)

func createDir(dirName string) {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		err := os.Mkdir(dirName, 0755)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func main() {

	dotName := string("")
	createDir("Graphs/" + HHPG.Dataset + "/")
	if strings.Contains(HHPG.Dataset, "ATLAS") || strings.Contains(HHPG.Dataset, "APT") {
		datasetName := strings.Split(HHPG.Dataset, "/")[1]
		dotName = "Graphs/" + HHPG.Dataset + "/" + datasetName + ".dot"
	} else {
		dotName = "Graphs/" + HHPG.Dataset + "/" + HHPG.Dataset + ".dot"
	}

	ConstructHHPG(dotName)

	HHPG.GetMemStats()

}
