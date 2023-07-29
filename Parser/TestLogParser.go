package main

import (
	"HHPG"
	"HHPG/CLF"
	"log"
	"strings"
	"sync"
)

var wgInserter = sync.WaitGroup{}
var wgParser = sync.WaitGroup{}

func addLogParse(_parser Parser, filename string) {
	wgParser.Add(1)
	go func() {

		defer wgParser.Done()
		parser := _parser
		err := ParseFile(filename, parser)
		if err != nil {
			log.Fatal(err)
		}
	}()
}

/* Parsers 20230330 */
func StartDNSLogParse() {
	pChanDNS := make(chan CLF.ParsedLog, 50)
	dnsInserter := CLF.DNSInserter{ParsedLogCh: &pChanDNS}

	for idx := 0; idx < 1; idx++ {

		wgInserter.Add(1)
		idx := idx
		go func() {
			defer wgInserter.Done()
			dnsInserter.Insert(idx)
		}()
	}

	addLogParse(NewDNSParser(&Pusher{&pChanDNS}), "Logs/"+HHPG.Dataset+"/dns")

	wgParser.Wait()
	close(pChanDNS)
	wgInserter.Wait()

}

func StartLogParse() {
	pChan := make(chan CLF.ParsedLog, 100)
	inserter := CLF.Inserter{ParsedLogCh: &pChan}

	for idx := 0; idx < 1; idx++ {

		wgInserter.Add(1)
		idx := idx
		go func() {
			defer wgInserter.Done()
			inserter.Insert(idx)
		}()
	}

	if strings.Contains(HHPG.Dataset, "ATLAS") {

		addLogParse(NewFirefoxParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/firefox.txt")

		seFileName := "Logs/" + HHPG.Dataset + "/security_events.txt"
		attri_map, more_lines_attris_list := Generate_attri_map(seFileName)
		seParser := NewSecurityEventsParser(&Pusher{&pChan}, attri_map, more_lines_attris_list)
		addLogParse(seParser, seFileName)
	} else if strings.Contains(HHPG.Dataset, "APT/S1") {
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/"+HHPG.Dataset+"/audit.log")
		addLogParse(NewApacheParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/apache.log")
		addLogParse(NewProftpdParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/proftpd.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/net.log")
	} else if strings.Contains(HHPG.Dataset, "APT/S1-1") {
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/"+HHPG.Dataset+"/audit.log")
		addLogParse(NewApacheParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/apache.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/net.log")
	} else if strings.Contains(HHPG.Dataset, "APT/S1-2") {
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/"+HHPG.Dataset+"/audit.log")
		addLogParse(NewProftpdParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/proftpd.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/net.log")
	} else if strings.Contains(HHPG.Dataset, "APT/S2") {
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/"+HHPG.Dataset+"/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/"+HHPG.Dataset+"/net.log")
	} else if HHPG.Dataset == "MiniHttpd" {
		addLogParse(NewMiniHttpParser(&Pusher{&pChan}), "Logs/MiniHttpd/mini_httpd.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/MiniHttpd/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/MiniHttpd/net.log")
	} else if HHPG.Dataset == "PostgreSql" {
		addLogParse(NewPostgresqlParser(&Pusher{&pChan}), "Logs/PostgreSql/postgresql.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, false), "Logs/PostgreSql/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/PostgreSql/net.log")
	} else if HHPG.Dataset == "Proftpd" {
		addLogParse(NewProftpdParser(&Pusher{&pChan}), "Logs/Proftpd/proftpd.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/Proftpd/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/Proftpd/net.log")
	} else if HHPG.Dataset == "Nginx" {
		addLogParse(NewNginxParser(&Pusher{&pChan}), "Logs/Nginx/nginx.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/Nginx/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/Nginx/net.log")
	} else if HHPG.Dataset == "Apache" {
		addLogParse(NewApacheParser(&Pusher{&pChan}), "Logs/Apache/apache.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/Apache/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/Apache/net.log")
	} else if HHPG.Dataset == "Redis" {
		addLogParse(NewRedisParser(&Pusher{&pChan}), "Logs/Redis/redis.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/Redis/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/Redis/net.log")
	} else if HHPG.Dataset == "Vim" {
		addLogParse(NewVimParser(&Pusher{&pChan}), "Logs/Vim/vim.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, true), "Logs/Vim/audit.log")
	} else if HHPG.Dataset == "Openssh" {
		addLogParse(NewOpensshParser(&Pusher{&pChan}), "Logs/Openssh/openssh.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, false), "Logs/Openssh/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/Openssh/net.log")
	} else if HHPG.Dataset == "ImageMagick" {
		addLogParse(NewImageMagickParser(&Pusher{&pChan}), "Logs/ImageMagick/imagemagick.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, false), "Logs/ImageMagick/audit.log")
	} else if HHPG.Dataset == "php" {
		addLogParse(NewApacheParser(&Pusher{&pChan}), "Logs/php/apache.log")
		addLogParse(NewAuditParser(&Pusher{&pChan}, false), "Logs/php/audit.log")
		addLogParse(NewNetworkParser(&Pusher{&pChan}), "Logs/php/net.log")
	}

	wgParser.Wait()
	close(pChan)
	wgInserter.Wait()

}

func main() {
	CLF.DBPrepare()
	if strings.Contains(HHPG.Dataset, "ATLAS") {
		StartDNSLogParse()
	}
	StartLogParse()

	HHPG.GetMemStats()
}
