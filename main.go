package main

import (
	"log"
	"log/syslog"
	"os"
	"strings"

	syslogServer "gopkg.in/mcuadros/go-syslog.v2"
)

var syslogListen = os.Getenv("SYSLOG_LISTEN")
var librenmsTarget = os.Getenv("LIBRENMS_TARGET")

func main() {

	sysLog, err := syslog.Dial("udp", librenmsTarget, syslog.LOG_WARNING, "DHCPMON")
	if err != nil {
		log.Fatal(err)
	}
	sysLog.Info("DHCPMON started")

	channel := make(syslogServer.LogPartsChannel)
	handler := syslogServer.NewChannelHandler(channel)

	server := syslogServer.NewServer()
	server.SetFormat(syslogServer.RFC3164)
	server.SetHandler(handler)
	server.ListenUDP(syslogListen)
	server.Boot()

	go func(channel syslogServer.LogPartsChannel) {
		for logParts := range channel {
			content := logParts["content"].(string)
			if strings.Contains(content, "DHCPACK") {
				go processDHCPLog(content, sysLog)
			}
		}
	}(channel)

	server.Wait()

}
