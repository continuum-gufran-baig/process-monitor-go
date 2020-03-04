package main

import (
	"fmt"

	"github.com/elastic/beats/winlogbeat/sys/eventlogging"
)

func main() {
	hFile, err := eventlogging.OpenEventLog("", `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application`)
	if err != nil {
		fmt.Println("failed to open eventlog with error %v", err)
	}

	lpBuffer := make([]byte, 102400)
	var level uint32 = 0

	flags := eventlogging.EVENTLOG_SEQUENTIAL_READ | eventlogging.EVENTLOG_FORWARDS_READ

	_, err = eventlogging.ReadEventLog(hFile, flags, level, lpBuffer)
	if err != nil {
		fmt.Println("failed to read eventlog with error %v", err)
	}

	lBuffer := make([]byte, 102400)
	rec, _, err := renderEvents(lpBuffer, 0, lBuffer, &StringInserts{})
	fmt.Println(len(rec))

	// for _, e := range rec {
	// 	fmt.Println(e)
	// }
}
