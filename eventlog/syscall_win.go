package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/elastic/beats/winlogbeat/sys"
	"golang.org/x/sys/windows"
)

var (
	libadvapi32  uintptr
	openEventLog uintptr
)

const (
	// MaxInsertStrings is the maximum number of strings that can be formatted by
	// FormatMessage API.
	MaxInsertStrings = 99
)

const (
	eventIDLowerMask uint32 = 0xFFFF
	eventIDUpperMask uint32 = 0xFFFF0000
)

type StringInserts struct {
	pointers [MaxInsertStrings]uintptr
	inserts  []string
	address  uintptr
}

// winEventLogRecord is equivalent to EVENTLOGRECORD.
// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa363646(v=vs.85).aspx
type eventLogRecord struct {
	length        uint32 // The size of this event record, in bytes
	reserved      uint32 // value that is always set to ELF_LOG_SIGNATURE (the value is 0x654c664c), which is ASCII for eLfL
	recordNumber  uint32 // The number of the record.
	timeGenerated uint32 // time at which this entry was submitted
	timeWritten   uint32 // time at which this entry was received by the service to be written to the log
	eventID       uint32 // The event identifier. The value is specific to the event source for the event, and is used
	// with source name to locate a description string in the message file for the event source.
	eventType           uint16 // The type of event
	numStrings          uint16 // number of strings present in the log
	eventCategory       uint16 // category for this event
	reservedFlags       uint16 // Reserved
	closingRecordNumber uint32 // Reserved
	stringOffset        uint32 // offset of the description strings within this event log record
	userSidLength       uint32 // size of the UserSid member, in bytes. This value can be zero if no security identifier was provided
	userSidOffset       uint32 // offset of the security identifier (SID) within this event log record
	dataLength          uint32 // size of the event-specific data in bytes
	dataOffset          uint32 // offset of the event-specific information within this event log record, in bytes

	//
	// Then follows the extra data.
	//
	// TCHAR SourceName[]
	// TCHAR Computername[]
	// SID   UserSid
	// TCHAR Strings[]
	// BYTE  Data[]
	// CHAR  Pad[]
	// DWORD Length;

	sourceName   string
	computerName string
	userSid      []byte
}

// unixTime takes a time which is an unsigned 32-bit integer, and converts it
// into a Golang time.Time pointer formatted as a unix time.
func unixTime(sec uint32) time.Time {
	t := time.Unix(int64(sec), 0)
	return t
}

type EventType uint16

func init() {
	libadvapi32 = doLoadLibrary("advapi32.dll")
	openEventLog = doGetProcAddress(libadvapi32, "OpenEventLogW")
}

func doGetProcAddress(lib uintptr, name string) uintptr {
	addr, _ := syscall.GetProcAddress(syscall.Handle(lib), name)
	return uintptr(addr)
}

func doLoadLibrary(name string) uintptr {
	lib, _ := syscall.LoadLibrary(name)
	return uintptr(lib)
}

func syscall3(trap, nargs, a1, a2, a3 uintptr) uintptr {
	ret, _, _ := syscall.Syscall(trap, nargs, a1, a2, a3)
	return ret
}

func unicode16FromString(s string) []uint16 {
	r := make([]rune, 0)
	for _, c := range s {
		r = append(r, c)
	}
	b := utf16.Encode(r)
	return append(b, uint16(0))
}

func OpenEventLog(lpUNCServerName string, lpSourceName string) windows.Handle {
	lpUNCServerNameStr := unicode16FromString(lpUNCServerName)
	lpSourceNameStr := unicode16FromString(lpSourceName)
	ret1 := syscall3(openEventLog, 2,
		uintptr(unsafe.Pointer(&lpUNCServerNameStr[0])),
		uintptr(unsafe.Pointer(&lpSourceNameStr[0])),
		0)
	return windows.Handle(ret1)
}

// RenderEvents reads raw events from the provided buffer, formats them into
// structured events, and adds each on to a slice that is returned.
func renderEvents(
	eventsRaw []byte,
	lang uint32,
	buffer []byte,
	insertStrings *StringInserts,
) ([]sys.Event, int, error) {
	var events []sys.Event
	var offset int
	for {
		if offset >= len(eventsRaw) {
			break
		}

		// Read a single EVENTLOGRECORD from the buffer.
		record, err := parseEventLogRecord(eventsRaw[offset:])
		if err != nil {
			return nil, 0, err
		}

		var qualifier = uint16((record.eventID & eventIDUpperMask) >> 16)
		var eventID = record.eventID & eventIDLowerMask
		event := sys.Event{
			Provider:        sys.Provider{Name: record.sourceName},
			EventIdentifier: sys.EventIdentifier{ID: eventID, Qualifiers: qualifier},
			LevelRaw:        uint8(record.eventType), // Possible overflow
			TaskRaw:         record.eventCategory,
			TimeCreated:     sys.TimeCreated{unixTime(record.timeGenerated)},
			RecordID:        uint64(record.recordNumber),
			Computer:        record.computerName,
			Level:           string(record.eventType),
		}
		events = append(events, event)
	}

	return events, 0, nil
}

// parseEventLogRecord parses a single Windows EVENTLOGRECORD struct from the
// buffer.
func parseEventLogRecord(buffer []byte) (eventLogRecord, error) {
	var record eventLogRecord
	reader := bytes.NewReader(buffer)

	// Length
	err := binary.Read(reader, binary.LittleEndian, &record.length)
	if err != nil {
		return record, err
	}
	if len(buffer) < int(record.length) {
		return record, fmt.Errorf("Decoded EVENTLOGRECORD length (%d) is "+
			"greater than the buffer length (%d)", record.length, len(buffer))
	}

	// Reserved
	err = binary.Read(reader, binary.LittleEndian, &record.reserved)
	if err != nil {
		return record, err
	}
	if record.reserved != uint32(0x654c664c) {
		return record, fmt.Errorf("Buffer does not contain ELF_LOG_SIGNATURE. "+
			"The data is invalid. Value is %X", record.reserved)
	}

	// Buffer appears to be value so slice it to the adjust length.
	buffer = buffer[:record.length]
	reader = bytes.NewReader(buffer)
	reader.Seek(8, 0)

	// RecordNumber
	err = binary.Read(reader, binary.LittleEndian, &record.recordNumber)
	if err != nil {
		return record, err
	}

	// TimeGenerated
	err = binary.Read(reader, binary.LittleEndian, &record.timeGenerated)
	if err != nil {
		return record, err
	}

	// TimeWritten
	err = binary.Read(reader, binary.LittleEndian, &record.timeWritten)
	if err != nil {
		return record, err
	}

	// EventID
	err = binary.Read(reader, binary.LittleEndian, &record.eventID)
	if err != nil {
		return record, err
	}

	// EventType
	err = binary.Read(reader, binary.LittleEndian, &record.eventType)
	if err != nil {
		return record, err
	}

	// NumStrings
	err = binary.Read(reader, binary.LittleEndian, &record.numStrings)
	if err != nil {
		return record, err
	}

	// EventCategory
	err = binary.Read(reader, binary.LittleEndian, &record.eventCategory)
	if err != nil {
		return record, err
	}

	// ReservedFlags (2 bytes), ClosingRecordNumber (4 bytes)
	_, err = reader.Seek(6, 1)
	if err != nil {
		return record, err
	}

	// StringOffset
	err = binary.Read(reader, binary.LittleEndian, &record.stringOffset)
	if err != nil {
		return record, err
	}
	if record.numStrings > 0 && record.stringOffset > record.length {
		return record, fmt.Errorf("StringOffset value (%d) is invalid "+
			"because it is greater than the Length (%d)", record.stringOffset,
			record.length)
	}

	// UserSidLength
	err = binary.Read(reader, binary.LittleEndian, &record.userSidLength)
	if err != nil {
		return record, err
	}

	// UserSidOffset
	err = binary.Read(reader, binary.LittleEndian, &record.userSidOffset)
	if err != nil {
		return record, err
	}
	if record.userSidLength > 0 && record.userSidOffset > record.length {
		return record, fmt.Errorf("UserSidOffset value (%d) is invalid "+
			"because it is greater than the Length (%d)", record.userSidOffset,
			record.length)
	}

	// DataLength
	err = binary.Read(reader, binary.LittleEndian, &record.dataLength)
	if err != nil {
		return record, err
	}

	// DataOffset
	err = binary.Read(reader, binary.LittleEndian, &record.dataOffset)
	if err != nil {
		return record, err
	}

	// SourceName (null-terminated UTF-16 string)
	begin, _ := reader.Seek(0, 1)
	sourceName, length, err := sys.UTF16BytesToString(buffer[begin:])
	if err != nil {
		return record, err
	}
	record.sourceName = sourceName
	begin, err = reader.Seek(int64(length), 1)
	if err != nil {
		return record, err
	}

	// ComputerName (null-terminated UTF-16 string)
	computerName, length, err := sys.UTF16BytesToString(buffer[begin:])
	if err != nil {
		return record, err
	}
	record.computerName = computerName
	_, err = reader.Seek(int64(length), 1)
	if err != nil {
		return record, err
	}

	return record, nil
}
