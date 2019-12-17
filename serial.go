package main

import "time"

type serial struct {
	YYYY int
	MM   int
	DD   int
	N    int
}

func (s *serial) toSerial() uint32 {
	return uint32(1000000*s.YYYY + 10000*s.MM + 100*s.DD + s.N)
}

var serials map[string]serial = map[string]serial{}

func initSerial(zones *[]Zone) {
	now := time.Now()
	for _, zone := range *zones {
		serials[zone.Suffix] = serial{
			YYYY: now.Year(),
			MM:   int(now.Month()),
			DD:   now.Day(),
			N:    1,
		}
	}
}

func getSerial(zoneName string) uint32 {
	serial, ok := serials[zoneName]
	if ok {
		return serial.toSerial()
	}
	return 0
}

func updateSerial(zoneName string) {
	now := time.Now()
	n := 1
	if serials[zoneName].YYYY == now.Year() &&
		serials[zoneName].MM == int(now.Month()) &&
		serials[zoneName].DD == now.Day() {
		n = serials[zoneName].N + 1
	}
	serials[zoneName] = serial{
		YYYY: now.Year(),
		MM:   int(now.Month()),
		DD:   now.Day(),
		N:    n,
	}
}
