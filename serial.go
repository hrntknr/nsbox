package main

type serial struct {
	YYYY int
	MM   int
	DD   int
	N    int
}

func marshalSerial(s *serial) uint32 {
	return uint32(1000000*s.YYYY + 10000*s.MM + 100*s.DD + s.N)
}

func unmarshalSerial(s uint32) *serial {
	remain := int(s)
	YYYY := remain / 1000000
	remain = remain % 1000000
	MM := remain / 10000
	remain = remain % 10000
	DD := remain / 100
	N := remain % 100

	return &serial{
		YYYY: YYYY,
		MM:   MM,
		DD:   DD,
		N:    N,
	}
}
