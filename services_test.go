package bacnet

import (
	"testing"
	"time"
)

const chiller = "4368696C6C65723031204F6E2D54696D653D342E3320486F757273" // "Chiller01 On-Time=4.3 Hours"

// Covers: SIG-IPE-1986
func TestAnnexFManagementVectors(t *testing.T) {
	t.Run("F.4.1 DeviceCommunicationControl", func(t *testing.T) {
		eqHex(t, "request", confirmedWith(5, 4, SvcDeviceCommControl, EncodeDCC(5, DCCStates["disable-initiation"], "#egbdf!")),
			hx(t, "00 04 05 11 09 05 19 02 2D 08 00 23656762646621"))
	})
	t.Run("F.4.4 ReinitializeDevice", func(t *testing.T) {
		eqHex(t, "request", confirmedWith(2, 1, SvcReinitializeDevice, EncodeReinitialize(ReinitStates["warmstart"], "AbCdEfGh")),
			hx(t, "00 01 02 14 09 01 1D 09 00 4162436445664768"))
	})
	t.Run("F.4.7 TimeSynchronization", func(t *testing.T) {
		at := time.Date(1992, 11, 17, 22, 45, 30, 700_000_000, time.UTC)
		eqHex(t, "request", append([]byte{0x10, SvcTimeSync}, EncodeTimeSync(at, time.UTC)...), hx(t, "10 06 A4 5C0B1102 B4 162D1E46"))
	})
	t.Run("F.4.8 Who-Has and I-Have", func(t *testing.T) {
		eqHex(t, "by name", EncodeWhoHas(nil, nil, "OATemp", nil), hx(t, "3D 07 00 4F4154656D70"))
		ai3 := ObjectID{AnalogInput, 3}
		eqHex(t, "by identifier", EncodeWhoHas(nil, nil, "", &ai3), hx(t, "2C 00000003"))
		lo, hi := uint32(8), uint32(8)
		eqHex(t, "with limits", EncodeWhoHas(&lo, &hi, "", &ai3), hx(t, "09 08 19 08 2C 00000003"))
		h, err := DecodeIHave(hx(t, "C4 02000008 C4 00000003 75 07 00 4F4154656D70"))
		if err != nil || h.Device != (ObjectID{8, 8}) || h.Object != ai3 || h.Name != "OATemp" {
			t.Fatalf("I-Have %+v, %v", h, err)
		}
	})
}

// Covers: SIG-IPE-1987
func TestAnnexFFileVectors(t *testing.T) {
	f1, f2 := ObjectID{ObjFile, 1}, ObjectID{ObjFile, 2}
	eqHex(t, "F.2.1 read stream", confirmedWith(0, 2, SvcAtomicReadFile, EncodeAtomicReadFile(f1, false, 0, 27)), hx(t, "00 02 00 06 C4 02800001 0E 31 00 21 1B 0F"))
	r, err := DecodeAtomicReadFileAck(hx(t, "10 0E 31 00 65 1B "+chiller+" 0F"))
	if err != nil || r.Eof || r.Record || r.Start != 0 || string(r.Data) != "Chiller01 On-Time=4.3 Hours" {
		t.Fatalf("stream ack %+v, %v", r, err)
	}
	eqHex(t, "F.2.1 read records", EncodeAtomicReadFile(f2, true, 14, 3), hx(t, "C4 02800002 1E 31 0E 21 03 1F"))
	r, err = DecodeAtomicReadFileAck(hx(t, "11 1E 31 0E 21 02 65 0A 31323A30302C34352E36 65 0A 31323A31352C34342E38 1F"))
	if err != nil || !r.Eof || !r.Record || r.Start != 14 || len(r.Records) != 2 || string(r.Records[1]) != "12:15,44.8" {
		t.Fatalf("record ack %+v, %v", r, err)
	}
	eqHex(t, "F.2.2 write stream", confirmedWith(0x55, 2, SvcAtomicWriteFile, EncodeAtomicWriteFile(f1, 30, []byte("Chiller01 On-Time=4.3 Hours"), nil)),
		hx(t, "00 02 55 07 C4 02800001 0E 31 1E 65 1B "+chiller+" 0F"))
	if p, rec, err := DecodeAtomicWriteFileAck(hx(t, "09 1E")); err != nil || rec || p != 30 {
		t.Fatalf("write ack %d %v %v", p, rec, err)
	}
	eqHex(t, "F.2.2 append records", EncodeAtomicWriteFile(f2, -1, nil, [][]byte{[]byte("12:00,45.6"), []byte("12:15,44.8")}),
		hx(t, "C4 02800002 1E 31 FF 21 02 65 0A 31323A30302C34352E36 65 0A 31323A31352C34342E38 1F"))
	if p, rec, err := DecodeAtomicWriteFileAck(hx(t, "19 0E")); err != nil || !rec || p != 14 {
		t.Fatalf("record write ack %d %v %v", p, rec, err)
	}
}

// Covers: SIG-IPE-1988
func TestAnnexFAccessVectors(t *testing.T) {
	t.Run("F.3.10 WritePropertyMultiple", func(t *testing.T) {
		av := func(i uint32) ObjectID { return ObjectID{AnalogValue, i} }
		b, err := EncodeWritePropertyMultiple([]PropWrite{
			{av(5), PropPresentValue, float32(67), 0}, {av(6), PropPresentValue, float32(67), 0}, {av(7), PropPresentValue, float32(72), 0}})
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "request", confirmedWith(1, 4, SvcWritePropertyMulti, b), hx(t, `00 04 01 10
			0C 00800005 1E 09 55 2E 44 42860000 2F 1F
			0C 00800006 1E 09 55 2E 44 42860000 2F 1F
			0C 00800007 1E 09 55 2E 44 42900000 2F 1F`))
		// WritePropertyMultiple-Error: the error and the first failed write.
		e := DecodeWPMError(hx(t, "0E 91 02 91 25 0F 1E 0C 00800006 19 55 1F"))
		w, ok := e.(*WPMError)
		if !ok || w.Class != 2 || w.Code != 37 || w.Object != av(6) || w.Prop != PropPresentValue {
			t.Fatalf("error %v", e)
		}
	})
	t.Run("F.1.11 SubscribeCOVProperty", func(t *testing.T) {
		inc := float32(1)
		eqHex(t, "request", confirmedWith(0x0f, 2, SvcSubscribeCOVProperty, EncodeSubscribeCOVProperty(18, ObjectID{AnalogInput, 10}, true, 60, PropPresentValue, &inc)),
			hx(t, "00 02 0F 1C 09 12 1C 0000000A 29 01 39 3C 4E 09 55 4F 5C 3F800000"))
	})
	t.Run("F.3.1 AddListElement", func(t *testing.T) {
		eqHex(t, "request", EncodeAddListElement(ObjectID{11, 3}, 53, hx(t, "0C 0000000F 1E 09 55 09 67 1F")),
			hx(t, "0C 02C00003 19 35 3E 0C 0000000F 1E 09 55 09 67 1F 3F"))
	})
	t.Run("F.1.6 GetAlarmSummary", func(t *testing.T) {
		s, err := DecodeGetAlarmSummaryAck(hx(t, "C4 00000002 91 03 82 0560 C4 00000003 91 04 82 05E0"))
		if err != nil || len(s) != 2 || s[0].Object != (ObjectID{0, 2}) || s[0].State != 3 || s[0].Acked.Bits[0] || !s[0].Acked.Bits[2] || s[1].State != 4 {
			t.Fatalf("summary %+v, %v", s, err)
		}
	})
	t.Run("F.1.8 GetEventInformation", func(t *testing.T) {
		eqHex(t, "request", append(hx(t, "02 02 01 1D"), EncodeGetEventInformation(nil)...), hx(t, "02 02 01 1D"))
		s, more, err := DecodeGetEventInformationAck(hx(t, `0E
			0C 00000002 19 03 2A 0560 3E 0C 0F230014 0C FFFFFFFF 0C FFFFFFFF 3F 49 00 5A 05E0 6E 21 0F 21 0F 21 14 6F
			0C 00000003 19 00 2A 05C0 3E 0C 0F280000 0C FFFFFFFF 0C 0F2D1E1E 3F 49 00 5A 05E0 6E 21 0F 21 0F 21 14 6F
			0F 19 00`))
		if err != nil || more || len(s) != 2 {
			t.Fatalf("ack %+v %v %v", s, more, err)
		}
		if s[0].State != 3 || *s[0].Notify != 0 || len(s[0].Stamps) != 3 || s[0].Priorities[2] != 20 || s[1].State != 0 {
			t.Fatalf("summaries %+v", s)
		}
		eqHex(t, "stamp", s[0].Stamps[0], hx(t, "0C 0F230014"))
		if v := StampValue(s[1].Stamps[2], time.UTC); v.(map[string]any)["time"] != "15:45:30.30" {
			t.Fatalf("stamp value %v", v)
		}
	})
}

// Covers: SIG-IPE-1989
func TestRecipientListDestination(t *testing.T) {
	d := Destination{Days: AllWeek(), To: [4]byte{23, 59, 59, 99}, MAC: hx(t, "0A000005BAC0"), Process: 1, Confirmed: false, Trans: AllTransitions()}
	b := EncodeDestination(d)
	eqHex(t, "BACnetDestination", b, hx(t, "82 01FE B4 00000000 B4 173B3B63 1E 21 00 65 06 0A000005BAC0 1F 21 01 10 82 05E0"))
	got, err := DecodeDestinations(append(b, b...))
	if err != nil || len(got) != 2 || got[1].Process != 1 || string(got[1].MAC) != string(d.MAC) || got[1].Device != nil {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	dev := ObjectID{ObjDevice, 99}
	d2 := Destination{Days: AllWeek(), To: [4]byte{23, 59, 59, 99}, Device: &dev, Process: 7, Confirmed: true, Trans: AllTransitions()}
	got, err = DecodeDestinations(EncodeDestination(d2))
	if err != nil || len(got) != 1 || *got[0].Device != dev || !got[0].Confirmed {
		t.Fatalf("decoded %+v, %v", got, err)
	}
}
