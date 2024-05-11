package snmp

import (
	"encoding/binary"
	"fmt"
	"github.com/gosnmp/gosnmp"
	gosmitypes "github.com/sleepinggenius2/gosmi/types"
	"snmp-test/snmp/parse"
	"strconv"
	"strings"
	"time"
)

// /////////////////// used for test /////////////////

func init() {
	parse.LoadMibFromDir("/vob/xll/mibs")
}

func getMibObjByName(name string) *parse.MibObject {
	mib, has := parse.FindMib(name)
	if !has {
		fmt.Println("failed to find: ", name)
	}
	return mib
}

func getMibObjByOID(oid string) *parse.MibObject {
	mib, has := parse.FindMib(oid)
	if !has {
		fmt.Println("failed to find: ", oid)
	}
	return mib
}

/////////////////////////////////////////////////////////

const zeroIndex = ".0"

func AddIndex(oid, index string) string {
	if index == "" {
		return oid
	}

	if strings.HasPrefix(index, ".") {
		return fmt.Sprintf("%s%s", oid, index)
	}

	return fmt.Sprintf("%s.%s", oid, index)
}

func GetIndex(parentOid, subOid string) string {
	if !strings.HasPrefix(subOid, parentOid) {
		return ""
	}

	return subOid[len(parentOid)+1:]
}

func pduValueAsString(mib *parse.MibObject, pdu *gosnmp.SnmpPDU) string {
	if mib == nil || pdu == nil {
		return ""
	}

	switch gosmitypes.BaseType(mib.SmiType) {
	case gosmitypes.BaseTypeInteger32, gosmitypes.BaseTypeUnsigned32, gosmitypes.BaseTypeInteger64, gosmitypes.BaseTypeUnsigned64, gosmitypes.BaseTypeFloat32, gosmitypes.BaseTypeFloat64, gosmitypes.BaseTypeFloat128:
		val := gosnmp.ToBigInt(pdu.Value)
		return val.String()
	case gosmitypes.BaseTypeOctetString:
		return octetTypeAsString(mib.Type, pdu.Value)
	case gosmitypes.BaseTypeObjectIdentifier:
		return pdu.Value.(string)[1:]
	case gosmitypes.BaseTypeEnum:
		return enumAsString(int(gosnmp.ToBigInt(pdu.Value).Int64()), mib.Syntax)
	case gosmitypes.BaseTypeBits:
		return bitsAsString(pdu.Value, mib.Syntax)
	case gosmitypes.BaseTypePointer:
		fallthrough
	case gosmitypes.BaseTypeUnknown:
		fallthrough
	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

func octetTypeAsString(typ string, value interface{}) string {
	bytes, ok := value.([]byte)
	if !ok {
		return ""
	}

	str := bytesOidsAsString(bytes, typ)
	return strings.ToValidUTF8(str, "�")
}

func bytes2Ints(bytes []byte) []int {
	parts := make([]int, len(bytes))
	for i, o := range bytes {
		parts[i] = int(o)
	}
	return parts
}

func bytesOidsAsString(bytes []byte, typ string) string {
	indexOids := bytes2Ints(bytes)

	switch typ {
	case "MacAddress":
		parts := make([]string, 6)
		for i, o := range indexOids {
			parts[i] = fmt.Sprintf("%02X", o)
		}
		return strings.Join(parts, ":")
	case "InetAddress", "InetAddressIPv4", "InetAddressIPv6":
		return toIp(indexOids)
	case "TAddress":
		return toTAddress(indexOids)
	case "OctetString":
		parts := make([]byte, len(indexOids))
		for i, o := range indexOids {
			parts[i] = byte(o)
		}
		if len(parts) == 0 {
			return ""
		}
		//return fmt.Sprintf("0x%X", string(parts))
		return string(parts)
	case "DisplayString":
		parts := make([]byte, len(indexOids))
		for i, o := range indexOids {
			parts[i] = byte(o)
		}
		return string(parts)
	case "DateAndTime":
		return fmt.Sprintf("%d-%d-%d %d:%d:%d",
			int(binary.BigEndian.Uint16(bytes[0:2])),
			time.Month(bytes[2]),
			int(bytes[3]),
			int(bytes[4]),
			int(bytes[5]),
			int(bytes[6]),
		)
	default:
		return string(bytes)
	}
}

func toIp(ipArr []int) string {
	switch len(ipArr) {
	case 4:
		return toIpv4(ipArr)
	case 6:
		return toIpv6(ipArr)
	default:
		return ""
	}
}

func toIpv4(ipArr []int) string {
	parts := make([]string, 4)
	for i, o := range ipArr {
		parts[i] = strconv.Itoa(o)
	}
	return strings.Join(parts, ".")
}

func toIpv6(ipArr []int) string {
	parts := make([]interface{}, 16)
	for i, o := range ipArr {
		parts[i] = o
	}
	return fmt.Sprintf("%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", parts...)
}

func toTAddress(indexOids []int) string {
	ipArr, portArr := indexOids[:4], indexOids[4:]

	ip := toIp(ipArr)
	port := (portArr[0] << 8) + portArr[1]

	return fmt.Sprintf("%s/%d", ip, port)
}

func enumAsString(valueName int, enumValues map[int]string) string {
	ret, ok := enumValues[valueName]
	if ok {
		return ret
	}
	return strconv.Itoa(valueName)
}

func bitsAsString(value interface{}, bitsValues map[int]string) string {
	bytes, ok := value.([]byte)
	if !ok {
		return ""
	}

	var ret string
	for k, v := range bitsValues {
		bitOn := false

		// most significant byte most significant bit, then most significant byte 2nd most significant bit
		if k < len(bytes)*8 {
			if (bytes[k/8] & (128 >> (k % 8))) != 0 {
				bitOn = true
			}
		}

		if bitOn {
			ret += " " + v
		}
	}

	return ret
}
