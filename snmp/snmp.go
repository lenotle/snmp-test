package snmp

import (
	"fmt"
	"github.com/gosnmp/gosnmp"
	"github.com/sleepinggenius2/gosmi/types"
	"log/slog"
	"snmp-test/snmp/parse"
	"snmp-test/snmp/scraper"
	"strings"
)

type SnmpClient interface {
	GetName(name string) (string, error)
	GetNames(names ...string) (map[string]string, error)
	GetNameByIndexes(name string, indexes []string) (map[string]string, error)
	GetTableByNamesAndIndexes(names, indexes []string) ([]map[string]string, error)
	GetBulk(name string) (map[string]string, error)
	GetBulkByNames(names []string) (map[string]map[string]string, error)
	GetBulkTable(name string) ([]map[string]string, error)
}

func NewClient(config *scraper.ClientConfig) SnmpClient {
	return &snmp{config: config}
}

var _ SnmpClient = (*snmp)(nil)

type snmp struct {
	config *scraper.ClientConfig
}

//////////////////////////////// Get //////////////////////////////////////////

func (s *snmp) GetName(name string) (string, error) {
	m, err := s.get(name, []string{zeroIndex})
	if err != nil {
		return "", nil
	}
	return m["0"], nil
}

func (s *snmp) GetNames(names ...string) (map[string]string, error) {
	return s.get1(names, zeroIndex)
}

func (s *snmp) GetNameByIndexes(name string, indexes []string) (map[string]string, error) {
	if len(indexes) == 0 {
		indexes = []string{zeroIndex}
	}
	return s.get(name, indexes)
}

func (s *snmp) GetTableByNamesAndIndexes(names, indexes []string) ([]map[string]string, error) {
	if len(names) == 0 {
		return []map[string]string{}, nil
	}
	if len(indexes) == 0 {
		indexes = []string{zeroIndex}
	}

	results := make([]map[string]string, 0, len(indexes))
	for _, index := range indexes {
		nameValue := make(map[string]string)
		nameValue["index"] = index
		ret, err := s.get1(names, index)
		if err == nil {
			for k, v := range ret {
				nameValue[k] = v
			}
		}
		results = append(results, nameValue)
	}
	return results, nil
}

func (s *snmp) get(name string, indexes []string) (map[string]string, error) {
	mibObject := getMibObjByName(name)
	if mibObject == nil {
		return nil, fmt.Errorf("failed to find mib name from db: %v", name)
	}

	oids := make([]string, 0, len(indexes))
	for _, index := range indexes {
		oids = append(oids, AddIndex(mibObject.OID, index))
	}

	client, err := s.initWrapper()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = client.Close()
	}()

	pdus, err := s._get(client, oids)
	if err != nil {
		return nil, err
	}

	indexValueMap := make(map[string]string, len(pdus))
	for _, pdu := range pdus {
		index := GetIndex(mibObject.OID, pdu.Name[1:])
		if index != "" {
			indexValueMap[index] = pduValueAsString(mibObject, &pdu)
		}
	}

	return indexValueMap, nil
}

func (s *snmp) get1(names []string, index string) (map[string]string, error) {
	oidMibObjectMap := make(map[string]*parse.MibObject, len(names))
	oids := make([]string, 0, len(names))
	for _, name := range names {
		object := getMibObjByName(name)
		if object != nil {
			oid := AddIndex(object.OID, index)
			oidMibObjectMap[oid] = object
			oids = append(oids, oid)
		}
	}
	if len(oidMibObjectMap) == 0 {
		return nil, fmt.Errorf("failed to find mib names from db: %v", strings.Join(names, ","))
	}

	client, err := s.initWrapper()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = client.Close()
	}()

	pdus, err := s._get(client, oids)
	if err != nil {
		return nil, err
	}

	nameValueMap := make(map[string]string, len(pdus))
	for _, pdu := range pdus {
		if mib, ok := oidMibObjectMap[pdu.Name[1:]]; ok {
			nameValueMap[mib.Name] = pduValueAsString(mib, &pdu)
		}
	}

	return nameValueMap, nil
}

func (s *snmp) _get(client *scraper.GoSNMPWrapper, getOids []string) ([]gosnmp.SnmpPDU, error) {
	maxOids := s.config.MaxOIDs
	isVersion1 := s.config.Version == scraper.Version1

	// max-repetition can be 0, max-oid can not. SNMPv1 can only report one OID error per call.
	if maxOids == 0 || isVersion1 {
		maxOids = 1
	} else if maxOids > gosnmp.MaxOids {
		maxOids = gosnmp.MaxOids
	}

	var results []gosnmp.SnmpPDU
	for len(getOids) > 0 {
		oidsLen := len(getOids)
		if oidsLen > maxOids {
			oidsLen = maxOids
		}

		packet, err := client.Get(getOids[:oidsLen])
		if err != nil {
			break
		}

		// SNMPv1 will return packet error for unsupported OIDs.
		if packet.Error == gosnmp.NoSuchName && isVersion1 {
			slog.Debug("OID not supported by target", "OID", getOids[0])
			getOids = getOids[oidsLen:]
			continue
		}

		// Response received with errors.
		if packet.Error != gosnmp.NoError {
			return results, fmt.Errorf("packet error, status %d", packet.Error)
		}

		for _, v := range packet.Variables {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance {
				slog.Debug("OID not supported by target", "oids", v.Name)
				continue
			}
			results = append(results, v)
		}

		getOids = getOids[oidsLen:]
	}

	return results, nil
}

///////////////////////////// Get bulk ////////////////////////////////////////////////////////

func (s *snmp) GetBulk(name string) (map[string]string, error) {
	mibObject := getMibObjByName(name)
	if mibObject == nil {
		return nil, fmt.Errorf("failed to find mib %s in db", name)
	}

	pdus, err := s._getBulkByOid(mibObject.OID)
	if err != nil {
		return nil, err
	}

	indexValueMap := make(map[string]string, len(pdus))
	for _, pdu := range pdus {
		index := GetIndex(mibObject.OID, pdu.Name[1:])
		if index != "" {
			indexValueMap[index] = pduValueAsString(mibObject, &pdu)
		}
	}
	return indexValueMap, nil
}

func (s *snmp) GetBulkByNames(names []string) (map[string]map[string]string, error) {
	nameValueMap := make(map[string]map[string]string)
	for _, name := range names {
		ret, err := s.GetBulk(name)
		if err == nil {
			nameValueMap[name] = ret
		}
	}
	return nameValueMap, nil
}

func (s *snmp) GetBulkTable(name string) ([]map[string]string, error) {
	mibObject := getMibObjByName(name)
	if mibObject == nil {
		return nil, fmt.Errorf("failed to find mib %q in db", name)
	}

	pdus, err := s._getBulkByOid(mibObject.OID)
	if err != nil {
		return nil, err
	}

	isChild := func(parentOid, subOid string) bool {
		po, err := types.OidFromString(parentOid)
		if err != nil {
			return false
		}
		so, err := types.OidFromString(subOid)
		if err != nil {
			return false
		}
		return po.ParentOf(so)
	}

	// Simplify the code to get all child-mib-object, not from db or cache
	childIndexMap := make(map[string]*parse.MibObject)
	for _, pdu := range pdus {
		subId := pdu.Name[1:]
		if !isChild(mibObject.OID, subId) {
			continue
		}
		id := GetIndex(mibObject.OID, subId)
		dotIndex := strings.Index(id, ".")
		if dotIndex > 0 {
			childIndex, _ := id[:dotIndex], id[:dotIndex]
			subOid := AddIndex(mibObject.OID, childIndex)
			if mib := getMibObjByOID(subOid); mib != nil {
				childIndexMap[childIndex] = mib
			}
		}
	}

	indexSubValueMap := make(map[string]map[string]string)
	for _, pdu := range pdus {
		subId := pdu.Name[1:]
		if !isChild(mibObject.OID, subId) {
			continue
		}

		id := GetIndex(mibObject.OID, subId)
		dotIndex := strings.Index(id, ".")
		if dotIndex > 0 {
			childIndex, index := id[:dotIndex], id[dotIndex+1:]

			if _, ok := indexSubValueMap[index]; !ok {
				indexSubValueMap[index] = make(map[string]string)
				indexSubValueMap[index]["index"] = index
			}

			if childObj, ok := childIndexMap[childIndex]; ok {
				indexSubValueMap[index][childObj.Name] = pduValueAsString(childObj, &pdu)
			}
		}
	}

	results := make([]map[string]string, 0, len(indexSubValueMap))
	for _, v := range indexSubValueMap {
		results = append(results, v)
	}
	return results, nil
}

func (s *snmp) _getBulkByOid(oid string) ([]gosnmp.SnmpPDU, error) {
	client, err := s.initWrapper()
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = client.Close()
	}()

	pdus, err := client.WalkAll(oid)
	if err != nil {
		return nil, err
	}

	return pdus, nil
}

func (s *snmp) initWrapper() (*scraper.GoSNMPWrapper, error) {
	wrapper, err := scraper.NewGoSNMP(s.config)
	if err != nil {
		return nil, err
	}
	if err = wrapper.Connect(); err != nil {
		return nil, err
	}
	return wrapper, nil
}
