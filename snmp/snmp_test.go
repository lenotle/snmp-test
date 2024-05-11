package snmp

import (
	"fmt"
	"snmp-test/snmp/scraper"
	"testing"
	"time"
)

var defaultConfig = scraper.ClientConfig{
	Target:    "172.0.1.130",
	Port:      161,
	Version:   scraper.Versionv2c,
	Community: "public",
	Timeout:   3 * time.Second,
	Retries:   2,
}

func printMap(m map[string]string) {
	for k, v := range m {
		fmt.Printf("%v: %v\n", k, v)
	}
}

func TestSnmpClient_GetName(t *testing.T) {
	client := NewClient(&defaultConfig)
	sysDescr, _ := client.GetName("sysDescr")
	sysUpTime, _ := client.GetName("sysUpTime")
	sysName, _ := client.GetName("sysName")
	casaSysConfigLastChanged, _ := client.GetName("casaSysConfigLastChanged")
	casaSysConfigLastSaved, _ := client.GetName("casaSysConfigLastSaved")

	fmt.Println("TestSnmpClient_GetName")
	fmt.Printf("sysDescr: %v\n", sysDescr)
	fmt.Printf("sysUpTime: %v\n", sysUpTime)
	fmt.Printf("sysName: %v\n", sysName)
	fmt.Printf("casaSysConfigLastChanged: %v\n", casaSysConfigLastChanged)
	fmt.Printf("casaSysConfigLastSaved: %v\n", casaSysConfigLastSaved)

	//sysDescr: CASA DCTS smm, HW=CASA-C100G, serial_no SB02CI1S0029, hardware revision 1.1, CFE version 12.5.3, software release version 8.8.3, Ver 6,buildc481
	//sysUpTime: 18295586
	//sysName: C100G-130
	//casaSysConfigLastChanged: 2024-5-7 10:24:11
	//casaSysConfigLastSaved: 2024-5-6 14:50:41
}

func TestSnmpClient_GetNames(t *testing.T) {
	client := NewClient(&defaultConfig)
	ret, err := client.GetNames("sysDescr", "sysUpTime", "sysName", "sysLocation", "sysContact", "casaSysConfigLastChanged", "casaSysConfigLastSaved")
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("\nTestSnmpClient_GetNames:\n")
	printMap(ret)

	//sysDescr: CASA DCTS smm, HW=CASA-C100G, serial_no SB02CI1S0029, hardware revision 1.1, CFE version 12.5.3, software release version 8.8.3, Ver 6,buildc481
	//sysUpTime: 18882827
	//sysName: C100G-130
	//sysLocation: test 102#A
	//sysContact: casaVideoInputProgEsTable
	//casaSysConfigLastChanged: 2024-5-7 10:24:11
	//casaSysConfigLastSaved: 2024-5-6 14:50:41
}

func TestSnmpClient_GetNameByIndexes(t *testing.T) {
	client := NewClient(&defaultConfig)
	ret, err := client.GetNameByIndexes("ifDescr", []string{"1000073", "1000168", "1002460"})
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("\nTestSnmpClient_GetNameByIndexes:\n")
	printMap(ret)

	//1002460: XGige 192:0/0
	//1000073: XGige 6/1
	//1000168: XGige 1:0/0
}

func TestSnmpClient_GetTableByNamesAndIndexes(t *testing.T) {
	client := NewClient(&defaultConfig)
	ret, _ := client.GetTableByNamesAndIndexes([]string{"ifDescr", "ifHCInOctets", "ifHCOutOctets", "ifHighSpeed"}, []string{"1000073", "1000168", "1002460"})

	fmt.Printf("\nTestSnmpClient_GetTableByNamesAndIndexes:\n")
	for _, v := range ret {
		printMap(v)
		fmt.Println()
	}

	//index: 1000073
	//ifHCOutOctets: 0
	//ifHighSpeed: 10000
	//ifDescr: XGige 6/1
	//ifHCInOctets: 0
	//
	//index: 1000168
	//ifHCInOctets: 0
	//ifHCOutOctets: 0
	//ifHighSpeed: 10000
	//ifDescr: XGige 1:0/0
	//
	//index: 1002460
	//ifHighSpeed: 10000
	//ifDescr: XGige 192:0/0
	//ifHCInOctets: 0
	//ifHCOutOctets: 0
}

func TestSnmpClient_GetBulk(t *testing.T) {
	client := NewClient(&defaultConfig)
	ret, err := client.GetBulk("docsRphyRpdDevInfoSysUpTime")
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("\nTestSnmpClient_GetBulk:\n")
	printMap(ret)

	//0.23.16.20.61.76: 0
	//0.23.16.43.103.216: 0
	//0.23.16.43.105.81: 0
	//0.23.16.43.105.88: 0
	//0.24.1.133.0.1: 0
	//0.23.16.42.238.36: 0
	//0.23.16.27.9.8: 2364564
	//0.23.16.38.132.238: 2361664
	//0.23.16.40.210.174: 0
	//0.23.16.40.210.242: 0
	//0.23.16.42.238.4: 0
}

func TestSnmpClient_GetBulkByNames(t *testing.T) {
	client := NewClient(&defaultConfig)
	ret, err := client.GetBulkByNames([]string{"casaModuleStatus", "casaModuleSubType"})
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("\nTestSnmpClient_GetBulkByNames:\n")
	for k, v := range ret {
		fmt.Println(k)
		printMap(v)
		fmt.Println()
	}

	//casaModuleStatus
	//4: primary
	//6: primary
	//8: primary
	//11: primary
	//
	//casaModuleSubType
	//4: QAM_8x96
	//6: SMM_300G
	//8: CSC_8x10G
	//11: UPS_16x8
}

func TestSnmpClient_GetBulkTable(t *testing.T) {
	client := NewClient(&defaultConfig)
	ret, err := client.GetBulkTable("casaRemotePhyNodeEntry")
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("\nTestSnmpClient_GetBulkTable:\n")
	for _, m := range ret {
		printMap(m)
		fmt.Println()
	}

	//casaRemotePhyNodeMacAddress: 00:17:10:2B:69:58
	//casaRemotePhyNodeIpv6Address:
	//casaRemotePhyNodeAdminStatus: down
	//casaRemotePhyNodeMacAddressString: 0017102b6958
	//index: 5
	//casaRemotePhyNodeRowStatus: active
	//casaRemotePhyNodeCinIfIndex: 0
	//casaRemotePhyNodeOperStatus: offline
	//casaRemotePhyNodeDescription:
	//casaRemotePhyNodeType: casa-rpd-310-1x2
	//casaRemotePhyNodeIpv4Address:
	//casaRemotePhyNodeEportIfIndex: 0
	//casaRemotePhyNodeDhcpPrimary: 0
	//casaRemotePhyNodeId: 5
}
