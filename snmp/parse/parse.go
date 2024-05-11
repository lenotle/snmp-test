package parse

import (
	"fmt"
	"github.com/sleepinggenius2/gosmi"
	"github.com/sleepinggenius2/gosmi/smi"
	"github.com/sleepinggenius2/gosmi/types"
	"os"
	"snmp-test/set"
	"strings"
)

type MibObject struct {
	Name      string
	OID       string
	ParentOID string
	Type      string
	SmiType   int
	Syntax    map[int]string
	Access    string
}

var tree = make(map[string]*MibObject, 1024*10)

func FindMib(name string) (*MibObject, bool) {
	v, ok := tree[name]
	return v, ok
}

func load(dir string) set.Set[string] {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("failLoad to read dir: %s\n", err)
		return nil
	}

	var failLoad []string
	var successLoad = set.New[string]()
	for _, entry := range dirEntries {
		info, err := entry.Info()
		if err != nil {
			failLoad = append(failLoad, entry.Name())
			continue
		}

		// skipping subdirectory and symlink
		if info.Mode().IsRegular() {
			moduleName, err := gosmi.LoadModule(info.Name())
			if err != nil {
				failLoad = append(failLoad, info.Name())
			} else {
				successLoad.Add(moduleName)
			}
		}
	}

	if len(failLoad) > 0 {
		fmt.Printf("failed to load (%d) mibs: %s\n", len(failLoad), strings.Join(failLoad, ","))
	}
	return successLoad
}

func buildMibObject(modules set.Set[string]) {
	for module := range modules {
		m, err := gosmi.GetModule(module)
		if err != nil {
			fmt.Printf("failed to get module (%s) information, err: %v\n", module, err)
			continue
		}

		for _, node := range m.GetNodes() {
			if node.OidLen == 0 || node.Name == "zeroDotZero" {
				continue
			}

			mib := &MibObject{
				Name:   node.Name,
				OID:    node.Oid.String(),
				Access: node.Access.String(),
			}
			if node.Type != nil {
				mib.Type = node.Type.Name
				mib.SmiType = int(node.Type.BaseType)
				nodeEnum := node.Type.Enum
				switch node.Type.BaseType {
				case types.BaseTypeEnum, types.BaseTypeBits:
					if nodeEnum != nil && len(nodeEnum.Values) != 0 {
						mib.Syntax = make(map[int]string, len(nodeEnum.Values))
						for _, value := range nodeEnum.Values {
							mib.Syntax[int(value.Value)] = value.Name
						}
					}
				}
			}
			if parent := smi.GetParentNode(node.GetRaw()); parent != nil {
				mib.ParentOID = parent.Oid.String()
			}

			tree[mib.OID] = mib
			tree[mib.Name] = mib
		}
	}
}

func LoadMibFromDir(dir string) {
	gosmi.Init()
	gosmi.SetPath(dir)
	defer gosmi.Exit()

	modules := load(dir)
	buildMibObject(modules)
}
