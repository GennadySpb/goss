// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/cheekybits/genny

package resource

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/aelsabbahy/goss/system"
	"github.com/aelsabbahy/goss/util"
)

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type AddrMap map[string]*Addr

func (r AddrMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Addr, error) {
	sysres, err := sys.NewAddr(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewAddr(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r AddrMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Addr, system.Addr, bool, error) {
	sysres, err := sys.NewAddr(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewAddr(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *AddrMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Addr{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Addr
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *AddrMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Addr{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Addr
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type CommandMap map[string]*Command

func (r CommandMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Command, error) {
	sysres, err := sys.NewCommand(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewCommand(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r CommandMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Command, system.Command, bool, error) {
	sysres, err := sys.NewCommand(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewCommand(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *CommandMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Command{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Command
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *CommandMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Command{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Command
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type DNSMap map[string]*DNS

func (r DNSMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*DNS, error) {
	sysres, err := sys.NewDNS(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewDNS(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r DNSMap) AppendSysResourceIfExists(sr string, sys *system.System) (*DNS, system.DNS, bool, error) {
	sysres, err := sys.NewDNS(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewDNS(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *DNSMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := DNS{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*DNS
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *DNSMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := DNS{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*DNS
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type FileMap map[string]*File

func (r FileMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*File, error) {
	sysres, err := sys.NewFile(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewFile(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r FileMap) AppendSysResourceIfExists(sr string, sys *system.System) (*File, system.File, bool, error) {
	sysres, err := sys.NewFile(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewFile(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *FileMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := File{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*File
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *FileMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := File{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*File
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type GossfileMap map[string]*Gossfile

func (r GossfileMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Gossfile, error) {
	sysres, err := sys.NewGossfile(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewGossfile(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r GossfileMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Gossfile, system.Gossfile, bool, error) {
	sysres, err := sys.NewGossfile(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewGossfile(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *GossfileMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Gossfile{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Gossfile
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *GossfileMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Gossfile{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Gossfile
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type GroupMap map[string]*Group

func (r GroupMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Group, error) {
	sysres, err := sys.NewGroup(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewGroup(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r GroupMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Group, system.Group, bool, error) {
	sysres, err := sys.NewGroup(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewGroup(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *GroupMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Group{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Group
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *GroupMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Group{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Group
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type PackageMap map[string]*Package

func (r PackageMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Package, error) {
	sysres, err := sys.NewPackage(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewPackage(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r PackageMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Package, system.Package, bool, error) {
	sysres, err := sys.NewPackage(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewPackage(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *PackageMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Package{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Package
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *PackageMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Package{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Package
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type PortMap map[string]*Port

func (r PortMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Port, error) {
	sysres, err := sys.NewPort(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewPort(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r PortMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Port, system.Port, bool, error) {
	sysres, err := sys.NewPort(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewPort(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *PortMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Port{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Port
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *PortMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Port{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Port
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type ProcessMap map[string]*Process

func (r ProcessMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Process, error) {
	sysres, err := sys.NewProcess(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewProcess(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r ProcessMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Process, system.Process, bool, error) {
	sysres, err := sys.NewProcess(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewProcess(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *ProcessMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Process{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Process
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *ProcessMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Process{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Process
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type ServiceMap map[string]*Service

func (r ServiceMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Service, error) {
	sysres, err := sys.NewService(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewService(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r ServiceMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Service, system.Service, bool, error) {
	sysres, err := sys.NewService(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewService(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *ServiceMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Service{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Service
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *ServiceMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Service{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Service
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type UserMap map[string]*User

func (r UserMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*User, error) {
	sysres, err := sys.NewUser(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewUser(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r UserMap) AppendSysResourceIfExists(sr string, sys *system.System) (*User, system.User, bool, error) {
	sysres, err := sys.NewUser(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewUser(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *UserMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := User{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*User
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *UserMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := User{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*User
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type KernelParamMap map[string]*KernelParam

func (r KernelParamMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*KernelParam, error) {
	sysres, err := sys.NewKernelParam(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewKernelParam(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r KernelParamMap) AppendSysResourceIfExists(sr string, sys *system.System) (*KernelParam, system.KernelParam, bool, error) {
	sysres, err := sys.NewKernelParam(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewKernelParam(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *KernelParamMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := KernelParam{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*KernelParam
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *KernelParamMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := KernelParam{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*KernelParam
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type MountMap map[string]*Mount

func (r MountMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Mount, error) {
	sysres, err := sys.NewMount(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewMount(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r MountMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Mount, system.Mount, bool, error) {
	sysres, err := sys.NewMount(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewMount(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *MountMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Mount{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Mount
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *MountMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Mount{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Mount
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type InterfaceMap map[string]*Interface

func (r InterfaceMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*Interface, error) {
	sysres, err := sys.NewInterface(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewInterface(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r InterfaceMap) AppendSysResourceIfExists(sr string, sys *system.System) (*Interface, system.Interface, bool, error) {
	sysres, err := sys.NewInterface(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewInterface(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *InterfaceMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := Interface{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Interface
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *InterfaceMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := Interface{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*Interface
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

//go:generate sed -i -e "/^\\/\\/ +build genny/d" resource_list.go
//go:generate goimports -w resource_list.go resource_list.go

type HTTPMap map[string]*HTTP

func (r HTTPMap) AppendSysResource(sr string, sys *system.System, config util.Config) (*HTTP, error) {
	sysres, err := sys.NewHTTP(sr, sys, config)
	if err != nil {
		return nil, err
	}
	res, err := NewHTTP(sysres, config)
	if err != nil {
		return nil, err
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, nil
}

func (r HTTPMap) AppendSysResourceIfExists(sr string, sys *system.System) (*HTTP, system.HTTP, bool, error) {
	sysres, err := sys.NewHTTP(sr, sys, util.Config{})
	if err != nil {
		return nil, nil, false, err
	}
	// FIXME: Do we want to be silent about errors?
	res, _ := NewHTTP(sysres, util.Config{})
	if e, _ := sysres.Exists(); e != true {
		return res, sysres, false, nil
	}
	if old_res, ok := r[res.ID()]; ok {
		res.Title = old_res.Title
		res.Meta = old_res.Meta
	}
	r[res.ID()] = res
	return res, sysres, true, nil
}

func (ret *HTTPMap) UnmarshalJSON(data []byte) error {
	// Curried json.Unmarshal
	unmarshal := func(i interface{}) error {
		if err := json.Unmarshal(data, i); err != nil {
			return err
		}
		return nil
	}

	// Validate configuration
	zero := HTTP{}
	whitelist, err := util.WhitelistAttrs(zero, util.JSON)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*HTTP
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}

func (ret *HTTPMap) UnmarshalYAML(unmarshal func(v interface{}) error) error {
	// Validate configuration
	zero := HTTP{}
	whitelist, err := util.WhitelistAttrs(zero, util.YAML)
	if err != nil {
		return err
	}
	if err := util.ValidateSections(unmarshal, zero, whitelist); err != nil {
		return err
	}

	var tmp map[string]*HTTP
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	typ := reflect.TypeOf(zero)
	typs := strings.Split(typ.String(), ".")[1]
	for id, res := range tmp {
		if res == nil {
			return fmt.Errorf("Could not parse resource %s:%s", typs, id)
		}
		res.SetID(id)
	}

	*ret = tmp
	return nil
}
