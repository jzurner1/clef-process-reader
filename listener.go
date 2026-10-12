package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"mini-soc/api"
	"mini-soc/utils"
	"runtime"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

func StartListener(ctx context.Context, auth utils.AuthDetails) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		log.Fatal(err)
	}
	defer ole.CoUninitialize()

	locator, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		log.Fatal(err)
	}
	defer locator.Release()

	wmi, err := locator.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		log.Fatal(err)
	}
	defer wmi.Release()

	svcRaw, err := oleutil.CallMethod(wmi, "ConnectServer", nil, `root\cimv2`)
	if err != nil {
		log.Fatal(err)
	}
	svc = svcRaw.ToIDispatch()
	defer svc.Release()

	// Seed the name cache with processes that are already running.
	query("SELECT ProcessId, Name FROM Win32_Process", func(row *ole.IDispatch) {
		v, err := oleutil.GetProperty(row, "ProcessId")
		if err == nil {
			names[uint32(v.Val)] = prop(row, "Name")
			v.Clear()
		}
	})

	srcRaw, err := oleutil.CallMethod(svc, "ExecNotificationQuery",
		"SELECT * FROM Win32_ProcessStartTrace")
	if err != nil {
		log.Fatal(err)
	}
	src := srcRaw.ToIDispatch()
	defer src.Release()

	fmt.Println("Listening for new processes...")
	for {
		evRaw, err := oleutil.CallMethod(src, "NextEvent")
		if err != nil {
			log.Fatal(err)
		}
		ev := evRaw.ToIDispatch()

		pidV := oleutil.MustGetProperty(ev, "ProcessID")
		ppidV := oleutil.MustGetProperty(ev, "ParentProcessID")
		pid, ppid := uint32(pidV.Val), uint32(ppidV.Val)
		pidV.Clear()
		ppidV.Clear()

		name := prop(ev, "ProcessName")
		user := userFromSid(ev)
		names[pid] = name

		var cmdline, path string
		query(fmt.Sprintf("SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE ProcessId = %d", pid),
			func(row *ole.IDispatch) {
				cmdline = prop(row, "CommandLine")
				path = prop(row, "ExecutablePath")
			})

		if cmdline == "" || path == "" {
			slog.WarnContext(ctx, "empty process")
			continue
		}

		details := api.ProcessDetails{
			User:    user,
			Parent:  fmt.Sprintf("%s (pid %d)", parentName(ppid), ppid),
			Path:    path,
			Cmdline: cmdline,
		}

		res, err := api.GetClefOpinion(ctx, details, auth)
		if err != nil {
			slog.WarnContext(ctx, "failed to get clef opinion", "err", err)
			continue
		}
		printProcessDetails(ctx, details, res)

		evRaw.Clear()
	}
}

var (
	svc   *ole.IDispatch
	names = map[uint32]string{} // pid -> process name, used for parent lookups
)

func str(v *ole.VARIANT) string {
	if v == nil || v.VT == ole.VT_NULL || v.VT == ole.VT_EMPTY {
		return ""
	}
	return fmt.Sprint(v.Value())
}

func prop(obj *ole.IDispatch, name string) string {
	v, err := oleutil.GetProperty(obj, name)
	if err != nil {
		return ""
	}
	defer v.Clear()
	return str(v)
}

// query runs a WQL query and calls fn for each returned row.
func query(q string, fn func(row *ole.IDispatch)) {
	setRaw, err := oleutil.CallMethod(svc, "ExecQuery", q)
	if err != nil {
		return
	}
	defer setRaw.Clear()
	set := setRaw.ToIDispatch()

	countV, err := oleutil.GetProperty(set, "Count")
	if err != nil {
		return
	}
	n := int(countV.Val)
	countV.Clear()

	for i := 0; i < n; i++ {
		itemRaw, err := oleutil.CallMethod(set, "ItemIndex", i)
		if err != nil {
			break
		}
		fn(itemRaw.ToIDispatch())
		itemRaw.Clear()
	}
}

// userFromSid converts the event's Sid byte array into DOMAIN\user.
func userFromSid(ev *ole.IDispatch) string {
	v, err := oleutil.GetProperty(ev, "Sid")
	if err != nil || v.VT&ole.VT_ARRAY == 0 {
		return ""
	}
	defer v.Clear()
	b := v.ToArray().ToByteArray()
	if len(b) == 0 {
		return ""
	}
	sid := (*windows.SID)(unsafe.Pointer(&b[0]))
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	return domain + `\` + account
}

func parentName(ppid uint32) string {
	if n, ok := names[ppid]; ok {
		return n
	}
	name := ""
	query(fmt.Sprintf("SELECT Name FROM Win32_Process WHERE ProcessId = %d", ppid),
		func(row *ole.IDispatch) { name = prop(row, "Name") })
	if name == "" {
		return "<exited/unknown>"
	}
	return name
}

func printProcessDetails(ctx context.Context, details api.ProcessDetails, clefVal float64) {
	slog.InfoContext(
		ctx,
		"Process observed",
		"path", details.Path,
		"cmdline", details.Cmdline,
		"parent", details.Parent,
		"user", details.User,
		"malicious", clefVal,
	)
}
