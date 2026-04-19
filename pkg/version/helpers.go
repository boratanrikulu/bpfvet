package version

import "github.com/cilium/ebpf/asm"

// Sourced from https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
var HelperVersion = map[asm.BuiltinFunc]KernelVersion{
	// 3.18
	asm.FnMapLookupElem: V(3, 18),
	asm.FnMapUpdateElem: V(3, 18),
	asm.FnMapDeleteElem: V(3, 18),

	// 4.1
	asm.FnProbeRead:         V(4, 1),
	asm.FnKtimeGetNs:        V(4, 1),
	asm.FnTracePrintk:       V(4, 1),
	asm.FnGetPrandomU32:     V(4, 1),
	asm.FnGetSmpProcessorId: V(4, 1),

	// 4.2
	asm.FnTailCall:          V(4, 2),
	asm.FnGetCurrentPidTgid: V(4, 2),
	asm.FnGetCurrentUidGid:  V(4, 2),
	asm.FnGetCurrentComm:    V(4, 2),

	// 4.3
	asm.FnSkbVlanPush: V(4, 3),
	asm.FnSkbVlanPop:  V(4, 3),

	// 4.4
	asm.FnPerfEventOutput: V(4, 4),
	asm.FnRedirect:        V(4, 4),
	asm.FnGetRouteRealm:   V(4, 4),

	// 4.5
	asm.FnSkbLoadBytes:    V(4, 5),
	asm.FnGetStackid:      V(4, 5),
	asm.FnCsumDiff:        V(4, 5),
	asm.FnSkbGetTunnelKey: V(4, 5),
	asm.FnSkbSetTunnelKey: V(4, 5),

	// 4.6
	asm.FnSkbGetTunnelOpt:  V(4, 6),
	asm.FnSkbSetTunnelOpt:  V(4, 6),
	asm.FnSkbChangeProto:   V(4, 6),
	asm.FnSkbChangeType:    V(4, 6),
	asm.FnSkbStoreBytes:    V(4, 6),
	asm.FnL3CsumReplace:    V(4, 6),
	asm.FnL4CsumReplace:    V(4, 6),
	asm.FnXdpAdjustHead:    V(4, 6),
	asm.FnGetCgroupClassid: V(4, 6),
	asm.FnCloneRedirect:    V(4, 6),

	// 4.7
	asm.FnSkbUnderCgroup: V(4, 7),
	asm.FnGetHashRecalc:  V(4, 7),

	// 4.8
	asm.FnGetCurrentTask:    V(4, 8),
	asm.FnProbeWriteUser:    V(4, 8),
	asm.FnPerfEventRead:     V(4, 8),
	asm.FnSkbChangeTail:     V(4, 8),
	asm.FnSkbPullData:       V(4, 8),
	asm.FnCsumUpdate:        V(4, 8),
	asm.FnSetHashInvalid:    V(4, 8),
	asm.FnCurrentTaskUnderCgroup: V(4, 8),

	// 4.9
	asm.FnGetNumaNodeId:  V(4, 9),
	asm.FnSkbChangeHead:  V(4, 9),

	// 4.10
	asm.FnGetSocketCookie: V(4, 10),
	asm.FnGetSocketUid:    V(4, 10),

	// 4.11
	asm.FnProbeReadStr: V(4, 11),
	asm.FnSetHash:      V(4, 11),

	// 4.13
	asm.FnSetsockopt:    V(4, 13),
	asm.FnSkbAdjustRoom: V(4, 13),

	// 4.14
	asm.FnRedirectMap:  V(4, 14),
	asm.FnSkRedirectMap: V(4, 14),
	asm.FnSockMapUpdate: V(4, 14),

	// 4.15
	asm.FnXdpAdjustMeta:     V(4, 15),
	asm.FnPerfEventReadValue: V(4, 15),
	asm.FnPerfProgReadValue:  V(4, 15),
	asm.FnGetsockopt:         V(4, 15),

	// 4.16
	asm.FnOverrideReturn:    V(4, 16),
	asm.FnSockOpsCbFlagsSet: V(4, 16),

	// 4.17
	asm.FnMsgRedirectMap: V(4, 17),
	asm.FnMsgApplyBytes:  V(4, 17),
	asm.FnMsgCorkBytes:   V(4, 17),
	asm.FnMsgPullData:    V(4, 17),
	asm.FnBind:           V(4, 17),

	// 4.18
	asm.FnXdpAdjustTail:       V(4, 18),
	asm.FnSkbGetXfrmState:     V(4, 18),
	asm.FnGetStack:            V(4, 18),
	asm.FnSkbLoadBytesRelative: V(4, 18),
	asm.FnFibLookup:            V(4, 18),
	asm.FnSockHashUpdate:       V(4, 18),
	asm.FnMsgRedirectHash:      V(4, 18),
	asm.FnSkRedirectHash:       V(4, 18),
	asm.FnLwtPushEncap:         V(4, 18),
	asm.FnLwtSeg6StoreBytes:    V(4, 18),
	asm.FnLwtSeg6AdjustSrh:     V(4, 18),
	asm.FnLwtSeg6Action:        V(4, 18),
	asm.FnRcRepeat:             V(4, 18),
	asm.FnRcKeydown:            V(4, 18),
	asm.FnSkbCgroupId:          V(4, 18),
	asm.FnGetCurrentCgroupId:   V(4, 18),
	asm.FnGetLocalStorage:      V(4, 18),

	// 4.19
	asm.FnSkSelectReuseport:  V(4, 19),
	asm.FnSkbAncestorCgroupId: V(4, 19),

	// 4.20
	asm.FnSkLookupTcp:  V(4, 20),
	asm.FnSkLookupUdp:  V(4, 20),
	asm.FnSkRelease:    V(4, 20),
	asm.FnMapPushElem:  V(4, 20),
	asm.FnMapPopElem:   V(4, 20),
	asm.FnMapPeekElem:  V(4, 20),
	asm.FnMsgPushData:  V(4, 20),
	asm.FnMsgPopData:   V(4, 20),
	asm.FnRcPointerRel: V(4, 20),

	// 5.1
	asm.FnSpinLock:   V(5, 1),
	asm.FnSpinUnlock: V(5, 1),
	asm.FnSkFullsock: V(5, 1),
	asm.FnTcpSock:    V(5, 1),
	asm.FnSkbEcnSetCe: V(5, 1),

	// 5.2
	asm.FnGetListenerSock:       V(5, 2),
	asm.FnSkcLookupTcp:          V(5, 2),
	asm.FnTcpCheckSyncookie:     V(5, 2),
	asm.FnSysctlGetName:         V(5, 2),
	asm.FnSysctlGetCurrentValue: V(5, 2),
	asm.FnSysctlGetNewValue:     V(5, 2),
	asm.FnSysctlSetNewValue:     V(5, 2),
	asm.FnStrtol:                V(5, 2),
	asm.FnStrtoul:               V(5, 2),

	// 5.3
	asm.FnSkStorageGet:    V(5, 3),
	asm.FnSkStorageDelete: V(5, 3),
	asm.FnSendSignal:      V(5, 3),
	asm.FnTcpGenSyncookie: V(5, 3),

	// 5.4
	asm.FnSkbOutput: V(5, 4),

	// 5.5
	asm.FnProbeReadUser:      V(5, 5),
	asm.FnProbeReadKernel:    V(5, 5),
	asm.FnProbeReadUserStr:   V(5, 5),
	asm.FnProbeReadKernelStr: V(5, 5),
	asm.FnTcpSendAck:         V(5, 5),
	asm.FnSendSignalThread:   V(5, 5),
	asm.FnJiffies64:          V(5, 5),

	// 5.6
	asm.FnReadBranchRecords:  V(5, 6),
	asm.FnGetNsCurrentPidTgid: V(5, 6),

	// 5.7
	asm.FnXdpOutput:      V(5, 7),
	asm.FnGetNetnsCookie: V(5, 7),
	asm.FnGetCurrentAncestorCgroupId: V(5, 7),

	// 5.8
	asm.FnSkAssign:        V(5, 8),
	asm.FnKtimeGetBootNs:  V(5, 8),
	asm.FnSeqPrintf:       V(5, 8),
	asm.FnSeqWrite:        V(5, 8),
	asm.FnSkCgroupId:      V(5, 8),
	asm.FnSkAncestorCgroupId: V(5, 8),
	asm.FnRingbufOutput:   V(5, 8),
	asm.FnRingbufReserve:  V(5, 8),
	asm.FnRingbufSubmit:   V(5, 8),
	asm.FnRingbufDiscard:  V(5, 8),
	asm.FnRingbufQuery:    V(5, 8),
	asm.FnCsumLevel:       V(5, 8),

	// 5.9
	asm.FnSkcToTcp6Sock:        V(5, 9),
	asm.FnSkcToTcpSock:         V(5, 9),
	asm.FnSkcToTcpTimewaitSock: V(5, 9),
	asm.FnSkcToTcpRequestSock:  V(5, 9),
	asm.FnSkcToUdp6Sock:        V(5, 9),
	asm.FnGetTaskStack:         V(5, 9),

	// 5.10
	asm.FnLoadHdrOpt:       V(5, 10),
	asm.FnStoreHdrOpt:      V(5, 10),
	asm.FnReserveHdrOpt:    V(5, 10),
	asm.FnInodeStorageGet:  V(5, 10),
	asm.FnInodeStorageDelete: V(5, 10),
	asm.FnDPath:             V(5, 10),
	asm.FnCopyFromUser:      V(5, 10),
	asm.FnSnprintfBtf:       V(5, 10),
	asm.FnSeqPrintfBtf:      V(5, 10),
	asm.FnSkbCgroupClassid:  V(5, 10),

	// 5.11
	asm.FnRedirectNeigh:      V(5, 11),
	asm.FnPerCpuPtr:          V(5, 11),
	asm.FnThisCpuPtr:         V(5, 11),
	asm.FnRedirectPeer:       V(5, 11),
	asm.FnTaskStorageGet:     V(5, 11),
	asm.FnTaskStorageDelete:  V(5, 11),
	asm.FnGetCurrentTaskBtf:  V(5, 11),

	// 5.12
	asm.FnBprmOptsSet:       V(5, 12),
	asm.FnKtimeGetCoarseNs:  V(5, 12),
	asm.FnImaInodeHash:      V(5, 12),
	asm.FnSockFromFile:      V(5, 12),

	// 5.13
	asm.FnCheckMtu:         V(5, 13),

	// 5.14
	asm.FnForEachMapElem: V(5, 14),
	asm.FnSnprintf:       V(5, 14),

	// 5.15
	asm.FnTimerInit:        V(5, 15),
	asm.FnTimerSetCallback: V(5, 15),
	asm.FnTimerStart:       V(5, 15),
	asm.FnTimerCancel:      V(5, 15),

	// 5.16
	asm.FnGetFuncIp:        V(5, 16),
	asm.FnGetAttachCookie:  V(5, 16),
	asm.FnTaskPtRegs:       V(5, 16),
	asm.FnGetBranchSnapshot: V(5, 16),

	// 5.17
	asm.FnTraceVprintk:      V(5, 17),
	asm.FnSkcToUnixSock:     V(5, 17),
	asm.FnKallsymsLookupName: V(5, 17),
	asm.FnFindVma:            V(5, 17),
	asm.FnLoop:               V(5, 17),
	asm.FnStrncmp:            V(5, 17),
	asm.FnGetFuncArg:         V(5, 17),
	asm.FnGetFuncRet:         V(5, 17),
	asm.FnGetFuncArgCnt:      V(5, 17),

	// 5.18
	asm.FnGetRetval:       V(5, 18),
	asm.FnSetRetval:       V(5, 18),
	asm.FnXdpGetBuffLen:   V(5, 18),
	asm.FnXdpLoadBytes:    V(5, 18),
	asm.FnXdpStoreBytes:   V(5, 18),

	// 5.19
	asm.FnCopyFromUserTask: V(5, 19),
	asm.FnSkbSetTstamp:     V(5, 19),
	asm.FnImaFileHash:      V(5, 19),
	asm.FnKptrXchg:         V(5, 19),
	asm.FnMapLookupPercpuElem: V(5, 19),

	// 6.0
	asm.FnSkcToMptcpSock:  V(6, 0),
	asm.FnDynptrFromMem:   V(6, 0),
	asm.FnRingbufReserveDynptr: V(6, 0),
	asm.FnRingbufSubmitDynptr:  V(6, 0),
	asm.FnRingbufDiscardDynptr: V(6, 0),
	asm.FnDynptrRead:           V(6, 0),
	asm.FnDynptrWrite:          V(6, 0),
	asm.FnDynptrData:           V(6, 0),

	// 6.1
	asm.FnTcpRawGenSyncookieIpv4:   V(6, 1),
	asm.FnTcpRawGenSyncookieIpv6:   V(6, 1),
	asm.FnTcpRawCheckSyncookieIpv4: V(6, 1),
	asm.FnTcpRawCheckSyncookieIpv6: V(6, 1),
	asm.FnKtimeGetTaiNs:            V(6, 1),
	asm.FnUserRingbufDrain:         V(6, 1),

	// 6.2
	asm.FnCgrpStorageGet:    V(6, 2),
	asm.FnCgrpStorageDelete: V(6, 2),

	// 6.3
	asm.FnSysBpf:            V(6, 3),
	asm.FnBtfFindByNameKind: V(6, 3),
	asm.FnSysClose:          V(6, 3),
}

// LookupHelper returns the kernel version for a helper, and ok=false
// if the helper is not in the map.
func LookupHelper(fn asm.BuiltinFunc) (KernelVersion, bool) {
	v, ok := HelperVersion[fn]
	return v, ok
}
