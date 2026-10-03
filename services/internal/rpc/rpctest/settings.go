package rpctest

import (
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Settings are the network's Soroban fees and limits, as its config settings publish them. Fees
// are in stroops: instructions per 10,000, entries each and bytes per 1 KiB.
type Settings struct {
	InstructionFee                                    int64
	MaxInstructions                                   uint32
	DiskReadEntryFee, WriteEntryFee                   int64
	DiskRead1KB, Write1KB, Historical1KB              int64
	TxSize1KB, Events1KB                              int64
	MaxDiskReadEntries, MaxWriteEntries, MaxFootprint uint32
	MaxDiskReadBytes, MaxWriteBytes                   uint32
	RentLow, RentHigh, StateTarget, StateSize         int64
	RentGrowth                                        uint32
	RentDenominator                                   int64
	MinPersistentTTL                                  uint32
	MaxTxBytes, MaxEventsBytes                        uint32
}

// Mainnet are mainnet's settings at ledger 64,754,596.
var Mainnet = Settings{
	InstructionFee: 7, MaxInstructions: 400_000_000,
	DiskReadEntryFee: 1_563, WriteEntryFee: 2_500,
	DiskRead1KB: 447, Write1KB: 875, Historical1KB: 4_059, TxSize1KB: 406, Events1KB: 5_000,
	MaxDiskReadEntries: 200, MaxWriteEntries: 200, MaxFootprint: 400,
	MaxDiskReadBytes: 200_000, MaxWriteBytes: 132_096,
	RentLow: -17_000, RentHigh: 10_000, StateTarget: 3_000_000_000, StateSize: 1_664_203_878, RentGrowth: 5_000,
	RentDenominator: 1_215, MinPersistentTTL: 2_073_600,
	MaxTxBytes: 132_096, MaxEventsBytes: 16_384,
}

// SetSettings publishes the network's Soroban settings.
func (f *Fake) SetSettings(s Settings) {
	window := make([]xdr.Uint64, 30)
	for i := range window {
		window[i] = xdr.Uint64(s.StateSize)
	}
	for _, c := range []xdr.ConfigSettingEntry{
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingContractComputeV0, ContractCompute: &xdr.ConfigSettingContractComputeV0{
			FeeRatePerInstructionsIncrement: xdr.Int64(s.InstructionFee), TxMaxInstructions: xdr.Int64(s.MaxInstructions),
		}},
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingContractLedgerCostV0, ContractLedgerCost: &xdr.ConfigSettingContractLedgerCostV0{
			TxMaxDiskReadEntries: xdr.Uint32(s.MaxDiskReadEntries), TxMaxDiskReadBytes: xdr.Uint32(s.MaxDiskReadBytes),
			TxMaxWriteLedgerEntries: xdr.Uint32(s.MaxWriteEntries), TxMaxWriteBytes: xdr.Uint32(s.MaxWriteBytes),
			FeeDiskReadLedgerEntry: xdr.Int64(s.DiskReadEntryFee), FeeWriteLedgerEntry: xdr.Int64(s.WriteEntryFee), FeeDiskRead1Kb: xdr.Int64(s.DiskRead1KB),
			SorobanStateTargetSizeBytes: xdr.Int64(s.StateTarget), RentFee1KbSorobanStateSizeLow: xdr.Int64(s.RentLow),
			RentFee1KbSorobanStateSizeHigh: xdr.Int64(s.RentHigh), SorobanStateRentFeeGrowthFactor: xdr.Uint32(s.RentGrowth),
		}},
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingContractLedgerCostExtV0, ContractLedgerCostExt: &xdr.ConfigSettingContractLedgerCostExtV0{
			TxMaxFootprintEntries: xdr.Uint32(s.MaxFootprint), FeeWrite1Kb: xdr.Int64(s.Write1KB),
		}},
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingContractHistoricalDataV0, ContractHistoricalData: &xdr.ConfigSettingContractHistoricalDataV0{
			FeeHistorical1Kb: xdr.Int64(s.Historical1KB),
		}},
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingContractEventsV0, ContractEvents: &xdr.ConfigSettingContractEventsV0{
			TxMaxContractEventsSizeBytes: xdr.Uint32(s.MaxEventsBytes), FeeContractEvents1Kb: xdr.Int64(s.Events1KB),
		}},
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingContractBandwidthV0, ContractBandwidth: &xdr.ConfigSettingContractBandwidthV0{
			TxMaxSizeBytes: xdr.Uint32(s.MaxTxBytes), FeeTxSize1Kb: xdr.Int64(s.TxSize1KB),
		}},
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingStateArchival, StateArchivalSettings: &xdr.StateArchivalSettings{
			MaxEntryTtl: 3_110_400, MinPersistentTtl: xdr.Uint32(s.MinPersistentTTL), PersistentRentRateDenominator: xdr.Int64(s.RentDenominator),
		}},
		{ConfigSettingId: xdr.ConfigSettingIdConfigSettingLiveSorobanStateSizeWindow, LiveSorobanStateSizeWindow: &window},
	} {
		f.SetEntry(vault.ConfigSettingKey(c.ConfigSettingId), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeConfigSetting, ConfigSetting: &c}, 1, nil)
	}
}
