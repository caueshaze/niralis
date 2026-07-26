#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviousBootFailpoint {
    BeforeResolutionIntent,
    AfterResolutionIntent,
    AfterNotReplayed,
    AfterHistoricalResolved,
    AfterRuntimeReleaseIntent,
    AfterRuntimeReleaseConfirmed,
    BeforeUnlink,
    AfterUnlinkBeforeReceipt,
    AfterRemovalReceipt,
    BeforeSeatFree,
}

#[cfg(any(test, feature = "supervisor-test-fixtures"))]
impl PreviousBootFailpoint {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::BeforeResolutionIntent => "before_resolution_intent",
            Self::AfterResolutionIntent => "after_resolution_intent",
            Self::AfterNotReplayed => "after_not_replayed",
            Self::AfterHistoricalResolved => "after_historical_resolved",
            Self::AfterRuntimeReleaseIntent => "after_runtime_release_intent",
            Self::AfterRuntimeReleaseConfirmed => "after_runtime_release_confirmed",
            Self::BeforeUnlink => "before_unlink",
            Self::AfterUnlinkBeforeReceipt => "after_unlink_before_receipt",
            Self::AfterRemovalReceipt => "after_removal_receipt",
            Self::BeforeSeatFree => "before_seat_free",
        }
    }
}

pub(crate) fn hit_previous_boot_failpoint(stage: PreviousBootFailpoint) {
    #[cfg(any(test, feature = "supervisor-test-fixtures"))]
    if std::env::var("NIRALIS_PREVIOUS_BOOT_FAILPOINT")
        .ok()
        .as_deref()
        == Some(stage.as_str())
    {
        std::process::exit(86);
    }
    #[cfg(not(any(test, feature = "supervisor-test-fixtures")))]
    let _ = stage;
}
