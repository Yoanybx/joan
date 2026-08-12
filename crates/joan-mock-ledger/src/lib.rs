//! Deterministic in-memory ledger for dispute simulation without real money.

use joan_canonical::{CanonicalError, Digest, digest_serializable};
use joan_dispute::{AutomaticDecisionReceipt, RemedyKind, verify_decision};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_HOLDS: usize = 100_000;
const MAX_IDEMPOTENCY_KEYS: usize = 200_000;

/// State of one simulated economic hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HoldStatus {
    /// Value is reserved and available for one decision.
    Reserved,
    /// Full value was released to provider.
    Settled,
    /// Full value was refunded to buyer.
    Refunded,
    /// Value was split between buyer and provider.
    Split,
    /// Value remains held for a repair cycle.
    RepairPending,
    /// Value remains frozen by the automatic safety fallback.
    Quarantined,
}

/// One simulated hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockHold {
    /// Stable hold identifier.
    pub hold_id: String,
    /// Buyer account.
    pub buyer_id: String,
    /// Provider account.
    pub provider_id: String,
    /// Exact contract digest.
    pub contract_digest: Digest,
    /// Initially reserved amount.
    pub original_amount_microunits: u64,
    /// Amount still locked after any decision.
    pub locked_amount_microunits: u64,
    /// Current status.
    pub status: HoldStatus,
    /// Applied decision, if any.
    pub decision_digest: Option<Digest>,
}

/// Entire deterministic ledger snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockLedger {
    /// Schema identifier.
    pub schema: String,
    /// Available account balances.
    pub balances: BTreeMap<String, u64>,
    /// Holds keyed by stable identifier.
    pub holds: BTreeMap<String, MockHold>,
    /// Consume-once operation keys.
    pub consumed_idempotency_keys: BTreeSet<String>,
    /// Monotonic ledger revision.
    pub revision: u64,
    /// Total value at ledger creation.
    pub initial_total_microunits: u64,
    /// Digest of every protected field above.
    pub ledger_root: Digest,
}

/// Exact-precondition reserve request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveRequest {
    /// Schema identifier.
    pub schema: String,
    /// Expected ledger root.
    pub expected_ledger_root: Digest,
    /// Expected revision.
    pub expected_revision: u64,
    /// Stable hold identifier.
    pub hold_id: String,
    /// Buyer account.
    pub buyer_id: String,
    /// Provider account.
    pub provider_id: String,
    /// Exact contract digest.
    pub contract_digest: Digest,
    /// Amount to reserve.
    pub amount_microunits: u64,
    /// Consume-once key.
    pub idempotency_key: String,
}

/// Exact-precondition decision application request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyDecisionRequest {
    /// Schema identifier.
    pub schema: String,
    /// Expected ledger root.
    pub expected_ledger_root: Digest,
    /// Expected revision.
    pub expected_revision: u64,
    /// Hold controlled by the decision.
    pub hold_id: String,
    /// Consume-once key.
    pub idempotency_key: String,
    /// Verified automatic decision.
    pub decision: AutomaticDecisionReceipt,
}

/// Receipt for a simulated ledger mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerMutationReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Stable operation kind.
    pub operation: String,
    /// Prior ledger root.
    pub prior_ledger_root: Digest,
    /// New ledger root.
    pub new_ledger_root: Digest,
    /// New revision.
    pub revision: u64,
    /// Affected hold.
    pub hold_id: String,
    /// Digest of the exact request.
    pub request_digest: Digest,
    /// Total value after the mutation.
    pub conserved_total_microunits: u64,
    /// True after every invariant passes.
    pub committed: bool,
}

/// Mock-ledger failure.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Canonical encoding or hashing failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Automatic decision failed verification.
    #[error(transparent)]
    Dispute(#[from] joan_dispute::DisputeError),
    /// Unsupported schema.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    /// Required field is empty.
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    /// Stored root or conservation invariant is invalid.
    #[error("stored mock ledger is invalid")]
    InvalidStoredLedger,
    /// Expected root did not match.
    #[error("expected mock ledger root does not match")]
    StaleRoot,
    /// Expected revision did not match.
    #[error("expected mock ledger revision does not match")]
    StaleRevision,
    /// Consume-once operation key was already used.
    #[error("mock ledger operation was replayed")]
    Replay,
    /// A required account does not exist.
    #[error("unknown account: {0}")]
    UnknownAccount(String),
    /// Buyer and provider must differ.
    #[error("buyer and provider accounts must differ")]
    SameAccount,
    /// Hold identifier already exists.
    #[error("duplicate hold: {0}")]
    DuplicateHold(String),
    /// Hold does not exist.
    #[error("unknown hold: {0}")]
    UnknownHold(String),
    /// Account cannot fund reservation.
    #[error("insufficient buyer balance")]
    InsufficientBalance,
    /// Hold already consumed a decision.
    #[error("hold is not reserved")]
    HoldNotReserved,
    /// Decision allocation does not equal the held amount.
    #[error("decision allocation does not match hold amount")]
    AllocationMismatch,
    /// Defensive capacity was exceeded.
    #[error("mock ledger capacity exhausted")]
    Capacity,
    /// Integer arithmetic overflowed.
    #[error("mock ledger amount overflow")]
    AmountOverflow,
}

#[derive(Serialize)]
struct LedgerCore<'a> {
    schema: &'a str,
    balances: &'a BTreeMap<String, u64>,
    holds: &'a BTreeMap<String, MockHold>,
    consumed_idempotency_keys: &'a BTreeSet<String>,
    revision: u64,
    initial_total_microunits: u64,
}

/// Create a deterministic ledger from explicit account balances.
pub fn create_ledger(balances: BTreeMap<String, u64>) -> Result<MockLedger, LedgerError> {
    if balances.is_empty() {
        return Err(LedgerError::Capacity);
    }
    for account in balances.keys() {
        require_nonempty(account, "account_id")?;
    }
    let initial_total_microunits = checked_sum(balances.values().copied())?;
    let mut ledger = MockLedger {
        schema: "joan.mock-ledger.v0".to_owned(),
        balances,
        holds: BTreeMap::new(),
        consumed_idempotency_keys: BTreeSet::new(),
        revision: 0,
        initial_total_microunits,
        ledger_root: placeholder_digest(),
    };
    ledger.ledger_root = compute_ledger_root(&ledger)?;
    Ok(ledger)
}

/// Verify root and conservation of available plus locked value.
pub fn verify_ledger(ledger: &MockLedger) -> Result<(), LedgerError> {
    if ledger.schema != "joan.mock-ledger.v0" {
        return Err(LedgerError::UnsupportedSchema(ledger.schema.clone()));
    }
    for (key, hold) in &ledger.holds {
        if key != &hold.hold_id || hold.locked_amount_microunits > hold.original_amount_microunits {
            return Err(LedgerError::InvalidStoredLedger);
        }
    }
    if total_value(ledger)? != ledger.initial_total_microunits
        || compute_ledger_root(ledger)? != ledger.ledger_root
    {
        return Err(LedgerError::InvalidStoredLedger);
    }
    Ok(())
}

/// Reserve value into a new hold on an isolated ledger clone.
pub fn reserve(
    ledger: &MockLedger,
    request: &ReserveRequest,
) -> Result<(MockLedger, LedgerMutationReceipt), LedgerError> {
    verify_ledger(ledger)?;
    validate_preconditions(
        ledger,
        &request.expected_ledger_root,
        request.expected_revision,
        &request.idempotency_key,
    )?;
    if request.schema != "joan.mock-reserve-request.v0" {
        return Err(LedgerError::UnsupportedSchema(request.schema.clone()));
    }
    require_nonempty(&request.hold_id, "hold_id")?;
    require_nonempty(&request.buyer_id, "buyer_id")?;
    require_nonempty(&request.provider_id, "provider_id")?;
    if request.buyer_id == request.provider_id {
        return Err(LedgerError::SameAccount);
    }
    if request.amount_microunits == 0 {
        return Err(LedgerError::AllocationMismatch);
    }
    if ledger.holds.len() >= MAX_HOLDS {
        return Err(LedgerError::Capacity);
    }
    if ledger.holds.contains_key(&request.hold_id) {
        return Err(LedgerError::DuplicateHold(request.hold_id.clone()));
    }
    if !ledger.balances.contains_key(&request.provider_id) {
        return Err(LedgerError::UnknownAccount(request.provider_id.clone()));
    }
    let buyer_balance = ledger
        .balances
        .get(&request.buyer_id)
        .copied()
        .ok_or_else(|| LedgerError::UnknownAccount(request.buyer_id.clone()))?;
    let remaining = buyer_balance
        .checked_sub(request.amount_microunits)
        .ok_or(LedgerError::InsufficientBalance)?;

    let prior_root = ledger.ledger_root.clone();
    let mut candidate = ledger.clone();
    candidate
        .balances
        .insert(request.buyer_id.clone(), remaining);
    candidate.holds.insert(
        request.hold_id.clone(),
        MockHold {
            hold_id: request.hold_id.clone(),
            buyer_id: request.buyer_id.clone(),
            provider_id: request.provider_id.clone(),
            contract_digest: request.contract_digest.clone(),
            original_amount_microunits: request.amount_microunits,
            locked_amount_microunits: request.amount_microunits,
            status: HoldStatus::Reserved,
            decision_digest: None,
        },
    );
    finish_mutation(
        candidate,
        request.idempotency_key.clone(),
        prior_root,
        request.hold_id.clone(),
        "reserve",
        digest_serializable("joan.mock-reserve-request.v0", request)?,
    )
}

/// Apply one verified automatic decision to one reserved hold.
pub fn apply_decision(
    ledger: &MockLedger,
    request: &ApplyDecisionRequest,
) -> Result<(MockLedger, LedgerMutationReceipt), LedgerError> {
    verify_ledger(ledger)?;
    validate_preconditions(
        ledger,
        &request.expected_ledger_root,
        request.expected_revision,
        &request.idempotency_key,
    )?;
    if request.schema != "joan.mock-apply-decision-request.v0" {
        return Err(LedgerError::UnsupportedSchema(request.schema.clone()));
    }
    verify_decision(&request.decision)?;
    let hold = ledger
        .holds
        .get(&request.hold_id)
        .ok_or_else(|| LedgerError::UnknownHold(request.hold_id.clone()))?;
    if hold.status != HoldStatus::Reserved || hold.decision_digest.is_some() {
        return Err(LedgerError::HoldNotReserved);
    }
    let allocated = checked_sum([
        request.decision.remedy.buyer_refund_microunits,
        request.decision.remedy.provider_release_microunits,
        request.decision.remedy.retained_microunits,
    ])?;
    if allocated != hold.original_amount_microunits {
        return Err(LedgerError::AllocationMismatch);
    }

    let prior_root = ledger.ledger_root.clone();
    let mut candidate = ledger.clone();
    credit(
        &mut candidate.balances,
        &hold.buyer_id,
        request.decision.remedy.buyer_refund_microunits,
    )?;
    credit(
        &mut candidate.balances,
        &hold.provider_id,
        request.decision.remedy.provider_release_microunits,
    )?;
    let updated_hold = candidate
        .holds
        .get_mut(&request.hold_id)
        .ok_or_else(|| LedgerError::UnknownHold(request.hold_id.clone()))?;
    updated_hold.locked_amount_microunits = request.decision.remedy.retained_microunits;
    updated_hold.status = status_for(request.decision.remedy.kind);
    updated_hold.decision_digest = Some(request.decision.decision_digest.clone());
    finish_mutation(
        candidate,
        request.idempotency_key.clone(),
        prior_root,
        request.hold_id.clone(),
        "apply-decision",
        digest_serializable("joan.mock-apply-decision-request.v0", request)?,
    )
}

fn finish_mutation(
    mut candidate: MockLedger,
    idempotency_key: String,
    prior_root: Digest,
    hold_id: String,
    operation: &str,
    request_digest: Digest,
) -> Result<(MockLedger, LedgerMutationReceipt), LedgerError> {
    candidate.consumed_idempotency_keys.insert(idempotency_key);
    candidate.revision = candidate
        .revision
        .checked_add(1)
        .ok_or(LedgerError::AmountOverflow)?;
    candidate.ledger_root = compute_ledger_root(&candidate)?;
    let conserved_total_microunits = total_value(&candidate)?;
    if conserved_total_microunits != candidate.initial_total_microunits {
        return Err(LedgerError::InvalidStoredLedger);
    }
    let receipt = LedgerMutationReceipt {
        schema: "joan.mock-ledger-mutation-receipt.v0".to_owned(),
        operation: operation.to_owned(),
        prior_ledger_root: prior_root,
        new_ledger_root: candidate.ledger_root.clone(),
        revision: candidate.revision,
        hold_id,
        request_digest,
        conserved_total_microunits,
        committed: true,
    };
    Ok((candidate, receipt))
}

fn validate_preconditions(
    ledger: &MockLedger,
    expected_root: &Digest,
    expected_revision: u64,
    idempotency_key: &str,
) -> Result<(), LedgerError> {
    require_nonempty(idempotency_key, "idempotency_key")?;
    if expected_root != &ledger.ledger_root {
        return Err(LedgerError::StaleRoot);
    }
    if expected_revision != ledger.revision {
        return Err(LedgerError::StaleRevision);
    }
    if ledger.consumed_idempotency_keys.contains(idempotency_key) {
        return Err(LedgerError::Replay);
    }
    if ledger.consumed_idempotency_keys.len() >= MAX_IDEMPOTENCY_KEYS {
        return Err(LedgerError::Capacity);
    }
    Ok(())
}

fn credit(
    balances: &mut BTreeMap<String, u64>,
    account: &str,
    amount: u64,
) -> Result<(), LedgerError> {
    let balance = balances
        .get(account)
        .copied()
        .ok_or_else(|| LedgerError::UnknownAccount(account.to_owned()))?;
    balances.insert(
        account.to_owned(),
        balance
            .checked_add(amount)
            .ok_or(LedgerError::AmountOverflow)?,
    );
    Ok(())
}

fn status_for(remedy: RemedyKind) -> HoldStatus {
    match remedy {
        RemedyKind::FullRefund => HoldStatus::Refunded,
        RemedyKind::ReleaseProvider => HoldStatus::Settled,
        RemedyKind::Split => HoldStatus::Split,
        RemedyKind::Repair => HoldStatus::RepairPending,
        RemedyKind::Quarantine => HoldStatus::Quarantined,
    }
}

fn total_value(ledger: &MockLedger) -> Result<u64, LedgerError> {
    checked_sum(
        ledger.balances.values().copied().chain(
            ledger
                .holds
                .values()
                .map(|hold| hold.locked_amount_microunits),
        ),
    )
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64, LedgerError> {
    values.into_iter().try_fold(0_u64, |total, value| {
        total.checked_add(value).ok_or(LedgerError::AmountOverflow)
    })
}

fn compute_ledger_root(ledger: &MockLedger) -> Result<Digest, CanonicalError> {
    digest_serializable(
        "joan.mock-ledger.v0",
        &LedgerCore {
            schema: &ledger.schema,
            balances: &ledger.balances,
            holds: &ledger.holds,
            consumed_idempotency_keys: &ledger.consumed_idempotency_keys,
            revision: ledger.revision,
            initial_total_microunits: ledger.initial_total_microunits,
        },
    )
}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), LedgerError> {
    if value.trim().is_empty() {
        Err(LedgerError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn placeholder_digest() -> Digest {
    Digest {
        algorithm: String::new(),
        profile: String::new(),
        domain: String::new(),
        value: String::new(),
    }
}
