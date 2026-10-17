//! Shared NU7 effect construction. Never signs a real input or broadcasts.
use crate::{Result, auxiliary::Auxiliary, err, refund_lock::RefundLock};
use orchard::{
    Note,
    keys::{FullViewingKey, Scope},
    tree::MerklePath,
};
use pczt::{
    Pczt,
    roles::{creator::Creator, io_finalizer::IoFinalizer},
};
use std::{collections::BTreeMap, convert::Infallible};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317::FeeRule,
};
use zcash_protocol::{
    consensus::{BranchId, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};
use zcash_transparent::bundle::OutPoint;

pub struct Source {
    pub fvk: FullViewingKey,
    pub note: Note,
    pub path: MerklePath,
}

pub struct Exit {
    pub joint: FullViewingKey,
    pub note: Note,
    pub path: MerklePath,
    /// One-time receive address; the builder never needs the recipient's keys.
    pub receiver: orchard::Address,
    pub payout: u64,
}

fn builder<P: Parameters>(
    params: P,
    height: u32,
    anchor: orchard::Anchor,
) -> Result<Builder<P, ()>> {
    if BranchId::for_height(&params, height.into()) != BranchId::Nu7 {
        return Err("transaction graph requires the pinned NU7 branch".into());
    }
    Ok(Builder::new(
        params,
        height.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(0u32.into()))
}

pub fn funding<P: Parameters>(
    params: P,
    height: u32,
    source: Source,
    joint: &FullViewingKey,
    principal: u64,
) -> Result<(Pczt, usize)> {
    let change = source
        .note
        .value()
        .inner()
        .checked_sub(principal)
        .and_then(|value| value.checked_sub(10_000))
        .filter(|value| *value > 0)
        .ok_or("funding requires principal, fee and positive shielded change")?;
    if principal <= 10_000 {
        return Err("positive payout after claim fee required".into());
    }
    let anchor = source.path.root(source.note.commitment().into());
    let mut b = builder(params, height, anchor)?;
    b.add_ironwood_spend::<Infallible>(source.fvk.clone(), source.note, source.path)
        .map_err(err)?;
    b.add_ironwood_output::<Infallible>(
        None,
        joint.address_at(0u32, Scope::External),
        Zatoshis::from_u64(principal)?,
        MemoBytes::empty(),
    )
    .map_err(err)?;
    b.add_ironwood_output::<Infallible>(
        None,
        source.fvk.address_at(0u32, Scope::External),
        Zatoshis::from_u64(change)?,
        MemoBytes::empty(),
    )
    .map_err(err)?;
    let mut rng = rand::rng();
    let parts = b
        .build_for_pczt(&mut rng, &FeeRule::standard())
        .map_err(err)?;
    let index = parts
        .ironwood_meta
        .output_action_index(0)
        .ok_or("funding output")?;
    let pczt =
        IoFinalizer::new(Creator::build_from_parts(parts.pczt_parts).ok_or("funding parts")?)
            .finalize_io(&mut rng)
            .map_err(err)?;
    Ok((pczt, index))
}

pub fn exit<P: Parameters>(
    params: P,
    height: u32,
    exit: Exit,
    refund: Option<(&Auxiliary, RefundLock)>,
) -> Result<Pczt> {
    if exit.payout == 0 || exit.payout.checked_add(10_000) != Some(exit.note.value().inner()) {
        return Err("exit amount/fee differs from pending note".into());
    }
    let anchor = exit.path.root(exit.note.commitment().into());
    let mut b = builder(params, height, anchor)?;
    b.add_ironwood_spend::<Infallible>(exit.joint, exit.note, exit.path)
        .map_err(err)?;
    b.add_ironwood_output::<Infallible>(
        None,
        exit.receiver,
        Zatoshis::from_u64(exit.payout)?,
        MemoBytes::empty(),
    )
    .map_err(err)?;
    if let Some((aux, _)) = refund {
        let change = u64::from(aux.coin.value())
            .checked_sub(5_000)
            .filter(|value| *value > 0)
            .ok_or("refund auxiliary amount")?;
        b.add_transparent_p2pkh_input(
            aux.public,
            OutPoint::new(*aux.txid.as_ref(), u32::try_from(aux.index)?),
            aux.coin.clone(),
        )
        .map_err(err)?;
        b.add_transparent_output(&aux.address, Zatoshis::from_u64(change)?)
            .map_err(err)?;
    }
    let mut rng = rand::rng();
    let mut parts = b
        .build_for_pczt(&mut rng, &FeeRule::standard())
        .map_err(err)?
        .pczt_parts;
    if let Some((aux, lock)) = refund {
        parts.lock_time = lock.value();
        let transparent = parts.transparent.as_mut().ok_or("refund transparent")?;
        let old = &transparent.inputs()[0];
        transparent.inputs_mut()[0] = zcash_transparent::pczt::Input::parse(
            *old.prevout_txid().as_ref(),
            *old.prevout_index(),
            Some(u32::MAX - 1),
            lock.required_time(),
            lock.required_height(),
            None,
            u64::from(*old.value()),
            aux.coin.script_pubkey().0.0.clone(),
            None,
            BTreeMap::new(),
            1,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .map_err(err)?;
    }
    IoFinalizer::new(Creator::build_from_parts(parts).ok_or("exit parts")?)
        .finalize_io(&mut rng)
        .map_err(|e| err(e).into())
}
