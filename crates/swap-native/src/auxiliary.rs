//! Dedicated transparent fee/timelock coin, separate from the shielded principal.
use crate::{Result, err, storage, wallet};
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, signer::Signer, spend_finalizer::SpendFinalizer,
    tx_extractor::TransactionExtractor,
};
use serde_json::{Value, json};
use std::path::Path;
use zcash_primitives::transaction::{
    Transaction, TxVersion,
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317::FeeRule,
};
use zcash_protocol::{TxId, consensus::BranchId, value::Zatoshis};
use zcash_transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};

pub const COMPACT_VALUE: u64 = 20_000;

pub struct Auxiliary {
    pub key: secp256k1::SecretKey,
    pub public: secp256k1::PublicKey,
    pub address: TransparentAddress,
    pub txid: TxId,
    pub index: usize,
    pub coin: TxOut,
}
impl Auxiliary {
    pub fn load(bank: &Path, height: u32) -> Result<Self> {
        let key = secp256k1::SecretKey::from_secret_bytes(
            storage::read(&bank.join("aux-key.bin"), 32)?
                .try_into()
                .map_err(|_| "aux key")?,
        )?;
        let public = secp256k1::PublicKey::from_secret_key(&key);
        let address = TransparentAddress::from_pubkey(&public);
        let compact = bank.join("aux-source-compact.json");
        let compact_exists = compact.exists();
        let data = storage::json(&if compact_exists {
            compact
        } else {
            bank.join("aux-source.json")
        })?;
        let raw = hex::decode(data["tx"].as_str().ok_or("aux tx")?)?;
        let mut cursor = std::io::Cursor::new(&raw);
        let tx = Transaction::read(&mut cursor, BranchId::Nu7)?;
        if cursor.position() != raw.len() as u64
            || tx.version() != TxVersion::V6
            || tx.consensus_branch_id() != BranchId::Nu7
        {
            return Err("aux transaction encoding/domain".into());
        }
        let bundle = tx.transparent_bundle().ok_or("aux bundle")?;
        let mined = data["height"].as_u64().ok_or("aux height")?;
        if mined > u64::from(height) || (bundle.is_coinbase() && mined + 100 > u64::from(height)) {
            return Err("immature or future auxiliary coin".into());
        }
        let (index, coin) = bundle
            .vout
            .iter()
            .enumerate()
            .find(|(i, c)| {
                c.recipient_address() == Some(address)
                    && (!compact_exists || data["index"].as_u64() == Some(*i as u64))
            })
            .ok_or("aux coin not owned by expected key")?;
        if u64::from(coin.value()) < 10_000
            || (compact_exists
                && (bundle.is_coinbase() || u64::from(coin.value()) != COMPACT_VALUE))
        {
            return Err("unexpected auxiliary reserve".into());
        }
        Ok(Self {
            key,
            public,
            address,
            txid: tx.txid(),
            index,
            coin: coin.clone(),
        })
    }
}

/// Split a disposable mined coin into a 20,000-zatoshi timelock/fee coin and
/// transparent change before preparing a swap. Never touches shielded principal.
pub fn compact(bank: &Path, scan: &Path) -> Result<Value> {
    let snapshot = storage::json(scan)?;
    if snapshot["genesis"] != wallet::GENESIS {
        return Err("wrong source chain".into());
    }
    if bank.join("aux-source-compact.json").exists() {
        return Err("compact auxiliary already recorded".into());
    }
    let height = u32::try_from(snapshot["height"].as_u64().ok_or("height")?)?;
    let aux = Auxiliary::load(bank, height)?;
    let value = u64::from(aux.coin.value());
    if value < COMPACT_VALUE * 2 {
        return Err("source auxiliary too small to split".into());
    }
    let mut builder = Builder::new(
        wallet::Regtest,
        (height + 1).into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(0u32.into());
    builder
        .add_transparent_p2pkh_input(
            aux.public,
            OutPoint::new(*aux.txid.as_ref(), aux.index as u32),
            aux.coin,
        )
        .map_err(err)?;
    builder
        .add_transparent_output(&aux.address, Zatoshis::from_u64(COMPACT_VALUE)?)
        .map_err(err)?;
    builder
        .add_transparent_output(
            &aux.address,
            Zatoshis::from_u64(value - COMPACT_VALUE - 10_000)?,
        )
        .map_err(err)?;
    let mut rng = rand::rng();
    let parts = builder
        .build_for_pczt(&mut rng, &FeeRule::standard())
        .map_err(err)?
        .pczt_parts;
    let p = IoFinalizer::new(Creator::build_from_parts(parts).ok_or("aux parts")?)
        .finalize_io(&mut rng)
        .map_err(err)?;
    let mut signer = Signer::new(p).map_err(err)?;
    signer.sign_transparent(0, &aux.key).map_err(err)?;
    let p = SpendFinalizer::new(signer.finish())
        .finalize_spends()
        .map_err(err)?;
    let tx = TransactionExtractor::new(p)
        .extract(&mut rng)
        .map_err(err)?;
    let output = tx
        .transparent_bundle()
        .ok_or("split output")?
        .vout
        .iter()
        .position(|c| {
            c.recipient_address() == Some(aux.address) && u64::from(c.value()) == COMPACT_VALUE
        })
        .ok_or("compact output missing")?;
    if tx.ironwood_bundle().is_some()
        || tx.orchard_bundle().is_some()
        || tx.sapling_bundle().is_some()
    {
        return Err("split must be transparent only".into());
    }
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    let path = bank.join("aux-compact.hex");
    storage::write(&path, hex::encode(raw).as_bytes())?;
    Ok(
        json!({"scope":"isolated auxiliary split, not yet broadcast","txid":tx.txid().to_string(),"index":output,"value_zatoshi":COMPACT_VALUE,"file":path}),
    )
}
