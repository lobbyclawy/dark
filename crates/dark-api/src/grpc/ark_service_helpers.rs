//! Public helper functions for asset packet parsing.
//! Used by both ark_service.rs and dark-core for asset registration.

use std::sync::Arc;

/// Decode the push data from an OP_RETURN script (public version).
pub fn decode_op_return_push_pub(script: &[u8]) -> Option<&[u8]> {
    if script.len() < 2 || script[0] != 0x6a {
        return None;
    }
    let mut pos = 1;
    let op = script[pos];
    pos += 1;
    if op <= 75 {
        let len = op as usize;
        if pos + len <= script.len() {
            return Some(&script[pos..pos + len]);
        }
    } else if op == 0x4c {
        if pos >= script.len() {
            return None;
        }
        let len = script[pos] as usize;
        pos += 1;
        if pos + len <= script.len() {
            return Some(&script[pos..pos + len]);
        }
    } else if op == 0x4d {
        if pos + 1 >= script.len() {
            return None;
        }
        let len = u16::from_le_bytes([script[pos], script[pos + 1]]) as usize;
        pos += 2;
        if pos + len <= script.len() {
            return Some(&script[pos..pos + len]);
        }
    }
    None
}

/// Read a protobuf-style base-128 varint. Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Parse the ARK extension data (after "ARK" magic is stripped) and store
/// issuance records for any issuance groups found.
///
/// An issuance group has no asset_id (presence bit 0 unset). Its asset_id
/// is derived as `hex(ark_txid_bytes ++ group_index_LE)`.
/// If it has a control asset reference (AssetRefByGroup), we record the
/// relationship.
pub async fn store_issuance_records(
    ext_data: &[u8],
    ark_txid: &str,
    asset_repo: &Arc<dyn dark_core::ports::AssetRepository>,
) {
    let mut pos = 0;
    // Skip to asset packet: type_byte(0x00) + varint_length + data
    if ext_data.is_empty() {
        return;
    }
    let pkt_type = ext_data[pos];
    pos += 1;
    let Some((pkt_len, n)) = read_varint(&ext_data[pos..]) else {
        return;
    };
    pos += n;
    if pkt_type != 0x00 {
        return; // not asset packet
    }
    let end = std::cmp::min(pos + pkt_len as usize, ext_data.len());
    let pkt_data = &ext_data[pos..end];

    // Parse groups
    let mut gpos = 0;
    let Some((group_count, gn)) = read_varint(pkt_data) else {
        return;
    };
    gpos += gn;

    // Track which group indices are issuance groups and their asset IDs
    let mut group_asset_ids: Vec<Option<String>> = Vec::new();
    // Track control asset refs (group_index of issued asset -> group_index of control)
    let mut control_refs: Vec<Option<u16>> = Vec::new();

    for group_idx in 0..group_count as u16 {
        if gpos >= pkt_data.len() {
            break;
        }
        let presence = pkt_data[gpos];
        gpos += 1;

        let has_asset_id = (presence & 0x01) != 0;
        let has_control_asset = (presence & 0x02) != 0;
        let has_metadata = (presence & 0x04) != 0;

        let asset_id_str: Option<String>;

        if has_asset_id {
            // Transfer group - skip 34 bytes
            if gpos + 34 > pkt_data.len() {
                break;
            }
            asset_id_str = Some(hex::encode(&pkt_data[gpos..gpos + 34]));
            gpos += 34;
        } else {
            // Issuance group
            let index_bytes = group_idx.to_le_bytes();
            asset_id_str = Some(format!("{}{}", ark_txid, hex::encode(index_bytes)));
        }

        let mut ctrl_ref: Option<u16> = None;
        if has_control_asset {
            if gpos >= pkt_data.len() {
                break;
            }
            let ref_type = pkt_data[gpos];
            gpos += 1;
            match ref_type {
                1 => gpos += 34, // AssetRefByID
                2 => {
                    if gpos + 2 <= pkt_data.len() {
                        ctrl_ref = Some(u16::from_le_bytes([pkt_data[gpos], pkt_data[gpos + 1]]));
                    }
                    gpos += 2;
                }
                _ => break,
            }
        }

        // Skip metadata
        if has_metadata {
            let Some((md_count, n)) = read_varint(&pkt_data[gpos..]) else {
                break;
            };
            gpos += n;
            for _ in 0..md_count {
                let Some((klen, n)) = read_varint(&pkt_data[gpos..]) else {
                    return;
                };
                gpos += n + klen as usize;
                let Some((vlen, n)) = read_varint(&pkt_data[gpos..]) else {
                    return;
                };
                gpos += n + vlen as usize;
            }
        }

        // Skip inputs
        let Some((input_count, n)) = read_varint(&pkt_data[gpos..]) else {
            break;
        };
        gpos += n;
        for _ in 0..input_count {
            if gpos >= pkt_data.len() {
                break;
            }
            let itype = pkt_data[gpos];
            gpos += 1;
            match itype {
                1 => {
                    gpos += 2;
                    let Some((_, n)) = read_varint(&pkt_data[gpos..]) else {
                        return;
                    };
                    gpos += n;
                }
                2 => {
                    gpos += 32 + 2;
                    let Some((_, n)) = read_varint(&pkt_data[gpos..]) else {
                        return;
                    };
                    gpos += n;
                }
                _ => return,
            }
        }

        // Skip outputs
        let Some((output_count, n)) = read_varint(&pkt_data[gpos..]) else {
            break;
        };
        gpos += n;
        for _ in 0..output_count {
            if gpos >= pkt_data.len() {
                break;
            }
            gpos += 1; // type
            gpos += 2; // vout
            let Some((_, n)) = read_varint(&pkt_data[gpos..]) else {
                break;
            };
            gpos += n;
        }

        group_asset_ids.push(asset_id_str);
        control_refs.push(ctrl_ref);
    }

    // Store issuance records with control asset relationships
    for (i, asset_id_opt) in group_asset_ids.iter().enumerate() {
        let Some(asset_id) = asset_id_opt else {
            continue;
        };

        // Find control asset ID if this group references another group
        let control_asset_id = control_refs
            .get(i)
            .and_then(|cr| *cr)
            .and_then(|ctrl_idx| group_asset_ids.get(ctrl_idx as usize))
            .and_then(|id| id.clone());

        let issuance = dark_core::domain::AssetIssuance {
            txid: ark_txid.to_string(),
            asset_id: asset_id.clone(),
            amount: 0, // We don't track amounts per-issuance here
            issuer_pubkey: String::new(),
            control_asset_id,
            metadata: std::collections::HashMap::new(),
        };
        let _ = asset_repo.store_issuance(&issuance).await;
    }
}
