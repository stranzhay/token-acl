use solana_account_info::AccountInfo;
use solana_cpi::invoke;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramResult;
use solana_pubkey::Pubkey;

use crate::{
    get_freeze_extra_account_metas_address, get_thaw_extra_account_metas_address, instruction,
};

pub fn invoke_can_thaw_permissionless<'a>(
    program_id: &Pubkey,
    signer: AccountInfo<'a>,
    token_account: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_account_owner: AccountInfo<'a>,
    flag_account: AccountInfo<'a>,
    additional_accounts: &[AccountInfo<'a>],
) -> ProgramResult {
    let mut instruction = instruction::can_thaw_permissionless(
        program_id,
        signer.key,
        token_account.key,
        mint.key,
        token_account_owner.key,
        flag_account.key,
    );

    let validation_pubkey = get_thaw_extra_account_metas_address(mint.key, program_id);

    let mut cpi_account_infos = vec![
        signer,
        token_account,
        mint,
        token_account_owner,
        flag_account,
    ];

    if let Some(validation_info) = additional_accounts
        .iter()
        .find(|&x| *x.key == validation_pubkey)
    {
        instruction
            .accounts
            .push(AccountMeta::new_readonly(validation_pubkey, false));
        cpi_account_infos.push(validation_info.clone());

        add_to_cpi_instruction_reusing_resolution_buffer::<
            instruction::CanThawPermissionlessInstruction,
        >(
            &mut instruction,
            &mut cpi_account_infos,
            &validation_info.try_borrow_data()?,
            additional_accounts,
        )?;
    }

    invoke(&instruction, &cpi_account_infos)
}

fn add_to_cpi_instruction_reusing_resolution_buffer<'a, T: spl_discriminator::SplDiscriminate>(
    cpi_instruction: &mut solana_instruction::Instruction,
    cpi_account_infos: &mut Vec<AccountInfo<'a>>,
    data: &[u8],
    account_infos: &[AccountInfo<'a>],
) -> Result<(), solana_program_error::ProgramError> {
    use spl_pod::list::ListView;
    use spl_tlv_account_resolution::account::ExtraAccountMeta;
    use spl_type_length_value::state::{TlvState, TlvStateBorrowed};

    let state = TlvStateBorrowed::unpack(data)?;
    let bytes = state.get_first_bytes::<T>()?;
    let extra_account_metas = ListView::<ExtraAccountMeta>::unpack(bytes)?;

    for extra_meta in extra_account_metas.iter() {
        let mut meta = {
            let mut account_key_data_refs = arrayvec::ArrayVec::<_, 64>::new();
            for info in cpi_account_infos.iter() {
                account_key_data_refs
                    .try_push((*info.key, info.try_borrow_data()?))
                    .map_err(|_| solana_program_error::ProgramError::InvalidArgument)?;
            }

            extra_meta.resolve(
                &cpi_instruction.data,
                &cpi_instruction.program_id,
                |index| {
                    account_key_data_refs
                        .get(index)
                        .map(|(pubkey, account_data)| (pubkey, Some(account_data.as_ref())))
                },
            )?
        };
        let maybe_highest_privileges = cpi_instruction
            .accounts
            .iter()
            .filter(|account| account.pubkey == meta.pubkey)
            .map(|account| account.is_writable)
            .reduce(|highest, is_writable| highest || is_writable);
        if let Some(false) = maybe_highest_privileges {
            meta.is_writable = false;
        }
        meta.is_signer = false;
        let account_info = account_infos
            .iter()
            .find(|info| *info.key == meta.pubkey)
            .ok_or(spl_tlv_account_resolution::error::AccountResolutionError::IncorrectAccount)?
            .clone();

        cpi_instruction.accounts.push(meta);
        cpi_account_infos.push(account_info);
    }
    Ok(())
}

pub fn invoke_can_freeze_permissionless<'a>(
    program_id: &Pubkey,
    signer: AccountInfo<'a>,
    token_account: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_account_owner: AccountInfo<'a>,
    flag_account: AccountInfo<'a>,
    additional_accounts: &[AccountInfo<'a>],
) -> ProgramResult {
    let mut instruction = instruction::can_freeze_permissionless(
        program_id,
        signer.key,
        token_account.key,
        mint.key,
        token_account_owner.key,
        flag_account.key,
    );

    let validation_pubkey = get_freeze_extra_account_metas_address(mint.key, program_id);
    let mut cpi_account_infos = vec![
        signer,
        token_account,
        mint,
        token_account_owner,
        flag_account,
    ];

    if let Some(validation_info) = additional_accounts
        .iter()
        .find(|&x| *x.key == validation_pubkey)
    {
        instruction
            .accounts
            .push(AccountMeta::new_readonly(validation_pubkey, false));
        cpi_account_infos.push(validation_info.clone());

        add_to_cpi_instruction_reusing_resolution_buffer::<
            instruction::CanFreezePermissionlessInstruction,
        >(
            &mut instruction,
            &mut cpi_account_infos,
            &validation_info.try_borrow_data()?,
            additional_accounts,
        )?;
    }

    invoke(&instruction, &cpi_account_infos)
}
