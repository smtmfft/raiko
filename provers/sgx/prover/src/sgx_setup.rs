use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
};

use crate::{bootstrap, check_bootstrap, register_sgx_instance, ELF_NAME};
use anyhow::{Context, Result};
use raiko_primitives::Address;
use serde_json::{Number, Value};

use std::process::Command;
use tracing::info;

#[derive(Debug)]
pub struct SgxAutoRegisterParams {
    pub l1_rpc: String,
    pub l1_chain_id: u64,
    pub sgx_verifier_address: Address,
}

pub(crate) async fn sgx_setup(
    secret_path: PathBuf,
    config_path: PathBuf,
    sgx_auto_reg_opt: Option<SgxAutoRegisterParams>,
) -> Result<()> {
    let cur_dir = env::current_exe()
        .expect("Fail to get current directory")
        .parent()
        .unwrap()
        .to_path_buf();

    let gramine_cmd = || -> Command {
        let mut cmd = Command::new("sudo");
        cmd.arg("gramine-sgx");
        cmd.current_dir(&cur_dir).arg(ELF_NAME);
        cmd
    };

    let registered_check_file = PathBuf::from(config_path.clone())
        .parent()
        .unwrap()
        .join("registered");

    let need_init = check_bootstrap(secret_path.clone(), gramine_cmd())
        .await
        .is_err()
        || (sgx_auto_reg_opt.is_some() && fs::metadata(&registered_check_file).is_err());

    if need_init {
        let bootstrap_proof = bootstrap(secret_path, gramine_cmd()).await?;
        match fs::remove_file(&registered_check_file) {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }?;

        if let Some(auto_reg_args) = sgx_auto_reg_opt {
            let _register_res = register_sgx_instance(
                &bootstrap_proof.quote,
                &auto_reg_args.l1_rpc,
                auto_reg_args.l1_chain_id,
                auto_reg_args.sgx_verifier_address,
            )
            .await
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;
            //todo: update the config
            // Config file has the lowest preference
            let file = File::open(config_path.clone())?;
            let reader = BufReader::new(file);
            let mut file_config: Value = serde_json::from_reader(reader)?;
            file_config["sgx"]["instance_id"] = Value::Number(Number::from(_register_res));

            //save to the same file
            info!("Saving bootstrap data file {}", config_path.display());
            let json = serde_json::to_string_pretty(&file_config)?;
            fs::write(config_path.clone(), json).context(format!(
                "Saving bootstrap data file {} failed",
                config_path.display()
            ))?;
            File::create(&registered_check_file)?;
        }
    }

    Ok(())
}
