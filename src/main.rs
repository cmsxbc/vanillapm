mod engine;
mod framework;

use crate::engine::sqlite::SQLiteManager;
use crate::engine::sqlite_legacy::SQLiteLegacyManager;
use crate::framework::{retry_guard, DataManager, Item, Repl};

use clap::{Parser, Subcommand, ValueEnum};
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, Write};
use std::str::FromStr;

struct IoRepl;

impl<T> Repl<T> for IoRepl
where
    T: DataManager,
{
    fn write(&self, output: &str) -> Result<(), Box<dyn Error>> {
        print!("{}", output);
        match io::stdout().flush() {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn write_line(&self, output: &str) -> Result<(), Box<dyn Error>> {
        println!("{}", output);
        Ok(())
    }

    fn read_line(&self) -> Result<String, Box<dyn Error>> {
        let mut input = String::new();
        if let Err(err) = io::stdin().read_line(&mut input) {
            return Err(err.into());
        }
        Ok(input)
    }

    fn read_password(&self) -> Result<String, Box<dyn Error>> {
        match rpassword::read_password() {
            Err(err) => Err(err.into()),
            Ok(password) => Ok(password),
        }
    }

    fn prompt_password(&self, msg: &str) -> Result<String, Box<dyn Error>> {
        match rpassword::prompt_password(msg) {
            Err(err) => Err(err.into()),
            Ok(password) => Ok(password),
        }
    }

    fn load(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        let mut reader = csv::Reader::from_path(input)?;
        let headers = reader.headers()?;
        println!("columns!");
        headers.into_iter().for_each(|h| println!("{}", h));
        let mut column_indices = [0; 3];
        let mut columns = [String::new(), String::new(), String::new()];
        'outer: for (i, expect_name) in ["site", "account", "password"].into_iter().enumerate() {
            print!("{} column=?", expect_name);
            io::stdout().flush()?;
            io::stdin().read_line(&mut columns[i])?;
            columns[i] = columns[i].trim().to_string();
            for (j, field) in headers.iter().enumerate() {
                if columns[i] == field {
                    column_indices[i] = j;
                    continue 'outer;
                }
            }
            println!("not a valid column");
            return Ok(());
        }

        for result in reader.records() {
            let record = result?;
            let site = record.get(column_indices[0]).unwrap().to_string();
            let account = record.get(column_indices[1]).unwrap().to_string();
            let password = record.get(column_indices[2]).unwrap().to_string();
            println!("{}, {}, {}", &site, &account, &password);
            manager.add(&Item {
                site,
                account,
                password,
            })?;
        }
        Ok(())
    }
}

#[derive(ValueEnum, Copy, Clone, Debug)]
pub enum Engine {
    Sqlite,
}

#[derive(Parser, Debug)]
#[clap(version)]
struct Argument {
    #[command(subcommand)]
    command: Command,

    db: String,

    #[clap(value_enum, short = 'e', long = "engine", default_value = "sqlite")]
    engine: Engine,

    #[clap(short = 'k', long = "key-db")]
    key_db: Option<String>,
}

macro_rules! define_cmd {
    ($($sub_cmd:ident);*) => {
        #[derive(Subcommand, Debug)]
        enum Command {
            #[command()]
            Repl {},
            /// Migrate a legacy (v1) database to the new secure (v2) format.
            #[command()]
            Migrate {
                /// Path for the new v2 database
                new_db: String,
                /// Optional separate key database for the new v2 database
                #[clap(long = "new-key-db")]
                new_key_db: Option<String>,
                /// Prompt for a new password instead of reusing the old one
                #[clap(long = "renew-password")]
                renew_password: bool,
            },
            /// Import credentials from another v2 database, skipping duplicates.
            #[command()]
            Import {
                /// Source database to import from
                source_db: String,
                /// Optional separate key database for the source
                #[clap(long = "source-key-db")]
                source_key_db: Option<String>,
            },
            /// Compare two v2 databases, showing items only in each side.
            #[command()]
            Diff {
                /// Other database to compare against
                other_db: String,
                /// Optional separate key database for the other database
                #[clap(long = "other-key-db")]
                other_key_db: Option<String>,
            },
            $(#[command()]
            $sub_cmd {
                #[clap(short = 'p', long = "password", group="passwd")]
                password: Option<String>,
                #[clap(long = "ask-password", group="passwd")]
                ask_password: bool,
                name: String
            }),*
        }
    };
}

define_cmd![Query;QueryOne;QueryLike;QueryAccount;QueryAccountLike];

fn print_items(items: Vec<Item>) -> Result<(), Box<dyn Error>> {
    for item in items {
        println!("{}\t{}\t{}", item.site, item.account, item.password);
    }
    Ok(())
}

fn get_password(
    env_password: &Option<(String, String)>,
    arg_password: &Option<String>,
    ask_password: bool,
) -> Result<String, Box<dyn Error>> {
    if let Some((_, password)) = env_password {
        Ok(password.clone())
    } else if ask_password {
        Ok(rpassword::prompt_password("password:")?)
    } else if let Some(password) = arg_password {
        Ok(password.clone())
    } else {
        Err("Lack of password".into())
    }
}

fn do_migrate(
    old_db: &str,
    old_key_db: &Option<String>,
    new_db: &str,
    new_key_db: &Option<String>,
    renew_password: bool,
) -> Result<(), Box<dyn Error>> {
    println!("=== VanillaPM Database Migration (v1 -> v2) ===");
    println!("Old database: {}", old_db);
    println!("New database: {}", new_db);
    println!();

    // Open old database with legacy reader
    let old_password = rpassword::prompt_password("Old database password>")?;
    let old_mgr = SQLiteLegacyManager::new_with_passwd(old_db, old_key_db, &old_password)?;
    let items = old_mgr.read_all()?;
    println!("Read {} items from old database.", items.len());

    // Create new v2 database
    println!("\nSetting up new database...");
    if renew_password {
        let new_mgr = SQLiteManager::new(new_db, new_key_db)?;
        new_mgr.batch_add(&items)?;
        new_mgr.finish()?;
    } else {
        let new_mgr = SQLiteManager::new_init_with_passwd(new_db, new_key_db, &old_password)?;
        new_mgr.batch_add(&items)?;
        new_mgr.finish()?;
    }
    println!(
        "\nMigration complete! {} items migrated successfully.",
        items.len()
    );
    Ok(())
}

fn read_all_from_any_db(
    filepath: &str,
    key_filepath: &Option<String>,
    password: &str,
) -> Result<Vec<Item>, Box<dyn Error>> {
    let conn = sqlite::open(filepath)?;
    let temp_conn;
    let key_conn = if let Some(k) = key_filepath {
        temp_conn = sqlite::open(k)?;
        &temp_conn
    } else {
        &conn
    };

    if SQLiteManager::is_legacy(key_conn) {
        let mgr = SQLiteLegacyManager::new_with_passwd(filepath, key_filepath, password)?;
        mgr.read_all()
    } else if SQLiteManager::is_v2(key_conn) {
        let mgr = SQLiteManager::new_with_passwd(filepath, key_filepath, password)?;
        Ok(mgr.get_all_items()?.unwrap_or_default())
    } else {
        Err("Not a valid VanillaPM database".into())
    }
}

fn do_import(
    target_db: &str,
    target_key_db: &Option<String>,
    source_db: &str,
    source_key_db: &Option<String>,
) -> Result<(), Box<dyn Error>> {
    use std::collections::HashSet;

    println!("=== VanillaPM Import ===");
    println!("Source: {}", source_db);
    println!("Target: {}", target_db);
    println!();

    // Open source database (supports v1 and v2)
    let source_items = retry_guard(
        || {
            let source_pw = rpassword::prompt_password("Source database password>")?;
            read_all_from_any_db(source_db, source_key_db, &source_pw)
        },
        |_| "password error".to_string(),
    )?;
    println!("Read {} items from source database.", source_items.len());

    if source_items.is_empty() {
        println!("Nothing to import.");
        return Ok(());
    }

    // Open target database
    let target_mgr = retry_guard(
        || {
            let target_pw = rpassword::prompt_password("Target database password>")?;
            SQLiteManager::new_with_passwd(target_db, target_key_db, &target_pw)
        },
        |_| "password error".to_string(),
    )?;

    let existing_items = target_mgr
        .get_all_items()?
        .unwrap_or_default();

    // Build dedup set: (site, account, password)
    let existing_set: HashSet<(String, String, String)> = existing_items
        .iter()
        .map(|item| (item.site.clone(), item.account.clone(), item.password.clone()))
        .collect();

    let mut imported = 0;
    let mut skipped = 0;
    for item in &source_items {
        let key = (item.site.clone(), item.account.clone(), item.password.clone());
        if existing_set.contains(&key) {
            skipped += 1;
        } else {
            target_mgr.add(item)?;
            imported += 1;
        }
    }

    target_mgr.finish()?;
    println!(
        "Imported {} items, skipped {} duplicates.",
        imported, skipped
    );
    Ok(())
}

fn do_diff(
    db_a: &str,
    key_db_a: &Option<String>,
    db_b: &str,
    key_db_b: &Option<String>,
) -> Result<(), Box<dyn Error>> {
    use std::collections::HashSet;

    println!("=== VanillaPM Diff ===");
    println!("A: {}", db_a);
    println!("B: {}", db_b);
    println!();

    // Open database A (supports v1 and v2)
    let items_a = retry_guard(
        || {
            let pw = rpassword::prompt_password("Password for A>")?;
            read_all_from_any_db(db_a, key_db_a, &pw)
        },
        |_| "password error".to_string(),
    )?;

    // Open database B (supports v1 and v2)
    let items_b = retry_guard(
        || {
            let pw = rpassword::prompt_password("Password for B>")?;
            read_all_from_any_db(db_b, key_db_b, &pw)
        },
        |_| "password error".to_string(),
    )?;

    // Build sets keyed by (site, account, password)
    let set_a: HashSet<(String, String, String)> = items_a
        .iter()
        .map(|item| (item.site.clone(), item.account.clone(), item.password.clone()))
        .collect();
    let set_b: HashSet<(String, String, String)> = items_b
        .iter()
        .map(|item| (item.site.clone(), item.account.clone(), item.password.clone()))
        .collect();

    let only_a: Vec<&(String, String, String)> = set_a.difference(&set_b).collect();
    let only_b: Vec<&(String, String, String)> = set_b.difference(&set_a).collect();
    let in_common = set_a.intersection(&set_b).count();

    if items_a.len() != set_a.len() {
        println!(
            "Note: A has {} internal duplicates ({} raw items, {} unique).",
            items_a.len() - set_a.len(),
            items_a.len(),
            set_a.len()
        );
    }
    if items_b.len() != set_b.len() {
        println!(
            "Note: B has {} internal duplicates ({} raw items, {} unique).",
            items_b.len() - set_b.len(),
            items_b.len(),
            set_b.len()
        );
    }

    if !only_a.is_empty() {
        println!("--- Only in A ({} items) ---", only_a.len());
        for (site, account, password) in &only_a {
            println!("{}\t{}\t{}", site, account, password);
        }
        println!();
    }

    if !only_b.is_empty() {
        println!("--- Only in B ({} items) ---", only_b.len());
        for (site, account, password) in &only_b {
            println!("{}\t{}\t{}", site, account, password);
        }
        println!();
    }

    println!(
        "=== Summary: {} only in A, {} only in B, {} in common ===",
        only_a.len(),
        only_b.len(),
        in_common
    );
    Ok(())
}

fn do_main<T: DataManager>(args: Argument) -> Result<(), Box<dyn Error>> {
    let env_password = std::env::vars().find(|(k, _)| k == "VANILLAPM_PASSWORD");

    match &args.command {
        Command::Repl {} => {
            let repl = IoRepl {};
            repl.main_loop(&move || T::new(&args.db, &args.key_db))
        }
        Command::Migrate { .. } => unreachable!("Migrate is handled in main()"),
        Command::QueryOne {
            password,
            ask_password,
            name,
        } => {
            let mgr = retry_guard(
                || {
                    let real_password = get_password(&env_password, password, *ask_password)?;
                    T::new_with_passwd(&args.db, &args.key_db, &real_password)
                },
                |_| "password error".to_string(),
            )?;
            print_items(vec![mgr.query_one(name)?.unwrap()])
        }
        sub_cmd => {
            macro_rules! deal_sub_cmd {
                ($( $ele: ident, $func: ident ); *) => {
                    match sub_cmd {
                        $(
                            Command::$ele {password, ask_password, name } => {
                                let mgr = retry_guard(|| {
                                    let real_password = get_password(&env_password, password, *ask_password)?;
                                    T::new_with_passwd(&args.db, &args.key_db, &real_password)
                                }, |_| "password error".to_string())?;
                                print_items(mgr.$func(name)?.unwrap())
                            }
                        ),*
                        _ => {Err("never arrived".into())}
                    }
                }
            }
            deal_sub_cmd! (
                Query, query;
                QueryLike, query_like;
                QueryAccount, query_account;
                QueryAccountLike, query_account_like
            )
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args_os: Vec<OsString> = std::env::args_os().collect();
    let args: Argument;
    if args_os.len() == 2 && args_os[1].as_os_str().to_str().unwrap().starts_with("-") {
        args = Argument::parse();
    } else {
        match Argument::try_parse_from(args_os.clone()) {
            Ok(args_) => args = args_,
            Err(_) => {
                args_os.append(&mut vec![OsString::from_str("repl")?]);
                args = Argument::parse_from(args_os.clone());
            }
        }
    }
    // Handle migrate and import commands before dispatching to engine-specific do_main
    if let Command::Migrate {
        ref new_db,
        ref new_key_db,
        renew_password,
    } = args.command
    {
        return do_migrate(&args.db, &args.key_db, new_db, new_key_db, renew_password);
    }
    if let Command::Import {
        ref source_db,
        ref source_key_db,
    } = args.command
    {
        return do_import(&args.db, &args.key_db, source_db, source_key_db);
    }
    if let Command::Diff {
        ref other_db,
        ref other_key_db,
    } = args.command
    {
        return do_diff(&args.db, &args.key_db, other_db, other_key_db);
    }

    match args.engine {
        Engine::Sqlite => do_main::<SQLiteManager>(args),
    }
}
