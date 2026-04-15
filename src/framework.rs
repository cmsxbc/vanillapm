use std::cmp;
use std::collections::BTreeMap;
use std::error::Error;

pub struct Item {
    pub site: String,
    pub account: String,
    pub password: String,
}

pub trait DataManager
where
    Self: Sized,
{
    fn new(config_str: &str, key_str: &Option<String>) -> Result<Self, Box<dyn Error>>;
    fn new_with_passwd(
        config_str: &str,
        key_str: &Option<String>,
        password: &str,
    ) -> Result<Self, Box<dyn Error>>;
    fn add(&self, item: &Item) -> Result<(), Box<dyn Error>>;
    fn batch_add(&self, items: &[Item]) -> Result<(), Box<dyn Error>> {
        for item in items {
            self.add(item)?
        }
        Ok(())
    }
    fn query_one(&self, site: &str) -> Result<Option<Item>, Box<dyn Error>>;
    fn query_like(&self, site: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>>;
    fn query(&self, site: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>>;
    fn query_account(&self, account: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>>;
    fn query_account_like(&self, account: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>>;
    fn list_sites(&self) -> Result<Option<Vec<String>>, Box<dyn Error>> {
        self.query_like("%").map(|items_c| match items_c {
            Some(items) => items.iter().map(|item| item.site.clone().into()).collect(),
            None => None,
        })
    }
    fn finish(&self) -> Result<(), Box<dyn Error>>;
}

pub fn retry_guard<T>(
    func: impl Fn() -> Result<T, Box<dyn Error>>,
    gen_msg: impl Fn(Box<dyn Error>) -> String,
) -> Result<T, Box<dyn Error>> {
    let mut retries = 3;
    loop {
        match func() {
            Ok(item) => return Ok(item),
            Err(err) => {
                retries -= 1;
                if retries > 0 {
                    println!("{}", gen_msg(err));
                    continue;
                }
                return Err(err);
            }
        }
    }
}

pub trait Repl<T>
where
    T: DataManager,
{
    fn add(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        if manager.query_one(input)?.is_some() {
            self.write("Duplicated!still add?[y/n]")?;
            let still = self.read_line()?;
            if still != "y\n" {
                return Ok(());
            }
        }
        self.write("account>")?;
        let account = self.read_line()?.trim().to_string();
        let password = self.prompt_password("password>")?;
        let confirm_password = self.prompt_password("confirm password>")?;
        if password != confirm_password {
            self.write_line("password mismatch")?;
            return Ok(());
        }
        if password.is_empty() {
            self.write_line("empty password is not allowed!")?;
            return Ok(());
        }
        manager.add(&Item {
            site: input.to_string(),
            account,
            password,
        })
    }
    fn load(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>>;
    fn query_like(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        if let Some(items) = manager.query_like(input)? {
            self.write_items(&items)?;
        }
        Ok(())
    }
    fn query_one(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        if let Some(item) = manager.query_one(input)? {
            self.write_line(&format!("account: {}", item.account))?;
            self.write_line(&format!("password: {}", item.password))?;
        } else {
            self.write_line("Not exists!")?;
        }
        Ok(())
    }
    fn query(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        if let Some(items) = manager.query(input)? {
            self.write_items(&items)?;
        }
        Ok(())
    }
    fn query_account(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        if let Some(items) = manager.query_account(input)? {
            self.write_items(&items)?;
        }
        Ok(())
    }
    fn query_account_like(&self, input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        if let Some(items) = manager.query_account_like(input)? {
            self.write_items(&items)?;
        }
        Ok(())
    }
    fn list_sites(&self, _input: &str, manager: &T) -> Result<(), Box<dyn Error>> {
        if let Some(sites) = manager.list_sites()? {
            for (i, site) in sites.into_iter().enumerate() {
                self.write_line(&format!("{}: {}", i, site))?;
            }
        }
        Ok(())
    }

    fn write(&self, output: &str) -> Result<(), Box<dyn Error>>;
    fn write_line(&self, output: &str) -> Result<(), Box<dyn Error>>;
    fn read_line(&self) -> Result<String, Box<dyn Error>>;
    fn read_password(&self) -> Result<String, Box<dyn Error>>;
    fn prompt_password(&self, msg: &str) -> Result<String, Box<dyn Error>> {
        self.write(msg)?;
        self.read_password()
    }

    fn debug_line(&self, output: &str) -> Result<(), Box<dyn Error>> {
        self.write_line(&("[DEBUG]".to_owned() + output))
    }

    fn write_items(&self, items: &[Item]) -> Result<(), Box<dyn Error>> {
        for item in items {
            self.write_line("----------------------------")?;
            self.write_line(&format!("site: {}", item.site))?;
            self.write_line(&format!("account: {}", item.account))?;
            self.write_line(&format!("password: {}", item.password))?;
        }
        Ok(())
    }

    fn main_loop(
        &self,
        create_manager: &dyn Fn() -> Result<T, Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        let manager = retry_guard(create_manager, |_| "password error".to_string())?;
        type Action<G, T> = fn(&G, &str, &T) -> Result<(), Box<dyn Error>>;
        let mut action_maps: BTreeMap<String, Action<Self, T>> = BTreeMap::new();
        action_maps.insert("query like ".to_string(), Self::query_like);
        action_maps.insert("query account like ".to_string(), Self::query_account_like);
        action_maps.insert("query account ".to_string(), Self::query_account);
        action_maps.insert("query one ".to_string(), Self::query_one);
        action_maps.insert("query ".to_string(), Self::query);
        action_maps.insert("add ".to_string(), Self::add);
        action_maps.insert("load ".to_string(), Self::load);
        action_maps.insert("list sites".to_string(), Self::list_sites);
        let mut actions: Vec<String> = action_maps.clone().into_keys().collect();
        actions.sort_by(|a, b| {
            let length_test = b.len().cmp(&a.len());
            if length_test == cmp::Ordering::Equal {
                return a.cmp(b);
            }
            length_test
        });

        'main: loop {
            self.write("vanillapm>>")?;
            let input = self.read_line()?.trim().to_lowercase();
            if input == "quit" || input == "exit" {
                break;
            } else if input == "help" {
                for action in actions.iter() {
                    self.write_line(action)?;
                }
                continue;
            }
            for action in actions.clone().into_iter() {
                if input.starts_with(&action.clone()) {
                    self.debug_line(&format!("action: {}", action))?;
                    let (_, input) = input.split_at(action.len());
                    let &func = action_maps.get(&action).unwrap();
                    if let Err(e) = func(self, input, &manager) {
                        self.write_line(&e.to_string())?
                    };
                    continue 'main;
                }
            }
            self.write_line("Unknown command!!")?
        }
        manager.finish()
    }
}
