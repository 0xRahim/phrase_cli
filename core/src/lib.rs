/* 
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
*/

pub mod Commands{
    pub mod vault{
        pub fn new(vname: &str){
            println!("Creating a new vault {} ", vname);
        }
        pub fn list(){
            println!("Listing all vaults");
        }
        pub fn rm(vname: &str){
            println!("Deleting Vault {} ", vname);
        }
        pub fn use_(vname: &str){
            println!("Switching To Vault {} ", vname);
        }
    }
    pub mod category{
        pub fn new(cname: &str){
            println!("Creating a new category {} ", cname);
        }
        pub fn list(){
            println!("Listing all categories");
        }
        pub fn rm(cname: &str){
            println!("Deleting Category {} ", cname);
        }
        pub fn use_(cname: &str){
            println!("Switching To Category {} ", cname);
        }
    }
    pub mod entry{
        pub fn new(ename: &str, cname: &str){
            println!("Creating a new entry {} in category {} ", ename, cname);
        }
        pub fn list(cname: &str){
            println!("Listing all entries in category {} ", cname);
        }
        pub fn rm(ename: &str, cname: &str){
            println!("Deleting Entry {} in category {} ", ename, cname);
        }
        pub fn edit(ename: &str, cname: &str){
            println!("Switching To Entry {} in category {} ", ename, cname);
        }
        pub fn get(ename: &str, cname: &str){
            println!("Getting Entry {} in category {} ", ename, cname);
        }
    }
}
