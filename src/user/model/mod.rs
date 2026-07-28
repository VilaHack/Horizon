mod login;

use mongodb::bson::Uuid;

pub use login::{Credentials, Login};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct User {
    _id: Uuid,
    login: Login,
    // application: Application,
    // team: Option<Uuid>,
}
